// Package mcp implements a transparent JSON-RPC proxy for MCP servers.
// It intercepts tools/call requests and runs them through the Aegis policy engine
// before forwarding to the upstream server.
package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/aegis-ai/aegis/internal/policy"
	"github.com/aegis-ai/aegis/internal/scorer"
	"github.com/aegis-ai/aegis/internal/store"
)

// hopHeaders must not be forwarded to the upstream mcp server.
var hopHeaders = []string{
	"Authorization",
	"Cookie",
	"X-Aegis-Key",
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      any             `json:"id,omitempty"`
}

type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Proxy sits in front of an MCP server and enforces Aegis policies.
type Proxy struct {
	upstream      *url.URL
	hashedAPIKey  []byte
	store         *store.Store
	evaluator     *policy.Evaluator
	client        *http.Client
}

// NewProxy creates a Proxy that forwards approved calls to upstream.
func NewProxy(upstream, apiKey string, db *store.Store, eval *policy.Evaluator) (*Proxy, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("api key is required for the mcp proxy")
	}
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream url: %w", err)
	}
	h := sha256.Sum256([]byte(apiKey))
	return &Proxy{
		upstream:     u,
		hashedAPIKey: h[:],
		store:        db,
		evaluator:    eval,
		client:       &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Handler returns an http.Handler that proxies MCP requests.
func (p *Proxy) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /", p.handleRPC)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := p.store.Ping(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintln(w, `{"status":"error","error":"database unavailable"}`)
			return
		}
		_, _ = fmt.Fprintln(w, `{"status":"ok"}`)
	})
	return mux
}

func (p *Proxy) handleRPC(w http.ResponseWriter, r *http.Request) {
	// auth is always enforced — NewProxy rejects empty keys at construction time.
	// SHA-256 both sides before compare to prevent length-based side-channel leakage.
	provided := r.Header.Get("X-Aegis-Key")
	h := sha256.Sum256([]byte(provided))
	if subtle.ConstantTimeCompare(h[:], p.hashedAPIKey) != 1 {
		writeRPCError(w, nil, -32600, "unauthorized")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeRPCError(w, nil, -32700, "read error")
		return
	}

	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPCError(w, nil, -32700, "parse error")
		return
	}

	// only intercept tool calls; everything else passes through untouched
	if req.Method != "tools/call" {
		p.forward(w, r, body)
		return
	}

	var params toolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeRPCError(w, req.ID, -32602, "invalid params")
		return
	}

	ctx := r.Context()
	sessionID := r.Header.Get("X-Session-ID")
	agentID := r.Header.Get("X-Agent-ID")
	if sessionID == "" {
		sessionID = uuid.New().String()
	}
	if agentID == "" {
		agentID = "mcp-client"
	}

	// Validate caller-supplied IDs to prevent log injection and unexpected chars in DB.
	if !isValidID(sessionID) || !isValidID(agentID) {
		writeRPCError(w, req.ID, -32600, "invalid X-Session-ID or X-Agent-ID header")
		return
	}
	if !isValidID(params.Name) {
		writeRPCError(w, req.ID, -32602, "invalid tool name")
		return
	}

	sess, err := p.store.GetOrCreateSession(ctx, sessionID, agentID, "")
	if err != nil {
		slog.Error("mcp: get session", "err", err)
		writeRPCError(w, req.ID, -32603, "internal error")
		return
	}
	// Reject cross-agent session access — same protection as the intercept API.
	if sess.AgentID != agentID {
		writeRPCError(w, req.ID, -32600, "session belongs to a different agent")
		return
	}

	recentCount, err := p.store.CountRecentCalls(ctx, sessionID, time.Minute)
	if err != nil {
		slog.Error("mcp: count recent calls", "err", err)
		// non-fatal: rate signal will be 0
	}

	history, err := p.store.GetToolCallHistory(ctx, sessionID, 20)
	if err != nil {
		slog.Error("mcp: get history", "err", err)
		// non-fatal: escalation signal will be 0
	}

	score := scorer.Compute(sess, history, params.Name, recentCount)

	dec := p.evaluator.Evaluate(policy.EvalRequest{
		Tool:              params.Name,
		Session:           sess,
		ToolCallsPerMin:   float64(recentCount),
		ComputedRiskScore: score.Total,
	})

	slog.Info("mcp intercept",
		"tool", params.Name,
		"session", sessionID,
		"decision", dec.Action,
		"risk", score.Total,
	)

	bg := context.WithoutCancel(ctx)

	switch dec.Action {
	case "DENY":
		writeRPCError(w, req.ID, -32603, fmt.Sprintf("denied by policy %q: %s", dec.Policy, dec.Reason))
		go func() {
			if err := p.store.AppendToolCall(bg, sessionID, store.ToolCall{
				Tool: params.Name, Decision: "DENY", Timestamp: time.Now(),
			}); err != nil {
				slog.Error("mcp: append tool call", "err", err)
			}
		}()
		return
	case "DEFER":
		// The mcp proxy is synchronous json-rpc with no polling channel, so a
		// deferred call cannot wait for human approval here — fail closed.
		writeRPCError(w, req.ID, -32603, fmt.Sprintf("call deferred by policy %q for human approval; DEFER is not supported over the mcp proxy — use the SDK", dec.Policy))
		go func() {
			if err := p.store.AppendToolCall(bg, sessionID, store.ToolCall{
				Tool: params.Name, Decision: "DEFER", Timestamp: time.Now(),
			}); err != nil {
				slog.Error("mcp: append tool call", "err", err)
			}
		}()
		return
	case "MODIFY":
		// Rewrite the tool arguments in place, then forward the modified request.
		if dec.Modify != nil {
			params.Arguments = dec.Modify.Apply(params.Arguments)
			if newParams, err := json.Marshal(params); err == nil {
				req.Params = newParams
				if newBody, err := json.Marshal(req); err == nil {
					body = newBody
				}
			}
		}
	}

	p.forward(w, r, body)

	sess.RiskScore = score.Total
	sess.ToolCallCount++
	go func() {
		if err := p.store.UpdateSession(bg, sess); err != nil {
			slog.Error("mcp: update session", "err", err)
		}
	}()
	go func() {
		if err := p.store.AppendToolCall(bg, sessionID, store.ToolCall{
			Tool: params.Name, Decision: dec.Action, Timestamp: time.Now(),
		}); err != nil {
			slog.Error("mcp: append tool call", "err", err)
		}
	}()
}

// forward proxies the raw body to the upstream, stripping hop-by-hop headers.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, body []byte) {
	target := *p.upstream
	target.Path = r.URL.Path
	target.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		writeRPCError(w, nil, -32603, "proxy error")
		return
	}

	req.Header = r.Header.Clone()
	for _, h := range hopHeaders {
		req.Header.Del(h)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		writeRPCError(w, nil, -32603, "upstream unreachable")
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// isValidID reports whether s is a safe opaque identifier: 1–128 alphanumeric
// chars plus underscore, dash, and dot. Mirrors validateID in the proxy package.
func isValidID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func writeRPCError(w http.ResponseWriter, id any, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC errors always use HTTP 200
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   rpcError{Code: code, Message: msg},
	})
}

// ListenAndServe starts the MCP proxy on addr. It blocks until ctx is cancelled.
func (p *Proxy) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:           addr,
		Handler:        p.Handler(),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 16, // 64 KB
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

