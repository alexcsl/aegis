package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/aegis-ai/aegis/internal/policy"
	"github.com/aegis-ai/aegis/internal/scorer"
	"github.com/aegis-ai/aegis/internal/store"
)

// interceptRequest is the body of POST /v1/intercept.
type interceptRequest struct {
	SessionID string         `json:"session_id"`
	AgentID   string         `json:"agent_id"`
	Tool      string         `json:"tool"`
	Args      map[string]any `json:"args"`
	Context   string         `json:"context,omitempty"`
	CostUSD   float64        `json:"cost_usd,omitempty"`
}

// interceptResponse is what the SDK receives after interception.
type interceptResponse struct {
	Decision  string  `json:"decision"`
	Reason    string  `json:"reason,omitempty"`
	Policy    string  `json:"policy,omitempty"`
	RiskScore float64 `json:"risk_score"`
	LatencyMs int64   `json:"latency_ms"`
}

func (s *Server) handleIntercept(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	var req interceptRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.SessionID == "" || req.AgentID == "" || req.Tool == "" {
		writeError(w, http.StatusBadRequest, "session_id, agent_id, and tool are required")
		return
	}

	if err := validateID(req.SessionID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid session_id: "+err.Error())
		return
	}
	if err := validateID(req.AgentID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent_id: "+err.Error())
		return
	}

	ctx := r.Context()

	sess, err := s.store.GetOrCreateSession(ctx, req.SessionID, req.AgentID, req.Context)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session error")
		return
	}
	// Reject cross-agent session access to prevent session poisoning.
	if sess.AgentID != req.AgentID {
		writeError(w, http.StatusForbidden, "session belongs to a different agent")
		return
	}

	// count calls via SQL so the rate signal is never capped by the history fetch limit
	recentCount, err := s.store.CountRecentCalls(ctx, req.SessionID, time.Minute)
	if err != nil {
		slog.Error("count recent calls", "err", err)
		// non-fatal: rate signal will be 0, which is the safe direction
	}

	history, err := s.store.GetToolCallHistory(ctx, req.SessionID, 20)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "history error")
		return
	}

	score := scorer.Compute(sess, history, req.Tool, recentCount)

	dec := s.evaluator.Evaluate(policy.EvalRequest{
		Tool:              req.Tool,
		Session:           sess,
		ToolCallsPerMin:   float64(recentCount),
		ComputedRiskScore: score.Total,
	})

	// detach from the request context so background writes survive after the
	// handler returns (http/2 cancels r.Context() immediately on return)
	bg := context.WithoutCancel(ctx)

	sess.RiskScore = score.Total
	sess.ToolCallCount++
	sess.CostUSD += req.CostUSD
	go func() {
		if err := s.store.UpdateSession(bg, sess); err != nil {
			slog.Error("update session", "session", req.SessionID, "err", err)
		}
	}()

	call := store.ToolCall{
		Tool:      req.Tool,
		Args:      sanitize(req.Args),
		Decision:  dec.Action,
		Timestamp: time.Now(),
		CostUSD:   req.CostUSD,
	}
	go func() {
		if err := s.store.AppendToolCall(bg, req.SessionID, call); err != nil {
			slog.Error("append tool call", "session", req.SessionID, "err", err)
		}
	}()

	latency := time.Since(start).Milliseconds()

	trace := store.Trace{
		TraceID:         uuid.New().String(),
		SessionID:       req.SessionID,
		AgentID:         req.AgentID,
		Timestamp:       time.Now(),
		Tool:            req.Tool,
		Input:           sanitize(req.Args),
		Decision:        dec.Action,
		PolicyTriggered: dec.Policy,
		RiskScore:       score.Total,
		LatencyMs:       latency,
		CostUSD:         req.CostUSD,
	}
	go func() {
		if err := s.store.InsertTrace(bg, trace); err != nil {
			slog.Error("insert trace", "session", req.SessionID, "err", err)
		}
	}()

	writeJSON(w, http.StatusOK, interceptResponse{
		Decision:  dec.Action,
		Reason:    dec.Reason,
		Policy:    dec.Policy,
		RiskScore: score.Total,
		LatencyMs: latency,
	})
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	agentID := r.URL.Query().Get("agent_id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "session id required")
		return
	}
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "agent_id query param required")
		return
	}
	sess, err := s.store.GetSession(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}
	if sess == nil {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	// validate ownership: prevent cross-agent session reads (IDOR)
	if sess.AgentID != agentID {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	writeJSON(w, http.StatusOK, sess)
}

func (s *Server) handleGetTraces(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	agentID := r.URL.Query().Get("agent_id")
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "session_id query param required")
		return
	}
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "agent_id query param required")
		return
	}
	// validate ownership before returning traces
	sess, err := s.store.GetSession(r.Context(), sessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}
	if sess == nil || sess.AgentID != agentID {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	traces, err := s.store.GetTraces(r.Context(), sessionID, 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}
	writeJSON(w, http.StatusOK, traces)
}

// idPattern matches safe opaque identifiers: alphanumeric plus - _ .
var idPattern = regexp.MustCompile(`^[A-Za-z0-9_\-.]+$`)

// validateID rejects IDs that are too long or contain characters outside the safe set.
// This prevents log poisoning and oversized key storage even with parameterized SQL.
func validateID(id string) error {
	if len(id) > 128 {
		return fmt.Errorf("must be ≤128 characters")
	}
	if !idPattern.MatchString(id) {
		return fmt.Errorf("must match [A-Za-z0-9_-.]")
	}
	return nil
}

// sanitize recursively redacts known sensitive keys and secret-looking values from arg maps.
func sanitize(args map[string]any) map[string]any {
	if args == nil {
		return nil
	}
	out := make(map[string]any, len(args))
	for k, v := range args {
		if isSensitiveKey(k) {
			out[k] = "[redacted]"
		} else {
			out[k] = sanitizeValue(v)
		}
	}
	return out
}

func sanitizeValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return sanitize(val)
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = sanitizeValue(item)
		}
		return out
	case string:
		return scrubSecretValues(val)
	default:
		return v
	}
}

// Compiled regexes for value-level secret detection.
var (
	reAWSKey  = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	reJWT     = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	rePrivKey = regexp.MustCompile(`-----BEGIN`)
)

// scrubSecretValues replaces recognisable secret patterns inside a string value.
func scrubSecretValues(s string) string {
	if rePrivKey.MatchString(s) {
		return "[redacted-private-key]"
	}
	s = reAWSKey.ReplaceAllString(s, "[redacted-aws-key]")
	s = reJWT.ReplaceAllString(s, "[redacted-jwt]")
	return s
}

var sensitiveKeyFragments = []string{
	"password", "passwd", "pwd",
	"token", "apikey", "api_key",
	"secret", "key",
	"auth", "authorization",
	"credential",
	"private",
	"bearer",
	"cookie",
	"session",
	"pin", "otp",
	"signature",
	"jwt",
}

func isSensitiveKey(k string) bool {
	lower := strings.ToLower(k)
	for _, frag := range sensitiveKeyFragments {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	return false
}
