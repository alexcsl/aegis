package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/aegis-ai/aegis/internal/policy"
	"github.com/aegis-ai/aegis/internal/scorer"
	"github.com/aegis-ai/aegis/internal/store"
)

// interceptRequest is the body of POST /v1/intercept.
type interceptRequest struct {
	SessionID  string         `json:"session_id"`
	AgentID    string         `json:"agent_id"`
	Tool       string         `json:"tool"`
	Args       map[string]any `json:"args"`
	Context    string         `json:"context,omitempty"`
	CostUSD    float64        `json:"cost_usd,omitempty"`
	TokenCount int            `json:"token_count,omitempty"`
}

// interceptResponse is what the SDK receives after interception.
type interceptResponse struct {
	Decision  string  `json:"decision"`
	Reason    string  `json:"reason,omitempty"`
	Policy    string  `json:"policy,omitempty"`
	RiskScore float64 `json:"risk_score"`
	LatencyMs int64   `json:"latency_ms"`
	// DecisionID is set on DEFER: the id the SDK polls for resolution.
	DecisionID string `json:"decision_id,omitempty"`
	// ModifiedArgs is set on MODIFY: the rewritten args the SDK must execute with.
	ModifiedArgs map[string]any `json:"modified_args,omitempty"`
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
	if err := validateID(req.Tool); err != nil {
		writeError(w, http.StatusBadRequest, "invalid tool name: "+err.Error())
		return
	}
	if req.CostUSD < 0 {
		writeError(w, http.StatusBadRequest, "cost_usd must be non-negative")
		return
	}
	if req.TokenCount < 0 {
		writeError(w, http.StatusBadRequest, "token_count must be non-negative")
		return
	}
	req.Context = sanitizeContext(req.Context)

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

	// Emit a structured audit log for decisions that block or hold a call.
	// Traces capture every call; this surfaces security-relevant events at WARN level
	// so they appear in log aggregators without requiring DB queries.
	if dec.Action == "DENY" || dec.Action == "DEFER" {
		slog.Warn("aegis security event",
			"event", dec.Action,
			"session", req.SessionID,
			"agent", req.AgentID,
			"tool", req.Tool,
			"policy", dec.Policy,
			"reason", dec.Reason,
			"risk_score", score.Total,
		)
	}

	// detach from the request context so background writes survive after the
	// handler returns (http/2 cancels r.Context() immediately on return)
	bg := context.WithoutCancel(ctx)

	resp := interceptResponse{
		Decision:  dec.Action,
		Reason:    dec.Reason,
		Policy:    dec.Policy,
		RiskScore: score.Total,
	}

	// MODIFY rewrites the input args; the SDK executes with these instead.
	execArgs := req.Args
	if dec.Action == "MODIFY" && dec.Modify != nil {
		execArgs = dec.Modify.Apply(req.Args)
		resp.ModifiedArgs = execArgs
	}

	// DEFER suspends the call: persist a pending decision (synchronously, since we
	// return its id) and optionally fire a webhook so a human is alerted.
	if dec.Action == "DEFER" {
		decisionID := uuid.New().String()
		if err := s.store.CreatePendingDecision(ctx, store.PendingDecision{
			ID:        decisionID,
			SessionID: req.SessionID,
			AgentID:   req.AgentID,
			Tool:      req.Tool,
			Args:      sanitize(req.Args),
			Reason:    dec.Reason,
			Policy:    dec.Policy,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "could not record deferred decision")
			return
		}
		resp.DecisionID = decisionID
		if dec.Notify != "" {
			go fireWebhook(bg, dec.Notify, webhookPayload{
				Event:      "decision.deferred",
				DecisionID: decisionID,
				SessionID:  req.SessionID,
				AgentID:    req.AgentID,
				Tool:       req.Tool,
				Reason:     dec.Reason,
				Policy:     dec.Policy,
			})
		}
	}

	sess.RiskScore = score.Total
	sess.ToolCallCount++
	sess.CostUSD += req.CostUSD
	sess.TokenCount += req.TokenCount
	go func() {
		if err := s.store.UpdateSession(bg, sess); err != nil {
			slog.Error("update session", "session", req.SessionID, "err", err)
		}
	}()

	// record the args that were (or would be) executed — MODIFY-rewritten when applicable
	recordedArgs := sanitize(execArgs)
	go func() {
		if err := s.store.AppendToolCall(bg, req.SessionID, store.ToolCall{
			Tool:      req.Tool,
			Args:      recordedArgs,
			Decision:  dec.Action,
			Timestamp: time.Now(),
			CostUSD:   req.CostUSD,
		}); err != nil {
			slog.Error("append tool call", "session", req.SessionID, "err", err)
		}
	}()

	latency := time.Since(start).Milliseconds()
	resp.LatencyMs = latency

	trace := store.Trace{
		TraceID:         uuid.New().String(),
		SessionID:       req.SessionID,
		AgentID:         req.AgentID,
		Timestamp:       time.Now(),
		Tool:            req.Tool,
		Input:           recordedArgs,
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

	writeJSON(w, http.StatusOK, resp)
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
	limit, offset := parsePagination(r, 100, 500)
	traces, err := s.store.GetTraces(r.Context(), sessionID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}
	writeJSON(w, http.StatusOK, traces)
}

// handleListSessions returns the most recently active sessions for an agent.
func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "agent_id query param required")
		return
	}
	limit, offset := parsePagination(r, 50, 200)
	sessions, err := s.store.ListSessions(r.Context(), agentID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

// handleGetDecision lets the SDK poll a deferred decision for its resolution.
// Requires ?agent_id= and validates ownership to prevent cross-agent reads.
func (s *Server) handleGetDecision(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	agentID := r.URL.Query().Get("agent_id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "decision id required")
		return
	}
	if err := validateID(id); err != nil {
		writeError(w, http.StatusBadRequest, "invalid decision id")
		return
	}
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "agent_id query param required")
		return
	}
	pd, err := s.store.GetPendingDecision(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}
	if pd == nil || pd.AgentID != agentID {
		writeError(w, http.StatusNotFound, "decision not found")
		return
	}
	writeJSON(w, http.StatusOK, pd)
}

// resolveRequest is the body of POST /v1/decisions/{id}/resolve.
type resolveRequest struct {
	Action string `json:"action"` // approve | reject
}

// handleResolveDecision is an operator action (admin-authed) that approves or
// rejects a pending decision. The agent then sees the new status on its next poll.
func (s *Server) handleResolveDecision(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "decision id required")
		return
	}
	if err := validateID(id); err != nil {
		writeError(w, http.StatusBadRequest, "invalid decision id")
		return
	}
	var body resolveRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var status string
	switch body.Action {
	case "approve":
		status = "approved"
	case "reject":
		status = "rejected"
	default:
		writeError(w, http.StatusBadRequest, `action must be "approve" or "reject"`)
		return
	}
	updated, err := s.store.ResolvePendingDecision(r.Context(), id, status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}
	if !updated {
		writeError(w, http.StatusConflict, "decision not found or already resolved")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": status})
}

// handleListDecisions returns pending decisions for an operator (admin-authed).
func (s *Server) handleListDecisions(w http.ResponseWriter, r *http.Request) {
	decisions, err := s.store.ListPendingDecisions(r.Context(), 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}
	writeJSON(w, http.StatusOK, decisions)
}

// webhookPayload is the JSON body POSTed to a policy's notify URL.
type webhookPayload struct {
	Event      string `json:"event"`
	DecisionID string `json:"decision_id"`
	SessionID  string `json:"session_id"`
	AgentID    string `json:"agent_id"`
	Tool       string `json:"tool"`
	Reason     string `json:"reason,omitempty"`
	Policy     string `json:"policy,omitempty"`
}

// webhookClient is shared across notify deliveries; the URL comes from operator
// config (not user input), so this is not a user-controlled SSRF surface.
var webhookClient = &http.Client{Timeout: 5 * time.Second}

// fireWebhook POSTs payload to url on a best-effort basis. Failures are logged, not retried.
func fireWebhook(ctx context.Context, url string, payload webhookPayload) {
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		slog.Error("webhook build", "url", url, "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := webhookClient.Do(req)
	if err != nil {
		slog.Error("webhook deliver", "url", url, "err", err)
		return
	}
	_ = resp.Body.Close()
}

// sanitizeContext caps the free-text context/intent field and strips ASCII
// control characters to prevent log injection and DB surprises.
const maxContextLen = 1024

func sanitizeContext(s string) string {
	if len(s) > maxContextLen {
		s = s[:maxContextLen]
	}
	return strings.Map(func(r rune) rune {
		// Allow printable chars, space, tab, and newline; drop everything else.
		if r < 32 && r != '\t' && r != '\n' {
			return -1
		}
		return r
	}, s)
}

// parsePagination reads ?limit= and ?offset= from the request, applying the
// given defaults and a hard cap on limit to prevent oversized responses.
func parsePagination(r *http.Request, defaultLimit, maxLimit int) (limit, offset int) {
	limit = defaultLimit
	offset = 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	return
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
