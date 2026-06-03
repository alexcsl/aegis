package policy

import (
	"slices"

	"github.com/aegis-ai/aegis/internal/store"
)

// Decision is the result of evaluating all policies against a request.
type Decision struct {
	Action string // ALLOW, DENY, DEFER, MODIFY
	Reason string
	Policy string
	// Notify is the webhook URL from the matched policy, if any.
	Notify string
	// Modify is the arg-rewrite spec, set only when Action is MODIFY.
	Modify *ModifySpec
}

// EvalRequest carries all context needed to evaluate policies.
type EvalRequest struct {
	Tool              string
	Session           *store.Session
	ToolCallsPerMin   float64
	// ComputedRiskScore is the freshly computed score for this call.
	// Use this rather than Session.RiskScore, which reflects the previous call.
	ComputedRiskScore float64
}

// Evaluator evaluates policies in order and returns the first match.
type Evaluator struct {
	cfg *Config
}

// NewEvaluator creates an Evaluator from a loaded Config.
func NewEvaluator(cfg *Config) *Evaluator {
	return &Evaluator{cfg: cfg}
}

// Evaluate returns the first matching policy decision.
// If no policy matches, DefaultDecision from config is used (defaults to "ALLOW").
func (e *Evaluator) Evaluate(req EvalRequest) Decision {
	for _, p := range e.cfg.Policies {
		if e.matches(p.Trigger, req) {
			return Decision{
				Action: p.Decision,
				Reason: p.Reason,
				Policy: p.Name,
				Notify: p.Notify,
				Modify: p.Modify,
			}
		}
	}
	def := e.cfg.DefaultDecision
	if def == "" {
		def = "ALLOW"
	}
	return Decision{Action: def}
}

func (e *Evaluator) matches(t Trigger, req EvalRequest) bool {
	// tool filter: if specified, the call's tool must be in the list
	if len(t.Tool) > 0 && !slices.Contains(t.Tool, req.Tool) {
		return false
	}

	if t.ToolCallsPerMinute != nil && !t.ToolCallsPerMinute.Matches(req.ToolCallsPerMin) {
		return false
	}

	// risk_score uses the freshly computed score for this call, not the stored one
	if t.RiskScore != nil && !t.RiskScore.Matches(req.ComputedRiskScore) {
		return false
	}

	// session-dependent conditions: if session is nil, treat as no-match so policies
	// that depend on session data don't silently fall through to ALLOW
	if t.SessionCostUSD != nil {
		if req.Session == nil {
			return false
		}
		if !t.SessionCostUSD.Matches(req.Session.CostUSD) {
			return false
		}
	}

	return true
}
