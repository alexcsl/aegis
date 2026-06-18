package policy

import (
	"testing"

	"github.com/aegis-ai/aegis/internal/store"
)

func ptr(f float64) *float64 { return &f }

// Condition.Matches

func TestConditionMatches(t *testing.T) {
	cases := []struct {
		name string
		cond Condition
		val  float64
		want bool
	}{
		{"gt pass", Condition{Gt: ptr(0.5)}, 0.6, true},
		{"gt fail", Condition{Gt: ptr(0.5)}, 0.5, false},
		{"gte pass", Condition{Gte: ptr(0.5)}, 0.5, true},
		{"gte fail", Condition{Gte: ptr(0.5)}, 0.4, false},
		{"lt pass", Condition{Lt: ptr(0.5)}, 0.4, true},
		{"lt fail", Condition{Lt: ptr(0.5)}, 0.5, false},
		{"lte pass", Condition{Lte: ptr(0.5)}, 0.5, true},
		{"lte fail", Condition{Lte: ptr(0.5)}, 0.6, false},
		{"range pass", Condition{Gt: ptr(0.3), Lte: ptr(0.8)}, 0.5, true},
		{"range fail low", Condition{Gt: ptr(0.3), Lte: ptr(0.8)}, 0.2, false},
		{"range fail high", Condition{Gt: ptr(0.3), Lte: ptr(0.8)}, 0.9, false},
		{"empty matches all", Condition{}, 999, true},
	}
	for _, c := range cases {
		got := c.cond.Matches(c.val)
		if got != c.want {
			t.Errorf("%s: Matches(%v) = %v, want %v", c.name, c.val, got, c.want)
		}
	}
}

func TestConditionNilMatches(t *testing.T) {
	var c *Condition
	if c.Matches(0.5) {
		t.Error("nil Condition.Matches should return false")
	}
}

// Evaluator.Evaluate

func cfg(policies ...Policy) *Config {
	return &Config{Version: 1, Policies: policies}
}

func TestEvaluateNoPolices(t *testing.T) {
	e := NewEvaluator(cfg())
	d := e.Evaluate(EvalRequest{Tool: "delete_file"})
	if d.Action != "ALLOW" {
		t.Errorf("expected ALLOW with no policies, got %s", d.Action)
	}
}

func TestEvaluateToolFilter(t *testing.T) {
	e := NewEvaluator(cfg(Policy{
		Name:     "block-delete",
		Trigger:  Trigger{Tool: []string{"delete_file"}},
		Decision: "DENY",
		Reason:   "destructive",
	}))

	if d := e.Evaluate(EvalRequest{Tool: "delete_file"}); d.Action != "DENY" {
		t.Errorf("expected DENY for delete_file, got %s", d.Action)
	}
	if d := e.Evaluate(EvalRequest{Tool: "search_web"}); d.Action != "ALLOW" {
		t.Errorf("expected ALLOW for search_web, got %s", d.Action)
	}
}

func TestEvaluateFirstMatchWins(t *testing.T) {
	e := NewEvaluator(cfg(
		Policy{Name: "p1", Trigger: Trigger{Tool: []string{"exec"}}, Decision: "DENY", Reason: "first"},
		Policy{Name: "p2", Trigger: Trigger{Tool: []string{"exec"}}, Decision: "ALLOW", Reason: "second"},
	))
	d := e.Evaluate(EvalRequest{Tool: "exec"})
	if d.Policy != "p1" || d.Action != "DENY" {
		t.Errorf("first-match failed: got policy=%s action=%s", d.Policy, d.Action)
	}
}

func TestEvaluateRiskScoreCondition(t *testing.T) {
	e := NewEvaluator(cfg(Policy{
		Name:     "high-risk",
		Trigger:  Trigger{RiskScore: &Condition{Gte: ptr(0.8)}},
		Decision: "DENY",
		Reason:   "risk too high",
	}))

	if d := e.Evaluate(EvalRequest{Tool: "x", ComputedRiskScore: 0.9}); d.Action != "DENY" {
		t.Errorf("expected DENY at 0.9 risk, got %s", d.Action)
	}
	if d := e.Evaluate(EvalRequest{Tool: "x", ComputedRiskScore: 0.5}); d.Action != "ALLOW" {
		t.Errorf("expected ALLOW at 0.5 risk, got %s", d.Action)
	}
}

func TestEvaluateRateCondition(t *testing.T) {
	e := NewEvaluator(cfg(Policy{
		Name:     "rate-limit",
		Trigger:  Trigger{ToolCallsPerMinute: &Condition{Gt: ptr(20.0)}},
		Decision: "DENY",
		Reason:   "rate exceeded",
	}))

	if d := e.Evaluate(EvalRequest{Tool: "x", ToolCallsPerMin: 25}); d.Action != "DENY" {
		t.Errorf("expected DENY at 25 calls/min, got %s", d.Action)
	}
	if d := e.Evaluate(EvalRequest{Tool: "x", ToolCallsPerMin: 10}); d.Action != "ALLOW" {
		t.Errorf("expected ALLOW at 10 calls/min, got %s", d.Action)
	}
}

func TestEvaluateCostConditionNilSession(t *testing.T) {
	// session_cost_usd trigger with nil session must not match (no silent pass-through)
	e := NewEvaluator(cfg(Policy{
		Name:     "cost-gate",
		Trigger:  Trigger{SessionCostUSD: &Condition{Gt: ptr(5.0)}},
		Decision: "DENY",
		Reason:   "cost exceeded",
	}))

	if d := e.Evaluate(EvalRequest{Tool: "x", Session: nil}); d.Action != "ALLOW" {
		t.Errorf("nil session should not match cost trigger, got %s", d.Action)
	}
}

func TestEvaluateCostConditionWithSession(t *testing.T) {
	e := NewEvaluator(cfg(Policy{
		Name:     "cost-gate",
		Trigger:  Trigger{SessionCostUSD: &Condition{Gt: ptr(5.0)}},
		Decision: "DENY",
		Reason:   "cost exceeded",
	}))

	rich := &store.Session{CostUSD: 10.0}
	if d := e.Evaluate(EvalRequest{Tool: "x", Session: rich}); d.Action != "DENY" {
		t.Errorf("expected DENY at $10 cost, got %s", d.Action)
	}

	cheap := &store.Session{CostUSD: 1.0}
	if d := e.Evaluate(EvalRequest{Tool: "x", Session: cheap}); d.Action != "ALLOW" {
		t.Errorf("expected ALLOW at $1 cost, got %s", d.Action)
	}
}

func TestEvaluateCatchAllPolicy(t *testing.T) {
	// a policy with no tool filter applies to every tool
	e := NewEvaluator(cfg(Policy{
		Name:     "catch-all",
		Trigger:  Trigger{},
		Decision: "DENY",
		Reason:   "default deny",
	}))

	for _, tool := range []string{"search_web", "delete_file", "send_email", "anything"} {
		if d := e.Evaluate(EvalRequest{Tool: tool}); d.Action != "DENY" {
			t.Errorf("catch-all should DENY %s, got %s", tool, d.Action)
		}
	}
}

func TestEvaluateDecisionFieldsPopulated(t *testing.T) {
	e := NewEvaluator(cfg(Policy{
		Name:     "my-policy",
		Trigger:  Trigger{Tool: []string{"exec"}},
		Decision: "DENY",
		Reason:   "not allowed",
	}))
	d := e.Evaluate(EvalRequest{Tool: "exec"})
	if d.Policy != "my-policy" {
		t.Errorf("expected Policy='my-policy', got %q", d.Policy)
	}
	if d.Reason != "not allowed" {
		t.Errorf("expected Reason='not allowed', got %q", d.Reason)
	}
}

func TestEvaluateDefaultDecisionDeny(t *testing.T) {
	// With default_decision: DENY, unknown tools must be blocked even with no matching policy.
	c := &Config{
		Version:         1,
		DefaultDecision: "DENY",
		Policies: []Policy{
			{Name: "allow-search", Trigger: Trigger{Tool: []string{"search_web"}}, Decision: "ALLOW"},
		},
	}
	e := NewEvaluator(c)

	if d := e.Evaluate(EvalRequest{Tool: "search_web"}); d.Action != "ALLOW" {
		t.Errorf("explicitly allowed tool: expected ALLOW, got %s", d.Action)
	}
	if d := e.Evaluate(EvalRequest{Tool: "delete_file"}); d.Action != "DENY" {
		t.Errorf("unmatched tool with default DENY: expected DENY, got %s", d.Action)
	}
}

func TestEvaluateDefaultDecisionAllowIsBackwardsCompatible(t *testing.T) {
	// Empty default_decision must still behave as ALLOW (backward compat).
	c := &Config{Version: 1}
	e := NewEvaluator(c)
	if d := e.Evaluate(EvalRequest{Tool: "anything"}); d.Action != "ALLOW" {
		t.Errorf("empty DefaultDecision should default to ALLOW, got %s", d.Action)
	}
}

func TestEvaluateTokenCountTrigger(t *testing.T) {
	e := NewEvaluator(cfg(Policy{
		Name:     "token-cap",
		Trigger:  Trigger{TokenCount: &Condition{Gt: ptr(500000)}},
		Decision: "DENY",
		Reason:   "token budget exceeded",
	}))

	rich := &store.Session{}
	if d := e.Evaluate(EvalRequest{Tool: "x", Session: rich, TokenCount: 600000}); d.Action != "DENY" {
		t.Errorf("expected DENY at 600k tokens, got %s", d.Action)
	}
	if d := e.Evaluate(EvalRequest{Tool: "x", Session: rich, TokenCount: 100000}); d.Action != "ALLOW" {
		t.Errorf("expected ALLOW at 100k tokens, got %s", d.Action)
	}
	if d := e.Evaluate(EvalRequest{Tool: "x", Session: nil, TokenCount: 600000}); d.Action != "ALLOW" {
		t.Errorf("nil session should not match token_count trigger, got %s", d.Action)
	}
}

func TestEvaluateToolCallCountTrigger(t *testing.T) {
	e := NewEvaluator(cfg(Policy{
		Name:     "call-cap",
		Trigger:  Trigger{ToolCallCount: &Condition{Gte: ptr(100.0)}},
		Decision: "DEFER",
		Reason:   "high call volume",
	}))

	sess := &store.Session{}
	if d := e.Evaluate(EvalRequest{Tool: "x", Session: sess, ToolCallCount: 100}); d.Action != "DEFER" {
		t.Errorf("expected DEFER at 100 calls, got %s", d.Action)
	}
	if d := e.Evaluate(EvalRequest{Tool: "x", Session: sess, ToolCallCount: 50}); d.Action != "ALLOW" {
		t.Errorf("expected ALLOW at 50 calls, got %s", d.Action)
	}
	if d := e.Evaluate(EvalRequest{Tool: "x", Session: nil, ToolCallCount: 100}); d.Action != "ALLOW" {
		t.Errorf("nil session should not match tool_call_count trigger, got %s", d.Action)
	}
}
