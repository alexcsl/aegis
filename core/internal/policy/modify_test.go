package policy

import (
	"testing"
)

func TestModifySpecApplySet(t *testing.T) {
	m := &ModifySpec{Set: map[string]any{"limit": 10}}
	in := map[string]any{"query": "x"}
	out := m.Apply(in)
	if out["limit"] != 10 {
		t.Errorf("expected limit=10, got %v", out["limit"])
	}
	if out["query"] != "x" {
		t.Errorf("query should be preserved, got %v", out["query"])
	}
	// input must not be mutated
	if _, ok := in["limit"]; ok {
		t.Error("Apply mutated the input map")
	}
}

func TestModifySpecApplyRedact(t *testing.T) {
	m := &ModifySpec{Redact: []string{"password"}}
	out := m.Apply(map[string]any{"password": "hunter2", "user": "bob"})
	if out["password"] != "[redacted]" {
		t.Errorf("expected redacted password, got %v", out["password"])
	}
	if out["user"] != "bob" {
		t.Errorf("user should be preserved, got %v", out["user"])
	}
}

func TestModifySpecApplyRedactMissingKeyIsNoop(t *testing.T) {
	m := &ModifySpec{Redact: []string{"password"}}
	out := m.Apply(map[string]any{"user": "bob"})
	if _, ok := out["password"]; ok {
		t.Error("redact should not create a missing key")
	}
}

func TestModifySpecApplyRemove(t *testing.T) {
	m := &ModifySpec{Remove: []string{"debug"}}
	out := m.Apply(map[string]any{"debug": true, "query": "x"})
	if _, ok := out["debug"]; ok {
		t.Error("debug key should have been removed")
	}
	if out["query"] != "x" {
		t.Errorf("query should be preserved, got %v", out["query"])
	}
}

func TestModifySpecApplyNilSpec(t *testing.T) {
	var m *ModifySpec
	in := map[string]any{"a": 1}
	out := m.Apply(in)
	if out["a"] != 1 {
		t.Errorf("nil spec should pass args through, got %v", out["a"])
	}
}

func TestValidateModifyRequiresBlock(t *testing.T) {
	c := &Config{Version: 1, Policies: []Policy{
		{Name: "m", Decision: "MODIFY"},
	}}
	if err := c.Validate(); err == nil {
		t.Error("MODIFY without a modify block should fail validation")
	}
}

func TestValidateModifyBlockOnlyWithModifyDecision(t *testing.T) {
	c := &Config{Version: 1, Policies: []Policy{
		{Name: "d", Decision: "DENY", Modify: &ModifySpec{Remove: []string{"x"}}},
	}}
	if err := c.Validate(); err == nil {
		t.Error("modify block on a non-MODIFY decision should fail validation")
	}
}

func TestValidateAcceptsValidModify(t *testing.T) {
	c := &Config{Version: 1, Policies: []Policy{
		{Name: "m", Decision: "MODIFY", Modify: &ModifySpec{Set: map[string]any{"limit": 5}}},
	}}
	if err := c.Validate(); err != nil {
		t.Errorf("valid MODIFY policy should pass validation, got %v", err)
	}
}

func TestValidateRejectsUnknownDecision(t *testing.T) {
	c := &Config{Version: 1, Policies: []Policy{
		{Name: "typo", Decision: "DNEY"},
	}}
	if err := c.Validate(); err == nil {
		t.Error("unknown decision value should fail validation")
	}
}

func TestEvaluateCarriesModifySpec(t *testing.T) {
	spec := &ModifySpec{Set: map[string]any{"limit": 5}}
	e := NewEvaluator(cfg(Policy{
		Name:     "cap-limit",
		Trigger:  Trigger{Tool: []string{"search"}},
		Decision: "MODIFY",
		Modify:   spec,
	}))
	d := e.Evaluate(EvalRequest{Tool: "search"})
	if d.Action != "MODIFY" {
		t.Fatalf("expected MODIFY, got %s", d.Action)
	}
	if d.Modify == nil {
		t.Fatal("expected Modify spec to be carried through")
	}
	if d.Modify.Set["limit"] != 5 {
		t.Errorf("modify spec not carried correctly: %v", d.Modify.Set)
	}
}
