package scorer

import (
	"testing"
	"time"

	"github.com/aegis-ai/aegis/internal/store"
)

func TestRateSignal(t *testing.T) {
	cases := []struct {
		calls int
		want  float64
	}{
		{0, 0},
		{15, 0.5},
		{30, 1.0},
		{60, 1.0}, // saturates at 1.0
	}
	for _, c := range cases {
		got := rateSignal(c.calls)
		if got != c.want {
			t.Errorf("rateSignal(%d) = %v, want %v", c.calls, got, c.want)
		}
	}
}

func TestCostSignal(t *testing.T) {
	cases := []struct {
		cost float64
		want float64
	}{
		{0, 0},
		{10, 0.5},
		{20, 1.0},
		{100, 1.0}, // saturates
	}
	for _, c := range cases {
		got := costSignal(c.cost)
		if got != c.want {
			t.Errorf("costSignal(%v) = %v, want %v", c.cost, got, c.want)
		}
	}
}

func TestSensitivitySignal(t *testing.T) {
	if sensitivitySignal("delete_file") != 0.8 {
		t.Error("expected 0.8 for delete_file")
	}
	if sensitivitySignal("search_web") != 0 {
		t.Error("expected 0 for search_web")
	}
}

func TestEscalationSignal(t *testing.T) {
	// fewer than 5 calls: no escalation
	if escalationSignal(nil) != 0 {
		t.Error("expected 0 for empty history")
	}

	now := time.Now()

	// 5 calls within 10 seconds: high escalation
	burst := make([]store.ToolCall, 5)
	for i := range burst {
		burst[i] = store.ToolCall{Timestamp: now.Add(-time.Duration(i) * time.Second)}
	}
	if escalationSignal(burst) != 0.8 {
		t.Errorf("expected 0.8 for burst, got %v", escalationSignal(burst))
	}

	// 5 calls spread over 2 minutes: no escalation
	spread := make([]store.ToolCall, 5)
	for i := range spread {
		spread[i] = store.ToolCall{Timestamp: now.Add(-time.Duration(i) * 30 * time.Second)}
	}
	if escalationSignal(spread) != 0 {
		t.Errorf("expected 0 for spread calls, got %v", escalationSignal(spread))
	}
}

func TestComputeNilSession(t *testing.T) {
	score := Compute(nil, nil, "search_web", 0)
	if score.Total != 0 {
		t.Errorf("expected 0 score for nil session, got %v", score.Total)
	}
}

func TestComputeClampsAt1(t *testing.T) {
	sess := &store.Session{CostUSD: 100}
	now := time.Now()
	burst := make([]store.ToolCall, 5)
	for i := range burst {
		burst[i] = store.ToolCall{Timestamp: now.Add(-time.Duration(i) * time.Second)}
	}
	score := Compute(sess, burst, "delete_file", 60)
	if score.Total > 1.0 {
		t.Errorf("score.Total %v exceeds 1.0", score.Total)
	}
}
