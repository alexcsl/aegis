package scorer

import (
	"math"
	"time"

	"github.com/aegis-ai/aegis/internal/store"
)

// DefaultSensitiveTools is the built-in fallback set of high-risk tool names.
// It is used when ScoringConfig.SensitiveTools is empty.
var DefaultSensitiveTools = map[string]bool{
	"execute_sql":       true,
	"execute_sql_write": true,
	"delete_file":       true,
	"send_email":        true,
	"http_request":      true,
	"shell":             true,
	"code_exec":         true,
	"write_file":        true,
}

// ScoringConfig holds tunable parameters for Compute.
// Zero values fall back to built-in defaults.
type ScoringConfig struct {
	// SensitiveTools overrides DefaultSensitiveTools when non-empty.
	SensitiveTools map[string]bool
	// SensitiveScore is the signal value for a sensitive tool hit (default 0.8).
	SensitiveScore float64
}

// Score holds the decomposed risk signals.
type Score struct {
	Total       float64 `json:"total"`
	Rate        float64 `json:"rate"`
	Escalation  float64 `json:"escalation"`
	Sensitivity float64 `json:"sensitivity"`
	Cost        float64 `json:"cost"`
}

// Compute returns a risk score for a new tool call given session history.
// recentCalls is the number of calls in the last 60 seconds.
func Compute(sess *store.Session, history []store.ToolCall, tool string, recentCalls int, cfg ScoringConfig) Score {
	if sess == nil {
		return Score{}
	}

	rate := rateSignal(recentCalls)
	esc := escalationSignal(history)
	sens := sensitivitySignal(tool, cfg)
	cost := costSignal(sess.CostUSD)

	total := math.Min(1.0, rate*0.25+esc*0.25+sens*0.3+cost*0.2)

	return Score{
		Total:       total,
		Rate:        rate,
		Escalation:  esc,
		Sensitivity: sens,
		Cost:        cost,
	}
}

// rateSignal saturates at 30 calls/min -> 1.0.
func rateSignal(callsLastMinute int) float64 {
	return math.Min(1.0, float64(callsLastMinute)/30.0)
}

// escalationSignal checks if recent calls are bunched in a short burst.
// assumes history is ordered newest-first, as returned by store.GetToolCallHistory.
func escalationSignal(history []store.ToolCall) float64 {
	if len(history) < 5 {
		return 0
	}
	newest := history[0].Timestamp
	oldest := history[4].Timestamp
	window := newest.Sub(oldest)
	switch {
	case window < 10*time.Second:
		return 0.8
	case window < 30*time.Second:
		return 0.4
	default:
		return 0
	}
}

// sensitivitySignal returns a penalty when tool is in the configured sensitive set.
func sensitivitySignal(tool string, cfg ScoringConfig) float64 {
	set := cfg.SensitiveTools
	if len(set) == 0 {
		set = DefaultSensitiveTools
	}
	if !set[tool] {
		return 0
	}
	score := cfg.SensitiveScore
	if score == 0 {
		score = 0.8
	}
	return score
}

// costSignal saturates at $20 accumulated session cost -> 1.0.
func costSignal(costUSD float64) float64 {
	return math.Min(1.0, costUSD/20.0)
}
