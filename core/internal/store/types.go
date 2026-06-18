package store

import "time"

// Metrics holds aggregated statistics over a time window.
type Metrics struct {
	PeriodHours    int            `json:"period_hours"`
	ActiveSessions int            `json:"active_sessions"`
	TotalDecisions int            `json:"total_decisions"`
	Decisions      map[string]int `json:"decisions"`
	AvgRiskScore   float64        `json:"avg_risk_score"`
	TopTools       []ToolCount    `json:"top_tools"`
	TopPolicies    []PolicyCount  `json:"top_policies"`
}

type ToolCount struct {
	Tool  string `json:"tool"`
	Count int    `json:"count"`
}

type PolicyCount struct {
	Policy string `json:"policy"`
	Count  int    `json:"count"`
}

type Session struct {
	ID            string    `json:"session_id"`
	AgentID       string    `json:"agent_id"`
	StartTime     time.Time `json:"start_time"`
	InitialIntent string    `json:"initial_intent,omitempty"`
	RiskScore     float64   `json:"risk_score"`
	Flags         []string  `json:"flags"`
	CostUSD       float64   `json:"cost_usd"`
	TokenCount    int       `json:"token_count"`
	ToolCallCount int       `json:"tool_call_count"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type ToolCall struct {
	Tool      string         `json:"tool"`
	Args      map[string]any `json:"args"`
	Decision  string         `json:"decision"`
	Timestamp time.Time      `json:"timestamp"`
	CostUSD   float64        `json:"cost_usd"`
}

// PendingDecision is a tool call suspended by a DEFER policy, awaiting
// approval or rejection by a human operator.
type PendingDecision struct {
	ID         string         `json:"id"`
	SessionID  string         `json:"session_id"`
	AgentID    string         `json:"agent_id"`
	Tool       string         `json:"tool"`
	Args       map[string]any `json:"args"`
	Reason     string         `json:"reason,omitempty"`
	Policy     string         `json:"policy,omitempty"`
	Status     string         `json:"status"` // pending | approved | rejected
	CreatedAt  time.Time      `json:"created_at"`
	ResolvedAt *time.Time     `json:"resolved_at,omitempty"`
}

type Trace struct {
	TraceID         string         `json:"trace_id"`
	SessionID       string         `json:"session_id"`
	AgentID         string         `json:"agent_id"`
	Timestamp       time.Time      `json:"timestamp"`
	Tool            string         `json:"tool"`
	Input           map[string]any `json:"input"`
	Decision        string         `json:"decision"`
	PolicyTriggered string         `json:"policy_triggered,omitempty"`
	RiskScore       float64        `json:"risk_score"`
	LatencyMs       int64          `json:"latency_ms"`
	CostUSD         float64        `json:"cost_usd"`
}
