package store

import "time"

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
