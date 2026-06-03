package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds the parsed aegis.config.yaml.
type Config struct {
	Version         int      `yaml:"version"`
	Policies        []Policy `yaml:"policies"`
	// DefaultDecision is returned when no policy matches.
	// Accepted values: "ALLOW" (default) or "DENY".
	// Set to "DENY" for an allowlist posture where only explicitly approved tools pass.
	DefaultDecision string   `yaml:"default_decision,omitempty"`
}

// Policy is a single rule: when trigger matches, apply decision.
type Policy struct {
	Name     string      `yaml:"name"`
	Trigger  Trigger     `yaml:"trigger"`
	Decision string      `yaml:"decision"` // ALLOW | DENY | DEFER | MODIFY
	Reason   string      `yaml:"reason,omitempty"`
	// Notify is an optional webhook URL. When set, a JSON payload is POSTed to it
	// (best effort) whenever this policy fires — primarily used to alert a human
	// that a DEFER decision is awaiting approval.
	Notify   string      `yaml:"notify,omitempty"`
	// Modify is required when Decision is MODIFY. It describes how the tool's
	// input arguments are rewritten before execution.
	Modify   *ModifySpec `yaml:"modify,omitempty"`
}

// ModifySpec rewrites a tool call's input arguments before execution.
// Operations are applied in order: set, then redact, then remove.
type ModifySpec struct {
	// Set assigns top-level keys to fixed values (e.g. force a `limit`).
	Set map[string]any `yaml:"set,omitempty"`
	// Redact replaces the value of each named top-level key with "[redacted]".
	Redact []string `yaml:"redact,omitempty"`
	// Remove deletes each named top-level key.
	Remove []string `yaml:"remove,omitempty"`
}

// Apply returns a shallow copy of args with the spec's operations applied.
// The input map is never mutated. A nil spec returns args unchanged.
func (m *ModifySpec) Apply(args map[string]any) map[string]any {
	out := make(map[string]any, len(args))
	for k, v := range args {
		out[k] = v
	}
	if m == nil {
		return out
	}
	for k, v := range m.Set {
		out[k] = v
	}
	for _, k := range m.Redact {
		if _, ok := out[k]; ok {
			out[k] = "[redacted]"
		}
	}
	for _, k := range m.Remove {
		delete(out, k)
	}
	return out
}

// Trigger defines the conditions that activate a policy.
type Trigger struct {
	Tool               []string   `yaml:"tool,omitempty"`
	ToolCallsPerMinute *Condition `yaml:"tool_calls_per_minute,omitempty"`
	SessionCostUSD     *Condition `yaml:"session_cost_usd,omitempty"`
	RiskScore          *Condition `yaml:"risk_score,omitempty"`
}

// Condition is a numeric comparison (gt, gte, lt, lte).
type Condition struct {
	Gt  *float64 `yaml:"gt,omitempty"`
	Gte *float64 `yaml:"gte,omitempty"`
	Lt  *float64 `yaml:"lt,omitempty"`
	Lte *float64 `yaml:"lte,omitempty"`
}

// Matches reports whether val satisfies all non-nil comparisons.
func (c *Condition) Matches(val float64) bool {
	if c == nil {
		return false
	}
	if c.Gt != nil && !(val > *c.Gt) {
		return false
	}
	if c.Gte != nil && !(val >= *c.Gte) {
		return false
	}
	if c.Lt != nil && !(val < *c.Lt) {
		return false
	}
	if c.Lte != nil && !(val <= *c.Lte) {
		return false
	}
	return true
}

// Validate checks that Config contains only recognised values.
// Call this after LoadConfig to catch typos in policy files at startup.
func (cfg *Config) Validate() error {
	validDefault := map[string]bool{"": true, "ALLOW": true, "DENY": true}
	if !validDefault[cfg.DefaultDecision] {
		return fmt.Errorf("invalid default_decision %q: must be ALLOW or DENY", cfg.DefaultDecision)
	}
	validDecision := map[string]bool{"ALLOW": true, "DENY": true, "DEFER": true, "MODIFY": true}
	for i, p := range cfg.Policies {
		if p.Name == "" {
			return fmt.Errorf("policy[%d] has no name", i)
		}
		if !validDecision[p.Decision] {
			return fmt.Errorf("policy %q: invalid decision %q (must be ALLOW, DENY, DEFER, or MODIFY)", p.Name, p.Decision)
		}
		if p.Decision == "MODIFY" && p.Modify == nil {
			return fmt.Errorf("policy %q: MODIFY decision requires a modify block", p.Name)
		}
		if p.Decision != "MODIFY" && p.Modify != nil {
			return fmt.Errorf("policy %q: modify block is only valid with a MODIFY decision", p.Name)
		}
	}
	return nil
}

// LoadConfig reads the YAML config from path.
// If the file does not exist, a default empty config is returned.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{Version: 1}, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}
