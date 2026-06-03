package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store wraps a postgres connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// New connects to postgres and returns a Store.
func New(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MinConns = 2

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() {
	s.pool.Close()
}

// Ping verifies the database connection is still alive.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// Migrate runs the schema migrations. Safe to call on every startup.
func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, ddl)
	return err
}

var ddl = `
CREATE TABLE IF NOT EXISTS sessions (
	id              TEXT PRIMARY KEY,
	agent_id        TEXT        NOT NULL,
	start_time      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	initial_intent  TEXT,
	risk_score      DOUBLE PRECISION DEFAULT 0,
	flags           JSONB        DEFAULT '[]',
	cost_usd        DOUBLE PRECISION DEFAULT 0,
	token_count     INTEGER      DEFAULT 0,
	tool_call_count INTEGER      DEFAULT 0,
	updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS sessions_agent_id_idx ON sessions (agent_id);
CREATE INDEX IF NOT EXISTS sessions_updated_at_idx ON sessions (updated_at);

CREATE TABLE IF NOT EXISTS tool_calls (
	id         BIGSERIAL PRIMARY KEY,
	session_id TEXT        NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
	tool       TEXT        NOT NULL,
	args       JSONB,
	decision   TEXT        NOT NULL,
	timestamp  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	cost_usd   DOUBLE PRECISION DEFAULT 0
);

CREATE INDEX IF NOT EXISTS tool_calls_session_id_idx ON tool_calls (session_id);
CREATE INDEX IF NOT EXISTS tool_calls_timestamp_idx  ON tool_calls (timestamp);

CREATE TABLE IF NOT EXISTS traces (
	trace_id         TEXT PRIMARY KEY,
	session_id       TEXT        NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
	agent_id         TEXT        NOT NULL,
	timestamp        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	tool             TEXT        NOT NULL,
	input            JSONB,
	decision         TEXT        NOT NULL,
	policy_triggered TEXT,
	risk_score       DOUBLE PRECISION,
	latency_ms       BIGINT,
	cost_usd         DOUBLE PRECISION DEFAULT 0
);

CREATE INDEX IF NOT EXISTS traces_session_id_idx ON traces (session_id);
CREATE INDEX IF NOT EXISTS traces_timestamp_idx  ON traces (timestamp);
`

// GetOrCreateSession upserts a session row and returns it.
func (s *Store) GetOrCreateSession(ctx context.Context, sessionID, agentID, initialIntent string) (*Session, error) {
	var (
		sess      Session
		flagsJSON []byte
		intent    *string
	)
	err := s.pool.QueryRow(ctx, `
		INSERT INTO sessions (id, agent_id, initial_intent, start_time, updated_at)
		VALUES ($1, $2, NULLIF($3, ''), NOW(), NOW())
		ON CONFLICT (id) DO UPDATE SET updated_at = NOW()
		RETURNING id, agent_id, start_time, initial_intent, risk_score, flags,
		          cost_usd, token_count, tool_call_count, updated_at
	`, sessionID, agentID, initialIntent).Scan(
		&sess.ID, &sess.AgentID, &sess.StartTime, &intent,
		&sess.RiskScore, &flagsJSON,
		&sess.CostUSD, &sess.TokenCount, &sess.ToolCallCount, &sess.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get or create session: %w", err)
	}
	if intent != nil {
		sess.InitialIntent = *intent
	}
	_ = json.Unmarshal(flagsJSON, &sess.Flags)
	return &sess, nil
}

// GetSession returns a session by ID, or nil if not found.
func (s *Store) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	var (
		sess      Session
		flagsJSON []byte
		intent    *string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT id, agent_id, start_time, initial_intent, risk_score, flags,
		       cost_usd, token_count, tool_call_count, updated_at
		FROM sessions WHERE id = $1
	`, sessionID).Scan(
		&sess.ID, &sess.AgentID, &sess.StartTime, &intent,
		&sess.RiskScore, &flagsJSON,
		&sess.CostUSD, &sess.TokenCount, &sess.ToolCallCount, &sess.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}
	if intent != nil {
		sess.InitialIntent = *intent
	}
	_ = json.Unmarshal(flagsJSON, &sess.Flags)
	return &sess, nil
}

// UpdateSession writes updated scoring fields back to the database.
func (s *Store) UpdateSession(ctx context.Context, sess *Session) error {
	flagsJSON, _ := json.Marshal(sess.Flags)
	_, err := s.pool.Exec(ctx, `
		UPDATE sessions SET
			risk_score      = $2,
			flags           = $3,
			cost_usd        = $4,
			token_count     = $5,
			tool_call_count = $6,
			updated_at      = NOW()
		WHERE id = $1
	`, sess.ID, sess.RiskScore, flagsJSON, sess.CostUSD, sess.TokenCount, sess.ToolCallCount)
	return err
}

// AppendToolCall records a single tool call under a session.
func (s *Store) AppendToolCall(ctx context.Context, sessionID string, call ToolCall) error {
	args, _ := json.Marshal(call.Args)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO tool_calls (session_id, tool, args, decision, timestamp, cost_usd)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, sessionID, call.Tool, args, call.Decision, call.Timestamp, call.CostUSD)
	return err
}

// GetToolCallHistory returns the most recent n calls for a session, newest first.
func (s *Store) GetToolCallHistory(ctx context.Context, sessionID string, n int) ([]ToolCall, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT tool, args, decision, timestamp, cost_usd
		FROM tool_calls WHERE session_id = $1
		ORDER BY timestamp DESC LIMIT $2
	`, sessionID, n)
	if err != nil {
		return nil, fmt.Errorf("get tool calls: %w", err)
	}
	defer rows.Close()

	var calls []ToolCall
	for rows.Next() {
		var (
			c        ToolCall
			argsJSON []byte
		)
		if err := rows.Scan(&c.Tool, &argsJSON, &c.Decision, &c.Timestamp, &c.CostUSD); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(argsJSON, &c.Args)
		calls = append(calls, c)
	}
	return calls, rows.Err()
}

// InsertTrace appends an audit trace event.
func (s *Store) InsertTrace(ctx context.Context, t Trace) error {
	input, _ := json.Marshal(t.Input)
	var policy *string
	if t.PolicyTriggered != "" {
		policy = &t.PolicyTriggered
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO traces
			(trace_id, session_id, agent_id, timestamp, tool, input,
			 decision, policy_triggered, risk_score, latency_ms, cost_usd)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, t.TraceID, t.SessionID, t.AgentID, t.Timestamp, t.Tool, input,
		t.Decision, policy, t.RiskScore, t.LatencyMs, t.CostUSD)
	return err
}

// GetTraces returns recent traces for a session.
func (s *Store) GetTraces(ctx context.Context, sessionID string, limit int) ([]Trace, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT trace_id, session_id, agent_id, timestamp, tool, input,
		       decision, policy_triggered, risk_score, latency_ms, cost_usd
		FROM traces WHERE session_id = $1
		ORDER BY timestamp DESC LIMIT $2
	`, sessionID, limit)
	if err != nil {
		return nil, fmt.Errorf("get traces: %w", err)
	}
	defer rows.Close()

	var traces []Trace
	for rows.Next() {
		var (
			t         Trace
			inputJSON []byte
			policy    *string
		)
		if err := rows.Scan(
			&t.TraceID, &t.SessionID, &t.AgentID, &t.Timestamp, &t.Tool, &inputJSON,
			&t.Decision, &policy, &t.RiskScore, &t.LatencyMs, &t.CostUSD,
		); err != nil {
			return nil, err
		}
		if policy != nil {
			t.PolicyTriggered = *policy
		}
		_ = json.Unmarshal(inputJSON, &t.Input)
		traces = append(traces, t)
	}
	return traces, rows.Err()
}

// CountRecentCalls returns the number of calls for a session within the given window.
// This is done in SQL to avoid the fetch-limit problem of GetToolCallHistory.
func (s *Store) CountRecentCalls(ctx context.Context, sessionID string, window time.Duration) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM tool_calls
		WHERE session_id = $1 AND timestamp > $2
	`, sessionID, time.Now().Add(-window)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count recent calls: %w", err)
	}
	return n, nil
}

// PruneExpiredSessions removes sessions older than maxAge and cascades to related rows.
func (s *Store) PruneExpiredSessions(ctx context.Context, maxAge time.Duration) (int64, error) {
	result, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE updated_at < $1`, time.Now().Add(-maxAge))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}
