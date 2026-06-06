export type Decision = 'ALLOW' | 'DENY' | 'MODIFY' | 'DEFER'

export interface InterceptRequest {
  session_id: string
  agent_id: string
  tool: string
  args: Record<string, unknown>
  context?: string
  cost_usd?: number
  token_count?: number
}

export interface InterceptResponse {
  decision: Decision
  reason?: string
  policy?: string
  risk_score: number
  latency_ms: number
  /** Set on DEFER: the id to poll via GET /v1/decisions/:id for resolution. */
  decision_id?: string
  /** Set on MODIFY: the rewritten args the SDK must execute the tool with. */
  modified_args?: Record<string, unknown>
}

export type DecisionStatus = 'pending' | 'approved' | 'rejected'

export interface PendingDecision {
  id: string
  session_id: string
  agent_id: string
  tool: string
  status: DecisionStatus
  reason?: string
  policy?: string
}

export interface AegisTool<
  TArgs extends Record<string, unknown> = Record<string, unknown>,
  TResult = unknown,
> {
  name: string
  description?: string
  execute: (args: TArgs) => Promise<TResult>
}

export interface AegisConfig {
  url?: string
  apiKey?: string
  sessionId?: string
  agentId?: string
  onDeny?: (response: InterceptResponse, toolName: string) => void
  /**
   * When true, a network error reaching the Aegis core will be swallowed and
   * the tool call will proceed as if it were ALLOW.
   *
   * Default: false (fail-closed). Only set this in local dev environments where
   * the core is not running. Never use in production.
   */
  failOpen?: boolean
  /**
   * How often (ms) to poll a DEFER decision for resolution. Default: 2000.
   */
  deferPollIntervalMs?: number
  /**
   * How long (ms) to wait for a DEFER decision to be approved before failing
   * closed (the call is rejected). Default: 300000 (5 minutes).
   */
  deferTimeoutMs?: number
}
