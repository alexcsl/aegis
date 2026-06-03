export type Decision = 'ALLOW' | 'DENY' | 'MODIFY' | 'DEFER'

export interface InterceptRequest {
  session_id: string
  agent_id: string
  tool: string
  args: Record<string, unknown>
  context?: string
  cost_usd?: number
}

export interface InterceptResponse {
  decision: Decision
  reason?: string
  policy?: string
  risk_score: number
  latency_ms: number
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
}
