import { AegisClient } from './client.js'
import type { AegisConfig, AegisTool, InterceptResponse } from './types.js'

export type {
  AegisConfig,
  AegisTool,
  Decision,
  DecisionStatus,
  InterceptRequest,
  InterceptResponse,
  PendingDecision,
} from './types.js'

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))

// thrown when a tool call is blocked by an aegis policy.
export class DeniedError extends Error {
  readonly response: InterceptResponse
  readonly tool: string

  constructor(tool: string, response: InterceptResponse) {
    const msg = response.reason
      ? `aegis denied "${tool}": ${response.reason}`
      : `aegis denied "${tool}" via policy "${response.policy ?? 'unknown'}"`
    super(msg)
    this.name = 'DeniedError'
    this.response = response
    this.tool = tool
  }
}

// Aegis wraps your agent tools with behavioral authorization.
//
// const aegis = new Aegis({ agentId: 'my-agent' })
// const tools = aegis.wrapAll({ searchWeb, readFile, sendEmail })
export class Aegis {
  private readonly client: AegisClient
  private readonly sessionId: string
  private readonly agentId: string
  private readonly onDeny?: AegisConfig['onDeny']
  private readonly failOpen: boolean
  private readonly deferPollIntervalMs: number
  private readonly deferTimeoutMs: number

  constructor(config: AegisConfig = {}) {
    const env = (typeof process !== 'undefined' ? process.env : {}) as Record<string, string | undefined>
    const url = config.url ?? env['AEGIS_URL'] ?? 'http://localhost:8080'
    const apiKey = config.apiKey ?? env['AEGIS_API_KEY'] ?? ''

    if (!apiKey) {
      throw new Error('aegis: api key is required - set AEGIS_API_KEY or pass apiKey in config')
    }

    this.client = new AegisClient(url, apiKey)
    this.sessionId = config.sessionId ?? globalThis.crypto.randomUUID()
    this.agentId = config.agentId ?? 'default'
    this.onDeny = config.onDeny
    this.failOpen = config.failOpen ?? false
    this.deferPollIntervalMs = config.deferPollIntervalMs ?? 2000
    this.deferTimeoutMs = config.deferTimeoutMs ?? 300_000
  }

  // wrap returns a protected version of a single tool.
  // By default, if the Aegis core is unreachable the call is blocked (fail-closed).
  // Set failOpen: true in config to allow calls through when the core is down.
  wrap<TArgs extends Record<string, unknown>, TResult>(
    tool: AegisTool<TArgs, TResult>,
  ): AegisTool<TArgs, TResult> {
    const execute = async (args: TArgs): Promise<TResult> => {
      let response: InterceptResponse
      try {
        response = await this.client.intercept({
          session_id: this.sessionId,
          agent_id: this.agentId,
          tool: tool.name,
          args: args as Record<string, unknown>,
        })
      } catch (err) {
        if (this.failOpen) {
          return tool.execute(args)
        }
        throw new Error(
          `aegis: core unreachable for tool "${tool.name}" — call blocked (failOpen is false). ` +
          `Original error: ${err instanceof Error ? err.message : String(err)}`,
        )
      }

      switch (response.decision) {
        case 'ALLOW':
          return tool.execute(args)
        case 'MODIFY':
          // Execute with the server-rewritten args; fall back to the originals
          // if the server signalled MODIFY without providing them.
          return tool.execute((response.modified_args as TArgs) ?? args)
        case 'DEFER':
          // Block until a human approves; throws on reject or timeout (fail-closed).
          await this.awaitApproval(response, tool.name)
          return tool.execute(args)
        default:
          // DENY or any unexpected decision — fail closed.
          this.onDeny?.(response, tool.name)
          throw new DeniedError(tool.name, response)
      }
    }

    const wrapped: AegisTool<TArgs, TResult> = tool.description !== undefined
      ? { name: tool.name, description: tool.description, execute }
      : { name: tool.name, execute }

    return wrapped
  }

  // awaitApproval polls a deferred decision until it is approved (returns),
  // rejected (throws DeniedError), or the timeout elapses (throws — fail-closed).
  private async awaitApproval(response: InterceptResponse, toolName: string): Promise<void> {
    const id = response.decision_id
    if (!id) {
      this.onDeny?.(response, toolName)
      throw new DeniedError(toolName, response)
    }
    const deadline = Date.now() + this.deferTimeoutMs
    for (;;) {
      const pd = await this.client.getDecision(id, this.agentId)
      if (pd.status === 'approved') return
      if (pd.status === 'rejected') {
        this.onDeny?.(response, toolName)
        throw new DeniedError(toolName, response)
      }
      if (Date.now() >= deadline) {
        throw new Error(
          `aegis: tool "${toolName}" was deferred for approval but timed out after ${this.deferTimeoutMs}ms — call blocked (fail-closed)`,
        )
      }
      await sleep(this.deferPollIntervalMs)
    }
  }

  // wrapAll wraps every tool in a keyed object, returning the same shape.
  wrapAll<T extends Record<string, AegisTool>>(tools: T): T {
    return Object.fromEntries(
      Object.entries(tools).map(([k, t]) => [k, this.wrap(t)]),
    ) as T
  }
}
