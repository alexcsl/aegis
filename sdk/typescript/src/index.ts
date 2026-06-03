import { AegisClient } from './client.js'
import type { AegisConfig, AegisTool, InterceptResponse } from './types.js'

export type { AegisConfig, AegisTool, Decision, InterceptRequest, InterceptResponse } from './types.js'

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

      // MODIFY and DEFER are not yet implemented server-side; treat them as DENY
      // (fail-closed) rather than silently allowing the call through.
      if (response.decision !== 'ALLOW') {
        this.onDeny?.(response, tool.name)
        throw new DeniedError(tool.name, response)
      }

      return tool.execute(args)
    }

    const wrapped: AegisTool<TArgs, TResult> = tool.description !== undefined
      ? { name: tool.name, description: tool.description, execute }
      : { name: tool.name, execute }

    return wrapped
  }

  // wrapAll wraps every tool in a keyed object, returning the same shape.
  wrapAll<T extends Record<string, AegisTool>>(tools: T): T {
    return Object.fromEntries(
      Object.entries(tools).map(([k, t]) => [k, this.wrap(t)]),
    ) as T
  }
}
