import type { InterceptRequest, InterceptResponse, PendingDecision } from './types.js'

export class AegisClient {
  private readonly base: string
  private readonly apiKey: string

  constructor(base: string, apiKey: string) {
    this.base = base.replace(/\/$/, '')
    this.apiKey = apiKey
  }

  async intercept(req: InterceptRequest): Promise<InterceptResponse> {
    const res = await fetch(`${this.base}/v1/intercept`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Aegis-Key': this.apiKey,
      },
      body: JSON.stringify(req),
    })

    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText)
      throw new Error(`aegis: intercept failed (${res.status}): ${text}`)
    }

    return res.json() as Promise<InterceptResponse>
  }

  // getDecision polls a deferred decision for its current resolution status.
  async getDecision(id: string, agentId: string): Promise<PendingDecision> {
    const url = `${this.base}/v1/decisions/${encodeURIComponent(id)}?agent_id=${encodeURIComponent(agentId)}`
    const res = await fetch(url, {
      method: 'GET',
      headers: { 'X-Aegis-Key': this.apiKey },
    })

    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText)
      throw new Error(`aegis: decision poll failed (${res.status}): ${text}`)
    }

    return res.json() as Promise<PendingDecision>
  }
}
