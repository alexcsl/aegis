import type { InterceptRequest, InterceptResponse } from './types.js'

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
}
