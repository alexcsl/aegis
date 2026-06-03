import { describe, it, mock, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { Aegis, DeniedError } from './index.js'
import type { AegisTool, InterceptResponse } from './types.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTool(name: string, result = 'ok'): AegisTool<Record<string, unknown>, string> {
  return {
    name,
    execute: async (_args) => result,
  }
}

function denyResponse(reason = 'blocked'): InterceptResponse {
  return { decision: 'DENY', reason, policy: 'test-policy', risk_score: 0.9, latency_ms: 1 }
}

function allowResponse(): InterceptResponse {
  return { decision: 'ALLOW', risk_score: 0.1, latency_ms: 1 }
}

function modifyResponse(modified: Record<string, unknown>): InterceptResponse {
  return { decision: 'MODIFY', modified_args: modified, risk_score: 0.2, latency_ms: 1 }
}

function deferResponse(id = 'dec-1'): InterceptResponse {
  return { decision: 'DEFER', decision_id: id, reason: 'needs approval', policy: 'defer-policy', risk_score: 0.5, latency_ms: 1 }
}

// ---------------------------------------------------------------------------
// Aegis constructor
// ---------------------------------------------------------------------------

describe('Aegis constructor', () => {
  it('throws when no api key is provided', () => {
    const origEnv = process.env['AEGIS_API_KEY']
    delete process.env['AEGIS_API_KEY']
    assert.throws(
      () => new Aegis({}),
      /api key is required/,
    )
    if (origEnv !== undefined) process.env['AEGIS_API_KEY'] = origEnv
  })

  it('reads api key from env', () => {
    process.env['AEGIS_API_KEY'] = 'env-key'
    assert.doesNotThrow(() => new Aegis({}))
    delete process.env['AEGIS_API_KEY']
  })
})

// ---------------------------------------------------------------------------
// wrap — DENY
// ---------------------------------------------------------------------------

describe('Aegis.wrap — DENY', () => {
  it('throws DeniedError and does not call the underlying tool', async () => {
    process.env['AEGIS_API_KEY'] = 'test-key-for-unit-tests-only'
    const aegis = new Aegis({ agentId: 'test' })

    // Patch the internal client
    ;(aegis as any).client.intercept = async () => denyResponse('not allowed')

    let toolCalled = false
    const tool: AegisTool<Record<string, unknown>, string> = {
      name: 'delete_file',
      execute: async () => { toolCalled = true; return 'deleted' },
    }

    const wrapped = aegis.wrap(tool)
    await assert.rejects(
      () => wrapped.execute({}),
      (err: unknown) => err instanceof DeniedError,
    )
    assert.equal(toolCalled, false, 'underlying tool must not be called on DENY')
    delete process.env['AEGIS_API_KEY']
  })

  it('DeniedError carries the response and tool name', async () => {
    process.env['AEGIS_API_KEY'] = 'test-key'
    const aegis = new Aegis({ agentId: 'test' })
    ;(aegis as any).client.intercept = async () => denyResponse('too risky')

    const wrapped = aegis.wrap(makeTool('shell'))
    try {
      await wrapped.execute({})
      assert.fail('should have thrown')
    } catch (err) {
      assert.ok(err instanceof DeniedError)
      assert.equal(err.tool, 'shell')
      assert.equal(err.response.reason, 'too risky')
    }
    delete process.env['AEGIS_API_KEY']
  })
})

// ---------------------------------------------------------------------------
// wrap — ALLOW
// ---------------------------------------------------------------------------

describe('Aegis.wrap — ALLOW', () => {
  it('executes the tool and returns its result', async () => {
    process.env['AEGIS_API_KEY'] = 'test-key'
    const aegis = new Aegis({ agentId: 'test' })
    ;(aegis as any).client.intercept = async () => allowResponse()

    const result = await aegis.wrap(makeTool('search_web', 'results')).execute({})
    assert.equal(result, 'results')
    delete process.env['AEGIS_API_KEY']
  })
})

// ---------------------------------------------------------------------------
// wrap — MODIFY
// ---------------------------------------------------------------------------

describe('Aegis.wrap — MODIFY', () => {
  it('executes the tool with the server-rewritten args', async () => {
    process.env['AEGIS_API_KEY'] = 'test-key'
    const aegis = new Aegis({ agentId: 'test' })
    ;(aegis as any).client.intercept = async () => modifyResponse({ limit: 10, query: 'safe' })

    let received: Record<string, unknown> | undefined
    const tool: AegisTool<Record<string, unknown>, string> = {
      name: 'search',
      execute: async (args) => { received = args; return 'ok' },
    }

    await aegis.wrap(tool).execute({ limit: 9999, query: 'safe' })
    assert.deepEqual(received, { limit: 10, query: 'safe' })
    delete process.env['AEGIS_API_KEY']
  })

  it('falls back to original args if modified_args is missing', async () => {
    process.env['AEGIS_API_KEY'] = 'test-key'
    const aegis = new Aegis({ agentId: 'test' })
    ;(aegis as any).client.intercept = async () => ({ decision: 'MODIFY', risk_score: 0.2, latency_ms: 1 })

    let received: Record<string, unknown> | undefined
    const tool: AegisTool<Record<string, unknown>, string> = {
      name: 'search',
      execute: async (args) => { received = args; return 'ok' },
    }

    await aegis.wrap(tool).execute({ q: 'original' })
    assert.deepEqual(received, { q: 'original' })
    delete process.env['AEGIS_API_KEY']
  })
})

// ---------------------------------------------------------------------------
// wrap — DEFER
// ---------------------------------------------------------------------------

describe('Aegis.wrap — DEFER', () => {
  it('executes the tool once the decision is approved', async () => {
    process.env['AEGIS_API_KEY'] = 'test-key'
    const aegis = new Aegis({ agentId: 'test', deferPollIntervalMs: 1, deferTimeoutMs: 1000 })
    ;(aegis as any).client.intercept = async () => deferResponse('dec-approve')
    let polls = 0
    ;(aegis as any).client.getDecision = async () => {
      polls++
      return { id: 'dec-approve', status: polls >= 2 ? 'approved' : 'pending' }
    }

    const result = await aegis.wrap(makeTool('send_email', 'sent')).execute({})
    assert.equal(result, 'sent')
    assert.ok(polls >= 2, 'should have polled until approved')
    delete process.env['AEGIS_API_KEY']
  })

  it('throws DeniedError when the decision is rejected', async () => {
    process.env['AEGIS_API_KEY'] = 'test-key'
    const aegis = new Aegis({ agentId: 'test', deferPollIntervalMs: 1, deferTimeoutMs: 1000 })
    ;(aegis as any).client.intercept = async () => deferResponse('dec-reject')
    ;(aegis as any).client.getDecision = async () => ({ id: 'dec-reject', status: 'rejected' })

    let toolCalled = false
    const tool: AegisTool<Record<string, unknown>, string> = {
      name: 'send_email',
      execute: async () => { toolCalled = true; return 'sent' },
    }

    await assert.rejects(() => aegis.wrap(tool).execute({}), (err: unknown) => err instanceof DeniedError)
    assert.equal(toolCalled, false, 'tool must not run on a rejected defer')
    delete process.env['AEGIS_API_KEY']
  })

  it('fails closed when the decision is never resolved before timeout', async () => {
    process.env['AEGIS_API_KEY'] = 'test-key'
    const aegis = new Aegis({ agentId: 'test', deferPollIntervalMs: 1, deferTimeoutMs: 20 })
    ;(aegis as any).client.intercept = async () => deferResponse('dec-timeout')
    ;(aegis as any).client.getDecision = async () => ({ id: 'dec-timeout', status: 'pending' })

    await assert.rejects(() => aegis.wrap(makeTool('send_email')).execute({}), /timed out/)
    delete process.env['AEGIS_API_KEY']
  })
})

// ---------------------------------------------------------------------------
// failOpen
// ---------------------------------------------------------------------------

describe('Aegis failOpen', () => {
  it('blocks the call by default when core is unreachable', async () => {
    process.env['AEGIS_API_KEY'] = 'test-key'
    const aegis = new Aegis({ agentId: 'test', failOpen: false })
    ;(aegis as any).client.intercept = async () => { throw new Error('ECONNREFUSED') }

    await assert.rejects(
      () => aegis.wrap(makeTool('any')).execute({}),
      /core unreachable/,
    )
    delete process.env['AEGIS_API_KEY']
  })

  it('allows the call through when failOpen is true and core is unreachable', async () => {
    process.env['AEGIS_API_KEY'] = 'test-key'
    const aegis = new Aegis({ agentId: 'test', failOpen: true })
    ;(aegis as any).client.intercept = async () => { throw new Error('ECONNREFUSED') }

    const result = await aegis.wrap(makeTool('any', 'tool-result')).execute({})
    assert.equal(result, 'tool-result')
    delete process.env['AEGIS_API_KEY']
  })
})

// ---------------------------------------------------------------------------
// wrapAll
// ---------------------------------------------------------------------------

describe('Aegis.wrapAll', () => {
  it('returns the same keys with wrapped tools', async () => {
    process.env['AEGIS_API_KEY'] = 'test-key'
    const aegis = new Aegis({ agentId: 'test' })
    ;(aegis as any).client.intercept = async () => allowResponse()

    const tools = aegis.wrapAll({
      toolA: makeTool('toolA', 'a'),
      toolB: makeTool('toolB', 'b'),
    })

    assert.ok('toolA' in tools)
    assert.ok('toolB' in tools)
    assert.equal(await tools.toolA.execute({}), 'a')
    delete process.env['AEGIS_API_KEY']
  })
})
