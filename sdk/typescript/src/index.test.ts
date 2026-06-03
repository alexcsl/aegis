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
