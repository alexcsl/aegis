/**
 * Aegis TypeScript SDK — minimal runnable example.
 *
 * Prerequisites:
 *   1. docker compose up -d        (starts aegis core + postgres)
 *   2. AEGIS_API_KEY env must match what is in your .env
 *
 * Run:
 *   npx tsx example.ts
 */

import { Aegis, DeniedError } from '@aegis-ai-observable/sdk'

// ------------------------------------------------------------------
// Define your tools (plain functions wrapped as AegisTool objects)
// ------------------------------------------------------------------

const searchWeb = {
  name: 'search_web',
  description: 'Search the web for a query',
  execute: async (args: { query: string }) => {
    console.log(`[tool] searching for: ${args.query}`)
    return `results for "${args.query}"`
  },
}

const deleteFile = {
  name: 'delete_file',
  description: 'Delete a file at the given path',
  execute: async (args: { path: string }) => {
    console.log(`[tool] deleting: ${args.path}`)
    return `deleted ${args.path}`
  },
}

// ------------------------------------------------------------------
// Wrap with Aegis
// ------------------------------------------------------------------

const aegis = new Aegis({
  agentId: 'example-agent',
  // failOpen: true,   // uncomment if running without the core for quick testing
})

const tools = aegis.wrapAll({ searchWeb, deleteFile })

// ------------------------------------------------------------------
// Run
// ------------------------------------------------------------------

async function main() {
  // This should ALLOW — search_web is not in the default sensitive-tools policy.
  try {
    const result = await tools.searchWeb.execute({ query: 'aegis ai security' })
    console.log('[allow]', result)
  } catch (err) {
    console.error('[unexpected error]', err)
  }

  // This should DENY — delete_file is blocked by the default sensitive-tools policy.
  try {
    await tools.deleteFile.execute({ path: '/etc/passwd' })
    console.log('[unexpected allow] delete_file should have been blocked')
  } catch (err) {
    if (err instanceof DeniedError) {
      console.log('[deny]', err.message)
      console.log('  policy:     ', err.response.policy)
      console.log('  risk_score: ', err.response.risk_score)
    } else {
      console.error('[unexpected error]', err)
    }
  }
}

main().catch(console.error)
