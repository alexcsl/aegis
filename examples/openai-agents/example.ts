/**
 * example: protecting openai agents sdk tools with aegis
 *
 * run:
 *   AEGIS_API_KEY=your-key OPENAI_API_KEY=your-key npx tsx example.ts
 */

import { Aegis, type AegisTool } from '@aegis-ai/sdk'

// define tools in the aegis format
const searchWeb: AegisTool = {
  name: 'search_web',
  description: 'search the web for a query',
  execute: async ({ query }: { query: string }) => {
    // real implementation goes here
    return `results for: ${query}`
  },
}

const deleteFile: AegisTool = {
  name: 'delete_file',
  description: 'delete a file from disk',
  execute: async ({ path }: { path: string }) => {
    // this will be blocked by the default sensitive-tools policy
    return `deleted: ${path}`
  },
}

const sendEmail: AegisTool = {
  name: 'send_email',
  description: 'send an email',
  execute: async ({ to, subject }: { to: string; subject: string }) => {
    return `sent email to ${to}: ${subject}`
  },
}

// wrap all tools with aegis
const aegis = new Aegis({
  agentId: 'my-openai-agent',
  onDeny: (resp, tool) => {
    console.warn(`[aegis] blocked "${tool}" - ${resp.reason}`)
  },
})

const tools = aegis.wrapAll({ searchWeb, deleteFile, sendEmail })

// simulate some tool calls
async function run() {
  try {
    const result = await tools.searchWeb.execute({ query: 'typescript best practices' })
    console.log('search result:', result)
  } catch (e) {
    console.error('search failed:', e)
  }

  try {
    await tools.deleteFile.execute({ path: '/important/data.csv' })
  } catch (e: unknown) {
    // DeniedError is expected here given the default policy
    if (e instanceof Error) {
      console.log('delete blocked (expected):', e.message)
    }
  }
}

run().catch(console.error)
