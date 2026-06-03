# @aegis-ai-observable/sdk

Behavioral authorization SDK for AI agents. Wraps your tools so every call is intercepted, scored, and enforced by the [Aegis](https://github.com/alexcsl/aegis) core before it executes.

## install

```bash
npm install @aegis-ai-observable/sdk
```

## quick start

```typescript
import { Aegis, DeniedError } from '@aegis-ai-observable/sdk'

const aegis = new Aegis({ agentId: 'my-agent' })

const tools = aegis.wrapAll({
  searchWeb,
  readFile,
  deleteFile,   // blocked by default policy
  sendEmail,    // blocked by default policy
})

try {
  await tools.deleteFile.execute({ path: '/etc/passwd' })
} catch (err) {
  if (err instanceof DeniedError) {
    console.log(err.message)        // "aegis denied "deleteFile": tool requires explicit allowlist entry"
    console.log(err.response)       // { decision: 'DENY', policy: 'sensitive_tool_block', risk_score: 0.3, ... }
  }
}
```

## configuration

```typescript
const aegis = new Aegis({
  url:       'http://localhost:8080',   // default: AEGIS_URL env var or http://localhost:8080
  apiKey:    'your-key',               // default: AEGIS_API_KEY env var
  agentId:   'my-agent',               // groups tool calls into a named agent
  sessionId: 'session-abc123',         // groups calls into one session (auto-generated if omitted)
  onDeny:    (res, tool) => { /* log, alert, etc. */ },
  failOpen:  false,                    // default: false (fail-closed)
})
```

### fail-closed behavior

By default the SDK **fails closed**: if the Aegis core is unreachable, the wrapped tool throws rather than executing. This is the safe default for production.

For local development without the core running, set `failOpen: true`:

```typescript
const aegis = new Aegis({
  agentId:  'dev-agent',
  failOpen: true,   // allow calls through when core is down — dev only
})
```

Never use `failOpen: true` in production.

## running the core

```bash
cp .env.example .env   # set AEGIS_API_KEY (use: openssl rand -hex 32)
docker compose up -d
```

See the [root README](https://github.com/alexcsl/aegis#readme) for policy configuration and self-hosting instructions.
