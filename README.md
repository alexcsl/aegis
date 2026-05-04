# Aegis

**Behavioral authorization middleware for AI agents.**

Aegis sits between your agent and its tools. Every tool call is scored against
session context and policy rules before execution. In under 50ms, Aegis decides
whether to allow or block it, and writes a full audit trace.

```
agent  ->  aegis  ->  tool
```

No behavior change for legitimate calls. No code restructure required.

---

## quick start

**1. start aegis with docker compose**

```bash
cp .env.example .env
# edit .env and set AEGIS_API_KEY to a strong random string

docker compose up -d
```

**2. install the sdk**

```bash
npm install @aegis-ai/sdk
```

**3. wrap your tools**

```typescript
import { Aegis } from '@aegis-ai/sdk'

const aegis = new Aegis({ agentId: 'my-agent' })

const tools = aegis.wrapAll({
  searchWeb,
  readFile,
  deleteFile,  // blocked by default policy
})

// use tools as normal - aegis intercepts before execution
```

That's it. Tool calls now go through policy evaluation and are logged to your
postgres audit table.

---

## how it works

each tool call hits the aegis core (go binary) via a lightweight http request.
the core:

1. loads or creates a session context from postgres
2. scores the call against behavioral signals (rate, escalation, sensitivity, cost)
3. evaluates it against your yaml policies in order
4. returns a decision: `ALLOW` or `DENY`
5. writes a trace event to the audit log

p95 overhead on `ALLOW` decisions is under 5ms on local postgres.

---

## configuration

policies live in `aegis.config.yaml`:

```yaml
version: 1

policies:
  - name: block_sensitive_tools
    trigger:
      tool: [delete_file, execute_sql_write, send_email]
    decision: DENY
    reason: "requires explicit approval"

  - name: rate_limit
    trigger:
      tool_calls_per_minute:
        gt: 20
    decision: DENY
    reason: "rate limit exceeded"

  - name: cost_cap
    trigger:
      session_cost_usd:
        gt: 5.00
    decision: DENY
    reason: "session cost cap reached"
```

policies are evaluated in order. first match wins. if nothing matches, the call
is allowed.

---

## mcp proxy mode

run aegis as a transparent proxy in front of any mcp server. no sdk required:

```bash
aegis proxy \
  --upstream http://localhost:3000 \
  --port 4000 \
  --config ./aegis.config.yaml
```

point your agent at `:4000`. all tool calls are intercepted automatically.

---

## api reference

the go core exposes a simple http api:

```
POST /v1/intercept
  body: { session_id, agent_id, tool, args, context?, cost_usd? }
  returns: { decision, reason?, policy?, risk_score, latency_ms }

GET /v1/session/:id
  returns: full session context

GET /v1/traces?session_id=...
  returns: audit log for a session

GET /healthz
  returns: { status: "ok" }
```

all endpoints require `X-Aegis-Key` header.

---

## architecture

```
core/
  cmd/aegis/          cli entrypoint (serve | proxy subcommands)
  internal/
    proxy/            intercept http api
    policy/           yaml policy loader and evaluator
    scorer/           rule-based risk scoring
    store/            postgres session store and audit log
    mcp/              json-rpc mcp proxy

sdk/
  typescript/         @aegis-ai/sdk npm package

policies/
  security/           default block lists
  compliance/         rate limiting
  cost/               cost cap examples

examples/
  openai-agents/      openai agents sdk integration
  mcp-server/         mcp proxy usage
```

---

## development

**prerequisites:** go 1.22+, node 18+, postgres 15+, docker (optional)

```bash
# run postgres
docker compose up postgres -d

# build and run the core
cd core
go mod tidy
DATABASE_URL=postgres://aegis:changeme@localhost:5432/aegis?sslmode=disable \
AEGIS_API_KEY=dev-key \
go run ./cmd/aegis serve

# build the sdk
cd sdk/typescript
npm install
npm run build
```

**running tests:**

```bash
cd core && go test ./...
```

---

## roadmap

**v0.1 (current)**
- go proxy core with ALLOW/DENY decisions
- session context store in postgres
- rule-based risk scoring
- yaml policy engine
- typescript sdk
- mcp proxy mode
- docker compose setup

**v0.2**
- `MODIFY` decision with pii redaction
- `DEFER` decision with human-in-the-loop webhook
- python sdk
- langchain middleware integration

**v0.3**
- next.js dashboard (session explorer, policy editor, cost tracker)
- ml-based behavioral scoring
- aegis cloud hosted service

---

## license

MIT - see [LICENSE](LICENSE)
