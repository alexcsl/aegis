<div align="center">

<img src="https://img.shields.io/badge/go-1.23-00ADD8?style=flat-square&logo=go&logoColor=white" />
<img src="https://img.shields.io/badge/npm-%40aegis--ai%2Fsdk-CB3837?style=flat-square&logo=npm&logoColor=white" />
<img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" />
<img src="https://img.shields.io/badge/status-v0.1%20MVP-orange?style=flat-square" />

<br /><br />

# Aegis

**Behavioral authorization middleware for AI agents.**

*Every tool call your agent makes — intercepted, scored, and enforced in under 50ms.*

<br />

```
your agent  →  aegis  →  tool
              ↕
         postgres audit log
```

</div>

---

## the problem

every AI agent framework today shares the same flaw: **if a tool is registered, the agent can call it. always.**

existing solutions don't solve this:

| | what it does | what it misses |
|---|---|---|
| policy engines (MS AGT, Ping) | checks "is this action type allowed?" | no session awareness, static rules only |
| observability (LangSmith, Arize) | logs what happened | cannot stop anything |
| **Aegis** | scores *this specific call* against what the agent has already done this session | — |

the attack vector both miss is **multi-turn manipulation** — an agent gradually steered across several interactions toward unauthorized behavior. by the time a static policy engine sees a rule violation, the damage is done.

---

## how it works

```
tool_call(name, args)
  │
  ▼
POST /v1/intercept
  ├─ GetOrCreateSession     load session context from postgres
  ├─ GetToolCallHistory     fetch last 20 calls
  ├─ scorer.Compute         rate + escalation + sensitivity + cost → risk score (0.0–1.0)
  └─ evaluator.Evaluate     first-match policy from aegis.config.yaml
        │
        ├─ ALLOW  →  tool executes normally
        └─ DENY   →  DeniedError returned to agent, call logged
```

session update, tool call insert, and trace insert run in goroutines after the response — keeping p95 under 5ms on local postgres.

---

## quick start

**1. spin up aegis**

```bash
cp .env.example .env          # set AEGIS_API_KEY to any strong string
docker compose up -d
```

**2. install the sdk**

```bash
npm install @aegis-ai-observable/sdk
```

**3. wrap your tools**

```typescript
import { Aegis, DeniedError } from '@aegis-ai-observable/sdk'

const aegis = new Aegis({ agentId: 'my-agent' })

const tools = aegis.wrapAll({
  searchWeb,
  readFile,
  deleteFile,   // blocked by default policy
  sendEmail,    // blocked by default policy
})

// drop into any framework — behavior is unchanged for allowed calls
const agent = new Agent({ tools, ... })
```

that's it. every call now hits the policy engine and lands in your audit log.

---

## policies

define rules in `aegis.config.yaml`. evaluated in order, first match wins.

```yaml
version: 1

policies:
  # block known destructive tools
  - name: sensitive_tool_block
    trigger:
      tool: [delete_file, execute_sql_write, send_email, shell]
    decision: DENY
    reason: "tool requires explicit allowlist entry"

  # rate limiting
  - name: rate_limit
    trigger:
      tool_calls_per_minute:
        gt: 20
    decision: DENY
    reason: "rate limit exceeded"

  # cost cap
  - name: cost_cap
    trigger:
      session_cost_usd:
        gt: 5.00
    decision: DENY
    reason: "session cost cap reached"

  # shut down high-risk sessions
  - name: high_risk
    trigger:
      risk_score:
        gt: 0.85
    decision: DENY
    reason: "risk score too high"
```

available trigger fields: `tool`, `tool_calls_per_minute`, `session_cost_usd`, `risk_score`.
conditions: `gt`, `gte`, `lt`, `lte`.

---

## risk scoring

each call produces a score from 0.0 to 1.0 built from four signals:

| signal | weight | how it's measured |
|---|---|---|
| rate | 0.25 | calls in last 60s, saturates at 30/min |
| escalation | 0.25 | burst detection across last 5 calls |
| sensitivity | 0.30 | hardcoded map of destructive tool names |
| cost | 0.20 | accumulated session cost, saturates at $20 |

the score is attached to every trace event and stored on the session. policies can trigger on it directly with `risk_score: { gt: 0.85 }`.

---

## mcp proxy mode

no sdk required. run aegis as a transparent proxy in front of any mcp server:

```bash
aegis proxy \
  --upstream http://localhost:3000 \
  --port 4000 \
  --config ./aegis.config.yaml
```

point your agent at `:4000`. only `tools/call` requests are intercepted — everything else passes through untouched.

pass `X-Session-ID` and `X-Agent-ID` headers from your mcp client for per-session tracking.

---

## api

all endpoints require `X-Aegis-Key`.

```
POST /v1/intercept
  { session_id, agent_id, tool, args, context?, cost_usd? }
  → { decision, reason?, policy?, risk_score, latency_ms }

GET  /v1/session/:id
  → full session context + accumulated stats

GET  /v1/traces?session_id=...
  → last 100 trace events for a session

GET  /healthz
  → { status: "ok" }
```

---

## self-hosting

**requirements:** go 1.23+, postgres 15+, docker (optional)

```bash
# postgres only
docker compose up postgres -d

# run the core
cd core
go mod tidy
DATABASE_URL=postgres://aegis:changeme@localhost:5432/aegis?sslmode=disable \
AEGIS_API_KEY=your-key \
go run ./cmd/aegis serve

# tests
go test -race -count=1 ./...
```

the go binary is a single static file (~8MB). the docker image is built on scratch.

---

## roadmap

**v0.1 — current**
- [x] go proxy core (ALLOW / DENY)
- [x] session context store in postgres
- [x] rule-based risk scoring
- [x] yaml policy engine
- [x] typescript sdk (`@aegis-ai-observable/sdk`)
- [x] mcp transparent proxy mode
- [x] docker compose setup

**v0.2**
- [ ] `MODIFY` decision — sanitize tool output before the agent sees it (pii redaction)
- [ ] `DEFER` decision — suspend call, fire webhook for human approval
- [ ] python sdk
- [ ] langchain + openai agents sdk middleware integrations

**v0.3**
- [ ] next.js dashboard — session explorer, policy editor, cost tracker
- [ ] ml-based behavioral scoring
- [ ] aegis cloud hosted service

---

## security

arg sanitization, constant-time auth, parameterized sql, 1MB request cap, scratch docker image.

full details in [SECURITY.md](SECURITY.md). report vulnerabilities to **aegisobservable@gmail.com**.

---

## contributing

the easiest way to contribute is adding policies to the `policies/` directory — they're plain yaml and need no go knowledge. open a PR and we'll review it.

for code contributions: fork, branch off `main`, open a PR. the ci pipeline runs `go test -race`, `go vet`, and `tsc` automatically.

---

## license

MIT — see [LICENSE](LICENSE)
