# changelog

## v0.3.0 (2026-06-05)

### features

- **Python SDK (`aegis-sdk` 0.3.0):** full parity with the TypeScript SDK.
  - `AsyncAegis` for async code (OpenAI Agents SDK, asyncio-based frameworks).
  - `Aegis` for sync code (LangChain sync tools, scripts) — uses a dedicated background event loop so it is safe to call from inside an existing async event loop.
  - Decorator-style `@aegis.wrap` and bulk `wrap_all()`.
  - ALLOW, DENY, MODIFY (executes with `modified_args`), DEFER (polls until approved/rejected/timeout).
  - `fail_open`, `defer_poll_interval`, `defer_timeout` config.
  - Context manager support (`async with AsyncAegis(...)` / `with Aegis(...)`).
  - 18 pytest tests covering all code paths.
- **LangChain integration example** (`examples/python-langchain/`) — wraps LangChain `@tool` functions with `@aegis.wrap`.
- **OpenAI Agents SDK integration example** (`examples/python-openai-agents/`) — wraps `@function_tool` callables with `@aegis.wrap` using `AsyncAegis`.
- **`token_count` wired through:** add `token_count` to `POST /v1/intercept` and it accumulates on `session.token_count`.
- **Traces pagination:** `GET /v1/traces` now accepts `?limit=` (default 100, max 500) and `?offset=` for cursor-free pagination.
- **Sessions listing:** `GET /v1/sessions?agent_id=...` returns the most recently active sessions for an agent (paginated).

### improvements

- Dead code removed: `core/internal/util/calls.go` was an empty stub package.
- CI now runs the Python SDK test suite on every push/PR.

---

## v0.2.0 (2026-06-03)

### features

- **`MODIFY` decision:** a policy can now rewrite a tool's input arguments before execution via a `modify:` block with `set` (force a value), `redact` (replace a value with `[redacted]`), and `remove` (drop a key). The intercept API echoes the rewritten args back as `modified_args`; the TypeScript SDK executes the tool with them. The MCP proxy rewrites the forwarded request in place.
- **`DEFER` decision:** a policy can suspend a tool call for human approval. The call is persisted to a new `pending_decisions` table and the SDK blocks, polling `GET /v1/decisions/:id` until an operator approves or rejects it (or `deferTimeoutMs`, default 5 min, elapses → fail-closed). New endpoints:
  - `GET /v1/decisions/:id?agent_id=...` — agent polls its own decision (ownership-checked).
  - `POST /v1/decisions/:id/resolve` — operator approves/rejects (admin-authed).
  - `GET /v1/decisions` — operator lists pending decisions (admin-authed).
- **`notify` webhook:** the previously-unused policy `notify:` field now fires a best-effort JSON webhook when a `DEFER` decision is created, so a human can be alerted. The URL comes from operator config (not user input).

### security

- **Admin key separation:** `AEGIS_ADMIN_KEY` / `--admin-key` guards the DEFER resolve and list endpoints. Without it they fall back to `AEGIS_API_KEY` — the key agents hold — which would let an agent approve its own deferred calls. aegis logs a warning at startup when no admin key is set.
- **MODIFY/DEFER are no longer silent passes:** unimplemented decision handling was removed; both are now first-class. Over the MCP proxy, `DEFER` fails closed (there is no polling channel).

### sdk (`@aegis-ai-observable/sdk` 0.2.0)

- Handles `MODIFY` (executes with `modified_args`) and `DEFER` (polls for approval).
- New config: `deferPollIntervalMs` (default 2000) and `deferTimeoutMs` (default 300000).
- New exported types: `DecisionStatus`, `PendingDecision`.

### notes

- MODIFY rewrites tool *input* args, not tool output.
- The README roadmap framed MODIFY as output sanitization; the shipped behavior is input-arg rewriting, which fits the pre-execution intercept model.

---

## v0.1.2 (2026-06-03)

### security

- **Session injection fix:** `POST /v1/intercept` now rejects requests where the supplied `agent_id` does not match the owner of the existing session. Previously any agent could append tool calls to another agent's session (IDOR / cross-agent session poisoning).
- **X-Forwarded-For gate:** `X-Forwarded-For` is now only trusted for IP extraction when `--behind-proxy` is set. Without it, `RemoteAddr` is used directly, preventing forged XFF headers from bypassing the auth-failure rate limiter.
- **ipLimiter size cap:** the auth-failure limiter map is now capped at 10,000 entries to prevent unbounded memory growth under a flood of distinct IPs.

### bugs

- **Docker Compose startup failure:** `docker-compose.yml` now passes `--behind-proxy` so the aegis service does not immediately exit when bound to a non-loopback address inside the container.
- **CI branch mismatch:** CI workflow now triggers on pushes to `master` (was `main`, so CI never ran on the default branch).
- **MCP proxy query string dropped:** `forward()` in the MCP proxy now copies `r.URL.RawQuery` to the upstream request URL. Previously query parameters were silently dropped.
- **Dead policy in `rate-limit.yaml`:** `rate_limit_relaxed` could never fire because `rate_limit_strict` always matched first. The file now documents the two options as mutually exclusive alternatives with the second one commented out.

### improvements

- **Config validation at startup:** `Config.Validate()` is called after loading `aegis.config.yaml`. Typos in `decision:` or `default_decision:` values now cause a fatal error at startup rather than silently allowing everything.
- **Healthz probes database:** `GET /healthz` on both the intercept server and MCP proxy now pings Postgres. Returns HTTP 503 when the database is unreachable instead of always returning `ok`.
- **Fail-closed for unimplemented decisions:** the TypeScript SDK now treats `DEFER` and `MODIFY` responses as `DENY` (fail-closed) instead of silently passing through as `ALLOW`. These decision types are not yet implemented server-side.

---

## v0.1.1 (2026-06-03)

### security

- **Auth timing fix:** `X-Aegis-Key` is now SHA-256 hashed before `ConstantTimeCompare` on both the proxy server and MCP proxy. The previous comparison leaked key length via timing — this is now length-invariant.
- **Auth rate limiting:** IPs that produce more than 10 failed authentication attempts per minute are blocked for the remainder of that window. Resets on a successful auth.
- **Startup key strength check:** aegis warns at startup if `AEGIS_API_KEY` is shorter than 32 characters or matches a known insecure default (`dev-key`, `changeme`, etc.).
- **TLS gate:** the `serve` command refuses to bind on a non-loopback address unless `--behind-proxy` is set. Prevents accidentally exposing plain HTTP to the network.
- **Expanded arg sanitization:** sensitive key fragments now include `bearer`, `cookie`, `session`, `apikey`, `api_key`, `pwd`, `passwd`, `pin`, `otp`, `signature`, `jwt`. Value-level scrubbing added for AWS access keys (`AKIA...`), JWTs (`eyJ...`), and PEM private-key headers.
- **ID validation:** `session_id` and `agent_id` are now validated to `[A-Za-z0-9_\-.]` (max 128 chars) before any DB work, preventing log poisoning.
- **MCP proxy hop headers:** `Authorization` and `Cookie` are now stripped from requests forwarded to the upstream MCP server.
- **`default_decision` config option:** add `default_decision: DENY` to `aegis.config.yaml` to enable an allowlist posture where unmatched tools are blocked by default.

### sdk (`@aegis-ai-observable/sdk`)

- **`failOpen` option:** set `failOpen: true` to allow tool calls through when the Aegis core is unreachable. Default is `false` (fail-closed). Never use `failOpen: true` in production.
- **Error message on network failure:** fail-closed network errors now produce a clear message identifying the tool name and the original error.
- Added `repository`, `bugs`, `homepage` fields to `package.json` so the npm page is populated.
- Added `README.md` for npm page.

### docs

- `README.md`: quick-start now includes the `aegis.config.yaml` copy step and the `openssl rand -hex 32` key hint.
- `README.md`: documents `default_decision` in the policies example.
- `docs/hn-post.md`: corrected npm package name to `@aegis-ai-observable/sdk`.
- `SECURITY.md`: rewritten with updated auth model, id validation, expanded sanitization, hop headers, and a production checklist.
- `.env.example`: added `openssl rand -hex 32` generation hint.

---

## v0.1.0 (2026-05-01)

First public release.

- Go proxy core (`aegis serve`, `aegis proxy`)
- Session context store in Postgres
- ALLOW / DENY enforcement
- Rule-based risk scoring (rate, escalation, sensitivity, cost signals)
- YAML policy engine
- TypeScript SDK (`@aegis-ai-observable/sdk`)
- MCP transparent proxy mode
- Docker Compose setup
