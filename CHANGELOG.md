# changelog

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
