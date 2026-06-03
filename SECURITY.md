# security

## reporting a vulnerability

please do not open a public github issue for security bugs.  
email **aegisobservable@gmail.com** with:

- a description of the issue
- steps to reproduce
- potential impact

you will get a response within 48 hours. we follow a 90-day disclosure timeline.

## security model

aegis sits on the critical path between an agent and its tools. the following
properties are part of the intended security model:

**authentication**  
all requests to the aegis core api require an `X-Aegis-Key` header.  
keys are hashed with SHA-256 before comparison (`crypto/subtle.ConstantTimeCompare`)
so the comparison is length-invariant and timing-safe.  
ips that produce more than 10 failed authentication attempts per minute are blocked
for the remainder of that window.  
run aegis inside a private network; do not expose port 8080 to the public internet.

**api key strength**  
aegis warns at startup when the key is shorter than 32 characters or matches a known
insecure default (`dev-key`, `changeme`, etc.).  
generate a strong key with: `openssl rand -hex 32`

**tls gate**  
when binding to a non-loopback address, aegis will refuse to start unless the
`--behind-proxy` flag is set. this is an explicit acknowledgement that a
tls-terminating reverse proxy (nginx, caddy, etc.) is in front. the flag does not
imply tls — it is a deployment signal only.

**input validation**  
request bodies are limited to 1 MB. all required fields are validated before
any database query is executed. `session_id` and `agent_id` are validated to
`[A-Za-z0-9_\-.]` (max 128 chars) to prevent log poisoning.

**argument sanitization**  
tool arguments are sanitized before storage. keys containing fragments such as
`password`, `token`, `secret`, `key`, `auth`, `credential`, `private`, `bearer`,
`cookie`, `session`, `pin`, `otp`, `signature`, `jwt`, and others are replaced
with `[redacted]`.  
string values are also scanned for recognisable secret patterns:
AWS access keys (`AKIA...`), JWTs (`eyJ...`), and PEM private-key headers
(`-----BEGIN`) are replaced before any db write.

**sql injection**  
all database queries use parameterized statements via pgx. no string interpolation
is used in sql.

**transport**  
tls termination is the responsibility of your reverse proxy (nginx, caddy, etc.).
aegis does not handle tls directly. always put it behind a tls-terminating proxy
in production and start with `--behind-proxy`.

**session isolation**  
sessions are keyed by `session_id`. callers are trusted to pass an accurate id.
`session_id` and `agent_id` are format-validated on every request.
if you need stronger isolation, generate session ids server-side and validate them
at the application layer before calling aegis.

**policy evaluation order**  
policies are evaluated in config file order. the first match wins.  
put your most restrictive policies first.

**hop-by-hop header stripping (mcp proxy)**  
the mcp proxy strips `Authorization`, `Cookie`, `X-Aegis-Key`, `Proxy-Authorization`,
and all standard hop-by-hop headers before forwarding to the upstream mcp server.

## production checklist

before exposing aegis to any network traffic outside localhost:

- [ ] generate a strong api key: `openssl rand -hex 32`
- [ ] set a strong postgres password: `openssl rand -hex 32`
- [ ] start with `--behind-proxy` and put a tls-terminating reverse proxy in front
- [ ] set `DATABASE_URL` with `sslmode=require` (or `verify-full`)
- [ ] restrict the network so only your agent can reach port 8080
- [ ] consider setting `default_decision: DENY` in `aegis.config.yaml` for an
      allowlist posture — only explicitly named tools will pass
- [ ] rotate the api key quarterly

## defer approval boundary

`DEFER` suspends a tool call until a human approves it. Approval (`POST /v1/decisions/:id/resolve`) and listing (`GET /v1/decisions`) are guarded by an admin key (`AEGIS_ADMIN_KEY`). If you do not set one, these endpoints fall back to `AEGIS_API_KEY` — the same key your agents hold — which means an agent could approve its own deferred calls. Set a distinct `AEGIS_ADMIN_KEY` in any deployment where agents are not fully trusted; aegis logs a warning at startup when it is unset.

## known limitations (v0.2)

- no built-in tls
- no multi-tenancy; single api key per deployment
- behavioral ml scoring is rule-based
- `MODIFY` rewrites tool *input* args only (not tool output)
- `DEFER` is not available over the synchronous mcp proxy (it fails closed there); use the sdk
