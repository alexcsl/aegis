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
keys are compared with constant-time equality to prevent timing attacks.  
run aegis inside a private network; do not expose port 8080 to the public internet.

**input validation**  
request bodies are limited to 1 MB. all required fields are validated before
any database query is executed.

**argument sanitization**  
tool arguments are sanitized before storage. keys containing `password`, `token`,
`secret`, `key`, `auth`, `credential`, or `private` are replaced with `[redacted]`
in both the audit log and session history.

**sql injection**  
all database queries use parameterized statements via pgx. no string interpolation
is used in sql.

**transport**  
tls termination is the responsibility of your reverse proxy (nginx, caddy, etc.).
aegis does not handle tls directly. always put it behind a tls-terminating proxy
in production.

**session isolation**  
sessions are keyed by `session_id`. callers are trusted to pass an accurate id.
if you need stronger isolation, generate session ids server-side and validate them
at the application layer before calling aegis.

**policy evaluation order**  
policies are evaluated in config file order. the first match wins.  
put your most restrictive policies first.

## known limitations (v0.1)

- the `MODIFY` and `DEFER` decisions are not yet implemented (v2 roadmap)
- no built-in tls
- no multi-tenancy; single api key per deployment
- behavioral ml scoring is rule-based in v1
