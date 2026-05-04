# mcp proxy example

run aegis as a transparent proxy in front of any mcp server.

```bash
# start your existing mcp server on port 3000, then:

aegis proxy \
  --upstream http://localhost:3000 \
  --port 4000 \
  --config ./aegis.config.yaml \
  --db $DATABASE_URL \
  --key $AEGIS_API_KEY
```

point your agent at `localhost:4000` instead of `localhost:3000`.  
no code changes required. all tool calls are now intercepted.

the proxy reads `X-Session-ID` and `X-Agent-ID` headers to group calls into sessions.
set these in your agent's mcp client config if you want per-session tracking.
