# aegis-sdk — Python

Python SDK for the [Aegis](https://github.com/alexcsl/aegis) AI agent safety proxy.

```bash
pip install aegis-sdk
```

## Quick start

```python
from aegis import AsyncAegis, DeniedError

aegis = AsyncAegis(agent_id="my-agent")  # reads AEGIS_API_KEY from env

@aegis.wrap
async def delete_file(path: str) -> None:
    os.remove(path)

# or wrap inline
safe_search = aegis.wrap(search_fn, name="search_web")
results = await safe_search(query="hello")
```

For sync contexts (LangChain tools, scripts):

```python
from aegis import Aegis

aegis = Aegis(agent_id="my-agent")

@aegis.wrap
def delete_file(path: str) -> None:
    os.remove(path)
```

See the [full docs](https://github.com/alexcsl/aegis) for DEFER, MODIFY, and framework integrations.
