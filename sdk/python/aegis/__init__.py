"""Aegis Python SDK — wrap agent tools with Aegis safety policies."""
from __future__ import annotations

import asyncio
import concurrent.futures
import functools
import inspect
import os
import threading
import uuid
from typing import Any, Callable, TypeVar

from ._client import AegisClient
from ._types import (
    Decision,
    DecisionStatus,
    InterceptRequest,
    InterceptResponse,
    PendingDecision,
)

__all__ = [
    "AsyncAegis",
    "Aegis",
    "DeniedError",
    "Decision",
    "DecisionStatus",
    "InterceptResponse",
    "PendingDecision",
]

F = TypeVar("F", bound=Callable[..., Any])


class DeniedError(Exception):
    """Raised when Aegis blocks a tool call (DENY, REJECT, or timeout)."""

    def __init__(self, tool: str, response: InterceptResponse) -> None:
        self.tool = tool
        self.response = response
        reason = response.reason or "denied by policy"
        super().__init__(f"aegis: tool '{tool}' was denied — {reason}")


class AsyncAegis:
    """Async Aegis client.

    Use this class from async code (OpenAI Agents SDK, asyncio-based frameworks).
    For sync code (LangChain sync tools, scripts) use :class:`Aegis` instead.

    Example::

        from aegis import AsyncAegis

        aegis = AsyncAegis(agent_id="my-agent")

        @aegis.wrap
        async def search(query: str) -> list[str]:
            ...

        # or with an explicit name
        wrapped = aegis.wrap(search_fn, name="search_web")
        results = await wrapped(query="hello")
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        url: str | None = None,
        agent_id: str = "default",
        session_id: str | None = None,
        fail_open: bool = False,
        defer_poll_interval: float = 2.0,
        defer_timeout: float = 300.0,
    ) -> None:
        resolved_key = api_key or os.environ.get("AEGIS_API_KEY") or ""
        if not resolved_key:
            raise ValueError(
                "aegis: api_key is required — set AEGIS_API_KEY or pass api_key="
            )
        resolved_url = os.environ.get("AEGIS_URL") or url or "http://localhost:8080"
        self._client = AegisClient(resolved_url, resolved_key)
        self.agent_id = agent_id
        self.session_id = session_id or str(uuid.uuid4())
        self.fail_open = fail_open
        self.defer_poll_interval = defer_poll_interval
        self.defer_timeout = defer_timeout

    def wrap(self, fn: F, *, name: str | None = None) -> F:  # type: ignore[return]
        """Wrap an async callable so every call is intercepted through Aegis.

        Can be used as a decorator::

            @aegis.wrap
            async def delete_file(path: str) -> None: ...

        Or to wrap an existing callable::

            safe_delete = aegis.wrap(delete_file, name="delete_file")
        """
        tool_name = name or getattr(fn, "__name__", None) or getattr(fn, "name", None)
        if not tool_name:
            raise ValueError(
                "aegis: cannot determine tool name — pass name= explicitly"
            )

        @functools.wraps(fn)
        async def _wrapped(*args: Any, **kwargs: Any) -> Any:
            args_dict = _bind_args(fn, args, kwargs)

            try:
                response = await self._client.intercept(
                    InterceptRequest(
                        session_id=self.session_id,
                        agent_id=self.agent_id,
                        tool=tool_name,
                        args=args_dict,
                    )
                )
            except Exception as exc:
                if self.fail_open:
                    return await _call(fn, args, kwargs)
                raise RuntimeError(
                    f"aegis: core unreachable ({exc}) — call blocked (fail-closed)"
                ) from exc

            decision = response.decision

            if decision == "ALLOW":
                return await _call(fn, args, kwargs)
            elif decision == "MODIFY":
                modified = response.modified_args if response.modified_args is not None else args_dict
                return await _call(fn, (), modified)
            elif decision == "DEFER":
                await self._await_approval(response, tool_name)
                return await _call(fn, args, kwargs)
            else:
                raise DeniedError(tool_name, response)

        return _wrapped  # type: ignore[return-value]

    def wrap_all(self, tools: dict[str, Callable]) -> dict[str, Callable]:
        """Wrap every callable in a dict; returns the same shape."""
        return {n: self.wrap(f, name=n) for n, f in tools.items()}

    async def _await_approval(
        self, response: InterceptResponse, tool_name: str
    ) -> None:
        decision_id = response.decision_id
        if not decision_id:
            raise DeniedError(tool_name, response)

        deadline = asyncio.get_event_loop().time() + self.defer_timeout
        while True:
            pd = await self._client.get_decision(decision_id, self.agent_id)
            if pd.status == "approved":
                return
            if pd.status == "rejected":
                raise DeniedError(tool_name, response)
            if asyncio.get_event_loop().time() >= deadline:
                raise TimeoutError(
                    f"aegis: tool '{tool_name}' deferred for approval but timed out "
                    f"after {self.defer_timeout}s — call blocked (fail-closed)"
                )
            await asyncio.sleep(self.defer_poll_interval)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncAegis":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()


class Aegis:
    """Synchronous Aegis client.

    Wraps :class:`AsyncAegis` via a dedicated background event loop so it is
    safe to call from *any* sync context — including inside an existing async
    event loop (e.g. Jupyter, LangChain's async executor).

    Example::

        from aegis import Aegis

        aegis = Aegis(agent_id="my-agent")

        @aegis.wrap
        def delete_file(path: str) -> None:
            os.remove(path)

        delete_file(path="/tmp/test.txt")  # blocks until decision is returned
    """

    def __init__(self, **kwargs: Any) -> None:
        # Run a background event loop on a dedicated daemon thread so we can
        # safely bridge sync → async regardless of what the caller's thread is doing.
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever, daemon=True, name="aegis-event-loop"
        )
        self._thread.start()
        self._async = AsyncAegis(**kwargs)

    def _run(self, coro: Any) -> Any:
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result()

    def wrap(self, fn: F, *, name: str | None = None) -> F:  # type: ignore[return]
        """Wrap a sync or async callable; every call blocks until Aegis decides."""
        tool_name = name or getattr(fn, "__name__", None) or getattr(fn, "name", None)
        if not tool_name:
            raise ValueError(
                "aegis: cannot determine tool name — pass name= explicitly"
            )

        @functools.wraps(fn)
        def _wrapped(*args: Any, **kwargs: Any) -> Any:
            args_dict = _bind_args(fn, args, kwargs)

            try:
                response = self._run(
                    self._async._client.intercept(
                        InterceptRequest(
                            session_id=self._async.session_id,
                            agent_id=self._async.agent_id,
                            tool=tool_name,
                            args=args_dict,
                        )
                    )
                )
            except Exception as exc:
                if self._async.fail_open:
                    return fn(*args, **kwargs) if not asyncio.iscoroutinefunction(fn) \
                        else self._run(fn(*args, **kwargs))
                raise RuntimeError(
                    f"aegis: core unreachable ({exc}) — call blocked (fail-closed)"
                ) from exc

            decision = response.decision

            if decision == "ALLOW":
                return fn(*args, **kwargs) if not asyncio.iscoroutinefunction(fn) \
                    else self._run(fn(*args, **kwargs))
            elif decision == "MODIFY":
                modified = response.modified_args if response.modified_args is not None else args_dict
                return fn(**modified) if not asyncio.iscoroutinefunction(fn) \
                    else self._run(fn(**modified))
            elif decision == "DEFER":
                self._run(self._async._await_approval(response, tool_name))
                return fn(*args, **kwargs) if not asyncio.iscoroutinefunction(fn) \
                    else self._run(fn(*args, **kwargs))
            else:
                raise DeniedError(tool_name, response)

        return _wrapped  # type: ignore[return-value]

    def wrap_all(self, tools: dict[str, Callable]) -> dict[str, Callable]:
        return {n: self.wrap(f, name=n) for n, f in tools.items()}

    def close(self) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)

    def __enter__(self) -> "Aegis":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _call(fn: Callable, args: tuple, kwargs: dict) -> Any:
    """Call fn with args/kwargs, awaiting the result if it is a coroutine."""
    result = fn(*args, **kwargs)
    if inspect.isawaitable(result):
        return await result
    return result


def _bind_args(fn: Callable, args: tuple, kwargs: dict) -> dict[str, Any]:
    """Serialize positional + keyword arguments into a plain dict."""
    try:
        sig = inspect.signature(fn)
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except (TypeError, ValueError):
        return dict(kwargs)
