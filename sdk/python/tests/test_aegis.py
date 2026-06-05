"""Tests for the Aegis Python SDK.

Uses respx to mock httpx calls so no real server is needed.
"""
from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aegis import AsyncAegis, Aegis, DeniedError
from aegis._types import InterceptResponse, PendingDecision


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def allow_response() -> InterceptResponse:
    return InterceptResponse(decision="ALLOW", risk_score=0.1, latency_ms=1)


def deny_response(reason: str = "blocked") -> InterceptResponse:
    return InterceptResponse(
        decision="DENY", risk_score=0.9, latency_ms=1,
        reason=reason, policy="test-policy",
    )


def modify_response(modified: dict) -> InterceptResponse:
    return InterceptResponse(
        decision="MODIFY", risk_score=0.2, latency_ms=1, modified_args=modified
    )


def defer_response(decision_id: str = "dec-1") -> InterceptResponse:
    return InterceptResponse(
        decision="DEFER", risk_score=0.5, latency_ms=1,
        decision_id=decision_id, reason="needs approval",
    )


def pending_decision(status: str = "pending") -> PendingDecision:
    return PendingDecision(
        id="dec-1", session_id="s-1", agent_id="test",
        tool="send_email", status=status,  # type: ignore[arg-type]
    )


def make_aegis(**kwargs) -> AsyncAegis:
    return AsyncAegis(api_key="test-key-for-unit-tests-only", agent_id="test", **kwargs)


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------

class TestConstructor:
    def test_raises_without_api_key(self, monkeypatch):
        monkeypatch.delenv("AEGIS_API_KEY", raising=False)
        with pytest.raises(ValueError, match="api_key is required"):
            AsyncAegis()

    def test_reads_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_API_KEY", "env-key")
        aegis = AsyncAegis(agent_id="test")
        assert aegis  # no exception

    def test_env_url_takes_precedence(self, monkeypatch):
        monkeypatch.setenv("AEGIS_URL", "http://custom:9000")
        aegis = AsyncAegis(api_key="k", url="http://ignored:8080")
        assert "9000" in aegis._client._base


# ---------------------------------------------------------------------------
# AsyncAegis.wrap — ALLOW
# ---------------------------------------------------------------------------

class TestWrapAllow:
    async def test_executes_tool_on_allow(self):
        aegis = make_aegis()
        aegis._client.intercept = AsyncMock(return_value=allow_response())

        @aegis.wrap
        async def search(query: str) -> str:
            return f"results:{query}"

        result = await search(query="hello")
        assert result == "results:hello"

    async def test_args_forwarded_to_intercept(self):
        aegis = make_aegis()
        mock = AsyncMock(return_value=allow_response())
        aegis._client.intercept = mock

        @aegis.wrap
        async def search(query: str, limit: int = 10) -> str:
            return "ok"

        await search("test", limit=5)
        req = mock.call_args[0][0]
        assert req.tool == "search"
        assert req.args == {"query": "test", "limit": 5}


# ---------------------------------------------------------------------------
# AsyncAegis.wrap — DENY
# ---------------------------------------------------------------------------

class TestWrapDeny:
    async def test_raises_denied_error(self):
        aegis = make_aegis()
        aegis._client.intercept = AsyncMock(return_value=deny_response("too risky"))

        executed = False

        @aegis.wrap
        async def delete(path: str) -> None:
            nonlocal executed
            executed = True

        with pytest.raises(DeniedError) as exc_info:
            await delete(path="/tmp/data")

        assert exc_info.value.tool == "delete"
        assert "too risky" in str(exc_info.value)
        assert not executed, "underlying function must not run on DENY"

    async def test_denied_error_carries_response(self):
        aegis = make_aegis()
        resp = deny_response("blocked by policy")
        aegis._client.intercept = AsyncMock(return_value=resp)

        @aegis.wrap
        async def shell(cmd: str) -> str:
            return ""

        with pytest.raises(DeniedError) as exc_info:
            await shell(cmd="rm -rf /")

        assert exc_info.value.response is resp


# ---------------------------------------------------------------------------
# AsyncAegis.wrap — MODIFY
# ---------------------------------------------------------------------------

class TestWrapModify:
    async def test_executes_with_modified_args(self):
        aegis = make_aegis()
        aegis._client.intercept = AsyncMock(
            return_value=modify_response({"query": "safe", "limit": 10})
        )

        received: dict = {}

        @aegis.wrap
        async def search(query: str, limit: int = 100) -> str:
            received["query"] = query
            received["limit"] = limit
            return "ok"

        await search(query="unsafe query", limit=9999)
        assert received == {"query": "safe", "limit": 10}

    async def test_falls_back_to_original_args_when_missing(self):
        aegis = make_aegis()
        aegis._client.intercept = AsyncMock(
            return_value=InterceptResponse(decision="MODIFY", risk_score=0.2, latency_ms=1)
        )

        received: dict = {}

        @aegis.wrap
        async def search(query: str) -> str:
            received["query"] = query
            return "ok"

        await search(query="original")
        assert received["query"] == "original"


# ---------------------------------------------------------------------------
# AsyncAegis.wrap — DEFER
# ---------------------------------------------------------------------------

class TestWrapDefer:
    async def test_executes_after_approval(self):
        aegis = make_aegis(defer_poll_interval=0.01, defer_timeout=5.0)
        aegis._client.intercept = AsyncMock(return_value=defer_response("dec-approve"))

        call_count = 0

        async def mock_get_decision(decision_id: str, agent_id: str) -> PendingDecision:
            nonlocal call_count
            call_count += 1
            status = "approved" if call_count >= 2 else "pending"
            return PendingDecision(
                id=decision_id, session_id="s", agent_id=agent_id,
                tool="send_email", status=status,  # type: ignore[arg-type]
            )

        aegis._client.get_decision = mock_get_decision

        @aegis.wrap
        async def send_email(to: str) -> str:
            return f"sent to {to}"

        result = await send_email(to="ops@example.com")
        assert result == "sent to ops@example.com"
        assert call_count >= 2

    async def test_raises_on_rejection(self):
        aegis = make_aegis(defer_poll_interval=0.01, defer_timeout=5.0)
        aegis._client.intercept = AsyncMock(return_value=defer_response("dec-reject"))
        aegis._client.get_decision = AsyncMock(
            return_value=PendingDecision(
                id="dec-reject", session_id="s", agent_id="test",
                tool="send_email", status="rejected",
            )
        )

        executed = False

        @aegis.wrap
        async def send_email(to: str) -> str:
            nonlocal executed
            executed = True
            return "sent"

        with pytest.raises(DeniedError):
            await send_email(to="ops@example.com")

        assert not executed

    async def test_timeout_fails_closed(self):
        aegis = make_aegis(defer_poll_interval=0.01, defer_timeout=0.05)
        aegis._client.intercept = AsyncMock(return_value=defer_response("dec-timeout"))
        aegis._client.get_decision = AsyncMock(
            return_value=PendingDecision(
                id="dec-timeout", session_id="s", agent_id="test",
                tool="send_email", status="pending",
            )
        )

        @aegis.wrap
        async def send_email(to: str) -> str:
            return "sent"

        with pytest.raises(TimeoutError, match="timed out"):
            await send_email(to="ops@example.com")


# ---------------------------------------------------------------------------
# AsyncAegis.wrap — failOpen
# ---------------------------------------------------------------------------

class TestFailOpen:
    async def test_blocks_by_default_when_core_unreachable(self):
        aegis = make_aegis(fail_open=False)
        aegis._client.intercept = AsyncMock(side_effect=ConnectionError("ECONNREFUSED"))

        @aegis.wrap
        async def search(query: str) -> str:
            return "results"

        with pytest.raises(RuntimeError, match="core unreachable"):
            await search(query="test")

    async def test_allows_through_when_fail_open(self):
        aegis = make_aegis(fail_open=True)
        aegis._client.intercept = AsyncMock(side_effect=ConnectionError("ECONNREFUSED"))

        @aegis.wrap
        async def search(query: str) -> str:
            return "results"

        result = await search(query="test")
        assert result == "results"


# ---------------------------------------------------------------------------
# AsyncAegis.wrap_all
# ---------------------------------------------------------------------------

class TestWrapAll:
    async def test_returns_same_shape(self):
        aegis = make_aegis()
        aegis._client.intercept = AsyncMock(return_value=allow_response())

        async def tool_a(x: int) -> str:
            return f"a:{x}"

        async def tool_b(y: str) -> str:
            return f"b:{y}"

        wrapped = aegis.wrap_all({"tool_a": tool_a, "tool_b": tool_b})
        assert set(wrapped.keys()) == {"tool_a", "tool_b"}
        assert await wrapped["tool_a"](x=1) == "a:1"


# ---------------------------------------------------------------------------
# Sync Aegis
# ---------------------------------------------------------------------------

class TestSyncAegis:
    def test_wrap_sync_function_allow(self):
        with Aegis(api_key="sync-test-key", agent_id="sync-test") as aegis:
            aegis._async._client.intercept = AsyncMock(return_value=allow_response())

            @aegis.wrap
            def greet(name: str) -> str:
                return f"hello {name}"

            result = greet(name="world")
            assert result == "hello world"

    def test_wrap_sync_function_deny(self):
        with Aegis(api_key="sync-test-key", agent_id="sync-test") as aegis:
            aegis._async._client.intercept = AsyncMock(return_value=deny_response())

            @aegis.wrap
            def delete(path: str) -> None:
                pass

            with pytest.raises(DeniedError):
                delete(path="/tmp/data")

    def test_tool_name_from_function_name(self):
        with Aegis(api_key="sync-test-key", agent_id="sync-test") as aegis:
            mock = AsyncMock(return_value=allow_response())
            aegis._async._client.intercept = mock

            @aegis.wrap
            def my_tool(x: int) -> int:
                return x + 1

            my_tool(x=5)
            req = mock.call_args[0][0]
            assert req.tool == "my_tool"
