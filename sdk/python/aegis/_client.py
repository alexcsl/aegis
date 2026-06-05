from __future__ import annotations

from typing import Any

import httpx

from ._types import InterceptRequest, InterceptResponse, PendingDecision


class AegisClient:
    """Low-level async HTTP client for the Aegis core API."""

    def __init__(self, base_url: str, api_key: str) -> None:
        self._base = base_url.rstrip("/")
        self._http = httpx.AsyncClient(
            headers={"X-Aegis-Key": api_key},
            timeout=30.0,
        )

    async def intercept(self, req: InterceptRequest) -> InterceptResponse:
        payload: dict[str, Any] = {
            "session_id": req.session_id,
            "agent_id": req.agent_id,
            "tool": req.tool,
            "args": req.args,
        }
        if req.context:
            payload["context"] = req.context
        if req.cost_usd:
            payload["cost_usd"] = req.cost_usd
        if req.token_count:
            payload["token_count"] = req.token_count

        resp = await self._http.post(f"{self._base}/v1/intercept", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return InterceptResponse(
            decision=data["decision"],
            risk_score=data.get("risk_score", 0.0),
            latency_ms=data.get("latency_ms", 0),
            reason=data.get("reason", ""),
            policy=data.get("policy", ""),
            decision_id=data.get("decision_id", ""),
            modified_args=data.get("modified_args"),
        )

    async def get_decision(self, decision_id: str, agent_id: str) -> PendingDecision:
        resp = await self._http.get(
            f"{self._base}/v1/decisions/{decision_id}",
            params={"agent_id": agent_id},
        )
        resp.raise_for_status()
        data = resp.json()
        return PendingDecision(
            id=data["id"],
            session_id=data["session_id"],
            agent_id=data["agent_id"],
            tool=data["tool"],
            status=data["status"],
            reason=data.get("reason", ""),
            policy=data.get("policy", ""),
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "AegisClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()
