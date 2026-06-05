from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Decision = Literal["ALLOW", "DENY", "MODIFY", "DEFER"]
DecisionStatus = Literal["pending", "approved", "rejected"]


@dataclass
class InterceptRequest:
    session_id: str
    agent_id: str
    tool: str
    args: dict[str, Any]
    context: str = ""
    cost_usd: float = 0.0
    token_count: int = 0


@dataclass
class InterceptResponse:
    decision: Decision
    risk_score: float
    latency_ms: int
    reason: str = ""
    policy: str = ""
    decision_id: str = ""
    modified_args: dict[str, Any] | None = None


@dataclass
class PendingDecision:
    id: str
    session_id: str
    agent_id: str
    tool: str
    status: DecisionStatus
    reason: str = ""
    policy: str = ""
