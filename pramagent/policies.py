"""
pramagent.policies
==================
Policy-as-code helpers for ToolGuard.

Security teams should be able to review and version tool policies without
editing application Python. JSON is supported with the standard library. YAML
is supported when PyYAML is installed; it is optional so the base package stays
small.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from .layers import ToolGuardLayer, ToolPolicy
from .layers.tool_guard import ToolDecision
from .types import Verdict


class PolicyLoadError(ValueError):
    """Raised when a policy-as-code file cannot be parsed into ToolPolicy."""


@dataclass
class BacktestCase:
    """One historical/proposed tool call used by ``backtest_policy_file``."""

    tool_name: str
    arguments: dict[str, Any]
    tenant_id: str = "default"
    session_id: str = "default"
    action_label: str = "tool_call"
    expected: Optional[str] = None
    case_id: str = ""


@dataclass
class BacktestResult:
    total: int
    allowed: int
    blocked: int
    escalated: int
    mismatches: list[dict[str, Any]]
    decisions: list[ToolDecision]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "allowed": self.allowed,
            "blocked": self.blocked,
            "escalated": self.escalated,
            "mismatches": self.mismatches,
            "decisions": [decision.to_dict() for decision in self.decisions],
        }


def _read_structured_file(path: str | Path) -> Any:
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    suffix = file_path.suffix.lower()
    if suffix == ".json":
        return json.loads(text)
    if suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except Exception as exc:
            raise PolicyLoadError(
                "YAML policies require PyYAML. Install it with "
                "`pip install pyyaml`, or use JSON policy files."
            ) from exc
        return yaml.safe_load(text)
    raise PolicyLoadError(
        f"unsupported policy file extension {suffix!r}; use .json, .yaml, or .yml"
    )


def _as_verdict(value: Any, *, field: str) -> Verdict:
    if isinstance(value, Verdict):
        return value
    try:
        return Verdict(str(value).strip().lower())
    except Exception as exc:
        raise PolicyLoadError(
            f"{field} must be one of {[v.value for v in Verdict]}, got {value!r}"
        ) from exc


def _as_optional_set(value: Any, *, field: str) -> Optional[set[str]]:
    if value in (None, "", "*"):
        return None
    if not isinstance(value, (list, tuple, set)):
        raise PolicyLoadError(f"{field} must be a list of strings or omitted")
    return {str(item) for item in value}


def _as_optional_int(value: Any, *, field: str) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        parsed = int(value)
    except Exception as exc:
        raise PolicyLoadError(f"{field} must be an integer or omitted") from exc
    if parsed < 0:
        raise PolicyLoadError(f"{field} must be >= 0")
    return parsed


def tool_policy_from_dict(data: dict[str, Any]) -> ToolPolicy:
    """Build one ToolPolicy from JSON/YAML data."""
    if not isinstance(data, dict):
        raise PolicyLoadError("each policy must be an object")
    if not data.get("name"):
        raise PolicyLoadError("policy.name is required")
    if not isinstance(data.get("schema"), dict):
        raise PolicyLoadError(f"policy {data.get('name')!r} requires object schema")

    return ToolPolicy(
        name=str(data["name"]),
        schema=dict(data["schema"]),
        side_effect=str(data.get("side_effect", "read")),
        action=_as_verdict(data.get("action", Verdict.ALLOW.value), field="action"),
        allowed_tenants=_as_optional_set(
            data.get("allowed_tenants"), field="allowed_tenants"),
        allowed_actions=_as_optional_set(
            data.get("allowed_actions"), field="allowed_actions"),
        max_calls_per_session=_as_optional_int(
            data.get("max_calls_per_session"), field="max_calls_per_session"),
        detail=str(data.get("detail", "")),
        output_schema=data.get("output_schema"),
        max_output_bytes=int(data.get("max_output_bytes", 0) or 0),
        skip_arg_injection_scan=bool(data.get("skip_arg_injection_scan", False)),
        escalate_if_severity_gte=data.get("escalate_if_severity_gte"),
    )


def load_tool_policies(path: str | Path) -> list[ToolPolicy]:
    """Load ToolPolicy objects from a JSON/YAML policy file.

    Supported shapes::

        {"policies": [{...}, {...}]}
        [{...}, {...}]
    """
    raw = _read_structured_file(path)
    if raw is None:
        raise PolicyLoadError("policy file is empty")
    policies = raw.get("policies") if isinstance(raw, dict) else raw
    if not isinstance(policies, list):
        raise PolicyLoadError("policy file must contain a list or {policies: [...]}")
    return [tool_policy_from_dict(policy) for policy in policies]


def load_tool_guard(
    path: str | Path,
    *,
    default_verdict: Verdict = Verdict.BLOCK,
) -> ToolGuardLayer:
    """Build a ToolGuardLayer from a policy-as-code file."""
    return ToolGuardLayer(
        policies=load_tool_policies(path),
        default_verdict=default_verdict,
    )


def _iter_jsonl(path: str | Path) -> Iterable[dict[str, Any]]:
    for lineno, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except Exception as exc:
            raise PolicyLoadError(f"invalid JSONL at {path}:{lineno}") from exc
        if not isinstance(item, dict):
            raise PolicyLoadError(f"JSONL line {lineno} must be an object")
        yield item


def load_backtest_cases(path: str | Path) -> list[BacktestCase]:
    """Load backtest cases from .json or .jsonl.

    Each case needs ``tool_name`` and ``arguments``. Optional fields:
    ``tenant_id``, ``session_id``, ``action_label``, ``expected``, ``case_id``.
    ``expected`` can be ``allow``, ``block``, or ``escalate``.
    """
    file_path = Path(path)
    if file_path.suffix.lower() == ".jsonl":
        raw_cases = list(_iter_jsonl(file_path))
    elif file_path.suffix.lower() == ".json":
        raw = json.loads(file_path.read_text(encoding="utf-8"))
        raw_cases = raw.get("cases") if isinstance(raw, dict) else raw
        if not isinstance(raw_cases, list):
            raise PolicyLoadError("backtest JSON must be a list or {cases: [...]}")
    else:
        raise PolicyLoadError("backtest cases must be .json or .jsonl")

    cases: list[BacktestCase] = []
    for index, item in enumerate(raw_cases, 1):
        if not isinstance(item, dict):
            raise PolicyLoadError(f"backtest case {index} must be an object")
        if not item.get("tool_name"):
            raise PolicyLoadError(f"backtest case {index} missing tool_name")
        arguments = item.get("arguments", {})
        if not isinstance(arguments, dict):
            raise PolicyLoadError(f"backtest case {index} arguments must be an object")
        expected = item.get("expected")
        if expected is not None:
            expected = _as_verdict(expected, field="expected").value
        cases.append(BacktestCase(
            tool_name=str(item["tool_name"]),
            arguments=arguments,
            tenant_id=str(item.get("tenant_id", "default")),
            session_id=str(item.get("session_id", "default")),
            action_label=str(item.get("action_label", "tool_call")),
            expected=expected,
            case_id=str(item.get("case_id", f"case-{index}")),
        ))
    return cases


async def backtest_tool_guard_async(
    guard: ToolGuardLayer,
    cases: Iterable[BacktestCase],
) -> BacktestResult:
    """Evaluate a proposed ToolGuardLayer against historical/proposed cases."""
    decisions: list[ToolDecision] = []
    mismatches: list[dict[str, Any]] = []
    for case in cases:
        decision = await guard.evaluate_async(
            case.tool_name,
            case.arguments,
            tenant_id=case.tenant_id,
            session_id=case.session_id,
            action_label=case.action_label,
        )
        decisions.append(decision)
        if case.expected is not None and decision.verdict.value != case.expected:
            mismatches.append({
                "case_id": case.case_id,
                "tool_name": case.tool_name,
                "expected": case.expected,
                "actual": decision.verdict.value,
                "reason": decision.reason,
            })

    return BacktestResult(
        total=len(decisions),
        allowed=sum(1 for d in decisions if d.verdict == Verdict.ALLOW),
        blocked=sum(1 for d in decisions if d.verdict == Verdict.BLOCK),
        escalated=sum(1 for d in decisions if d.verdict == Verdict.ESCALATE),
        mismatches=mismatches,
        decisions=decisions,
    )


def backtest_policy_file(
    policy_file: str | Path,
    cases_file: str | Path,
) -> BacktestResult:
    """Load a policy file and backtest it against JSON/JSONL tool-call cases."""
    guard = load_tool_guard(policy_file)
    cases = load_backtest_cases(cases_file)
    return asyncio.run(backtest_tool_guard_async(guard, cases))
