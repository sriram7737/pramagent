"""
pramagent.adapters.generic
==========================
Framework-agnostic helpers. Use these when there's no dedicated adapter for
your stack — or when you want to reuse the same guard inside a custom loop.

    protect(armor, fn)          # wrap an async LLM-call coroutine
    protect_tool(armor, fn)     # wrap a tool function (sync or async)
    guarded_tool(...)           # alias/decorator for existing Python tools
"""
from __future__ import annotations

import asyncio
import functools
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from ..core import Pramagent
from ..action_control import ActionRequest
from ..types import AgentResponse, Verdict


@dataclass
class ProtectedCallResult:
    """Return value from a protected wrapper."""
    output: Any
    blocked: bool = False
    reason: str = ""
    trace_id: Optional[str] = None


def protect(armor: Pramagent, fn: Callable[..., Awaitable[str]],
            *, action: str = "respond"):
    """Wrap an async LLM-call coroutine. The wrapped function takes the user
    prompt as its first positional argument and Pramagent provides the
    pre/post checks, PII scrubbing, HITL gate, and audit trail.

    Example::

        @protect(armor)
        async def call_my_model(prompt: str) -> str:
            return await my_provider.complete(prompt)
    """
    @functools.wraps(fn)
    async def wrapper(prompt: str, *,
                      tenant_id: str = "default",
                      session_id: str = "default",
                      **kwargs) -> ProtectedCallResult:
        # We need the provider behind armor to be the actual model. If the
        # caller passes their own coroutine, we use Pramagent.run() with the
        # provider already configured on `armor`.
        resp: AgentResponse = await armor.run(
            prompt, tenant_id=tenant_id, session_id=session_id, action=action)
        return ProtectedCallResult(
            output=resp.output,
            blocked=resp.blocked,
            reason=resp.block_reason,
            trace_id=resp.trace.call_id,
        )
    return wrapper


def protect_tool(armor: Pramagent, fn: Optional[Callable[..., Any]] = None,
                 *, tool_name: Optional[str] = None,
                 action_label: str = "tool_call"):
    """Wrap a tool function so every invocation passes through ToolGuardLayer
    first. Works on sync and async callables.

    Example::

        @protect_tool(armor, tool_name="send_email")
        def send_email(to: str, body: str): ...
    """
    if fn is None:
        return lambda real_fn: protect_tool(
            armor,
            real_fn,
            tool_name=tool_name,
            action_label=action_label,
        )

    name = tool_name or getattr(fn, "__name__", "tool")
    is_coro = asyncio.iscoroutinefunction(fn)

    def _raise_if_not_allowed(decision):
        if decision.verdict == Verdict.BLOCK:
            raise PermissionError(f"tool blocked by Pramagent: {decision.reason}")
        if decision.verdict == Verdict.ESCALATE:
            raise PermissionError(
                "tool requires human approval before execution: "
                f"{decision.reason}")

    @functools.wraps(fn)
    def sync_wrapper(*args, tenant_id: str = "default",
                     session_id: str = "default", **kwargs):
        decision = armor.validate_tool(
            name, {"args": list(args), "kwargs": dict(kwargs)},
            tenant_id=tenant_id, session_id=session_id,
            action_label=action_label,
        )
        _raise_if_not_allowed(decision)
        return fn(*args, **kwargs)

    @functools.wraps(fn)
    async def async_wrapper(*args, tenant_id: str = "default",
                            session_id: str = "default", **kwargs):
        decision = armor.validate_tool(
            name, {"args": list(args), "kwargs": dict(kwargs)},
            tenant_id=tenant_id, session_id=session_id,
            action_label=action_label,
        )
        _raise_if_not_allowed(decision)
        return await fn(*args, **kwargs)

    return async_wrapper if is_coro else sync_wrapper


def guarded_tool(armor: Pramagent, fn: Optional[Callable[..., Any]] = None,
                 *, policy: Optional[str] = None,
                 tool_name: Optional[str] = None,
                 action_label: str = "tool_call"):
    """One-line decorator for existing Python tools.

    ``policy`` names the ToolPolicy/tool entry to evaluate. It is an alias for
    ``tool_name`` so application code can read naturally::

        @guarded_tool(armor, policy="finance_payment")
        def send_wire(amount_usd: float, destination: str): ...

    BLOCK and ESCALATE both stop execution. Use the full HITL queue / dashboard
    path when a human needs to approve and then re-run the side effect.
    """
    selected_name = tool_name or policy
    if fn is None:
        return lambda real_fn: guarded_tool(
            armor,
            real_fn,
            policy=selected_name,
            action_label=action_label,
        )
    return protect_tool(
        armor,
        fn,
        tool_name=selected_name,
        action_label=action_label,
    )

def mediated_tool(
    armor: Pramagent,
    fn: Optional[Callable[..., Any]] = None,
    *,
    request_factory: Callable[[tuple[Any, ...], dict[str, Any]], ActionRequest],
    tool_name: Optional[str] = None,
    operator_token: str,
):
    """Register and wrap a synchronous tool behind task-scoped mediation.

    ``request_factory`` is trusted adapter code: it extracts operation,
    resources, destinations, and limits from detached call arguments. The
    wrapped function never calls ``fn`` directly. It returns an
    ``ActionDecision``; pending approval therefore cannot fall through into
    execution.

    For a hard process boundary, register the executor in a separate service
    and submit the same ActionRequest over an authenticated transport instead.
    """
    if fn is None:
        return lambda real_fn: mediated_tool(
            armor,
            real_fn,
            request_factory=request_factory,
            tool_name=tool_name,
            operator_token=operator_token,
        )
    controller = armor.action_controller
    if controller is None:
        raise RuntimeError("mediated_tool requires Pramagent(action_controller=...)")
    if asyncio.iscoroutinefunction(fn):
        raise TypeError("mediated_tool currently requires a synchronous executor")
    name = tool_name or getattr(fn, "__name__", "tool")

    def executor(payload: dict[str, Any], request: ActionRequest):
        call_args = payload.get("args")
        call_kwargs = payload.get("kwargs")
        if type(call_args) is not list or type(call_kwargs) is not dict:
            raise ValueError("mediated tool payload is malformed")
        return fn(*call_args, **call_kwargs)

    controller.register_executor(name, executor, token=operator_token)

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        # Reuse ActionRequest canonicalization as the immutable boundary; the
        # factory receives detached plain values only.
        payload = {"args": list(args), "kwargs": dict(kwargs)}
        detached = ActionRequest.create(
            execution_id="_snapshot", task_id="_snapshot", tenant_id="_snapshot",
            policy_version=0, tool_name=name, operation="_snapshot",
            arguments=payload,
        ).arguments
        request = request_factory(tuple(detached["args"]), detached["kwargs"])
        if not isinstance(request, ActionRequest):
            raise TypeError("request_factory must return ActionRequest")
        if request.tool_name != name:
            raise ValueError("request_factory tool_name does not match the registered executor")
        return armor.execute_action(request)

    return wrapper
