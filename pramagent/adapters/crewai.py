"""
pramagent.adapters.crewai
=========================
CrewAI adapter. Wrap any CrewAI Tool or Agent with ``PramagentGuard`` so its
calls go through Pramagent first.

Usage::

    from crewai import Agent, Tool
    from pramagent import Pramagent
    from pramagent.adapters.crewai import PramagentGuard

    armor = Pramagent(...)
    guard = PramagentGuard(armor=armor)

    @guard.wrap_tool(name="send_email", action_label="email_send")
    def send_email(to: str, subject: str, body: str): ...

    safe_agent = guard.wrap_agent(Agent(role="planner", ...))
"""
from __future__ import annotations

import asyncio
import functools
from typing import Any, Callable, Optional

from ..core import Pramagent
from ..types import AgentResponse, Verdict


class PramagentGuard:
    """Factory of guarded CrewAI wrappers."""

    def __init__(self, armor: Pramagent, *,
                 tenant_id: str = "crewai",
                 session_id: str = "default"):
        self.armor = armor
        self.tenant_id = tenant_id
        self.session_id = session_id

    # Tool wrapper
    def wrap_tool(self, fn: Optional[Callable] = None, *,
                  name: Optional[str] = None,
                  action_label: str = "tool_call"):
        """Decorator. ``PramagentGuard(armor=...).wrap_tool(fn)``."""
        def _decorate(f: Callable) -> Callable:
            tool_name = name or getattr(f, "__name__", "tool")
            is_coro = asyncio.iscoroutinefunction(f)

            @functools.wraps(f)
            def sync_w(*args, **kwargs):
                decision = self.armor.validate_tool(
                    tool_name, {"args": list(args), "kwargs": dict(kwargs)},
                    tenant_id=self.tenant_id, session_id=self.session_id,
                    action_label=action_label,
                )
                if decision.verdict in (Verdict.BLOCK, Verdict.ESCALATE):
                    raise PermissionError(
                        f"tool '{tool_name}' not authorized by Pramagent: {decision.reason}")
                return f(*args, **kwargs)

            @functools.wraps(f)
            async def async_w(*args, **kwargs):
                decision = self.armor.validate_tool(
                    tool_name, {"args": list(args), "kwargs": dict(kwargs)},
                    tenant_id=self.tenant_id, session_id=self.session_id,
                    action_label=action_label,
                )
                if decision.verdict in (Verdict.BLOCK, Verdict.ESCALATE):
                    raise PermissionError(
                        f"tool '{tool_name}' not authorized by Pramagent: {decision.reason}")
                return await f(*args, **kwargs)

            return async_w if is_coro else sync_w

        if fn is not None and callable(fn):
            return _decorate(fn)
        return _decorate

    # Agent wrapper
    def wrap_agent(self, agent: Any) -> Any:
        """Patch a CrewAI Agent so its prompt → response cycle runs through
        Pramagent. Returns the same agent object (mutated in place) — CrewAI's
        crew machinery keeps the reference and so won't break.
        """
        if not hasattr(agent, "execute_task"):
            # Not the shape we expect; bail out without changing the object.
            return agent

        original = agent.execute_task

        @functools.wraps(original)
        def patched(task, *args, **kwargs):
            prompt = getattr(task, "description", "") or getattr(task, "prompt", "") or str(task)
            try:
                loop = asyncio.get_event_loop()
                in_loop = loop.is_running()
            except RuntimeError:
                in_loop = False
            if in_loop:
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    resp: AgentResponse = ex.submit(
                        asyncio.run,
                        self.armor.run(prompt, tenant_id=self.tenant_id,
                                       session_id=self.session_id),
                    ).result()
            else:
                resp = asyncio.run(self.armor.run(
                    prompt, tenant_id=self.tenant_id, session_id=self.session_id))
            if resp.blocked:
                return "[BLOCKED by Pramagent: " + resp.block_reason + "]"
            # The original agent still does the real work — Pramagent gates input.
            return original(task, *args, **kwargs)

        agent.execute_task = patched
        return agent


__all__ = ["PramagentGuard"]
