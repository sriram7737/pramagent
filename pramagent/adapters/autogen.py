"""
pramagent.adapters.autogen
==========================
AutoGen adapter. Register a ``PramagentHook`` on any AutoGen agent and every
message it produces or receives is passed through the trust pipeline.

AutoGen exposes a few extension points; we support both:

  * ``ConversableAgent.register_hook("process_message_before_send", fn)``
  * ``ConversableAgent.register_reply([trigger], reply_func)``

You don't have to know which API your AutoGen version exposes — call
``PramagentHook.attach(agent)`` and the adapter picks the right one.

Usage::

    from autogen import ConversableAgent
    from pramagent import Pramagent, SafetyLayer
    from pramagent.rules import ALL_RULES
    from pramagent.adapters.autogen import PramagentHook

    armor = Pramagent(safety=SafetyLayer(rules=ALL_RULES))
    agent = ConversableAgent(...)
    PramagentHook(armor=armor).attach(agent)
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from ..core import Pramagent
from ..types import AgentResponse

log = logging.getLogger(__name__)


class PramagentHook:
    """Pre/post hook for AutoGen agents.

    Parameters
    ----------
    armor : Pramagent
        Pre-configured orchestrator.
    direction : str
        ``"both"`` (default), ``"incoming"``, or ``"outgoing"``.
    tenant_id, session_id : str
        Default labels for traces.
    """

    def __init__(self, armor: Pramagent, *,
                 direction: str = "both",
                 tenant_id: str = "autogen",
                 session_id: str = "default"):
        if direction not in ("both", "incoming", "outgoing"):
            raise ValueError("direction must be 'both', 'incoming', or 'outgoing'")
        self.armor = armor
        self.direction = direction
        self.tenant_id = tenant_id
        self.session_id = session_id

    # Public API
    def attach(self, agent: Any) -> None:
        """Wire the hook into an AutoGen agent using whichever API is available."""
        if hasattr(agent, "register_hook"):
            try:
                if self.direction in ("both", "outgoing"):
                    agent.register_hook("process_message_before_send",
                                        self._before_send)
                if self.direction in ("both", "incoming"):
                    # Newer AutoGen exposes "process_last_received_message"
                    if hasattr(agent, "register_hook"):
                        agent.register_hook("process_last_received_message",
                                            self._after_receive)
                return
            except Exception as exc:
                log.debug("AutoGen register_hook path failed; trying fallback: %s", exc)

        # Fallback: wrap generate_reply if no hook API present
        if hasattr(agent, "register_reply"):
            agent.register_reply([Any], self._reply_wrapper, position=0)
            return

        raise RuntimeError(
            "PramagentHook could not find a registration API on the agent. "
            "Pass an AutoGen ConversableAgent (or set up the wrapper manually).")

    # Hook callbacks
    def _run(self, prompt: str) -> AgentResponse:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    return ex.submit(
                        asyncio.run,
                        self.armor.run(prompt, tenant_id=self.tenant_id,
                                       session_id=self.session_id),
                    ).result()
        except RuntimeError:
            pass
        return asyncio.run(self.armor.run(
            prompt, tenant_id=self.tenant_id, session_id=self.session_id))

    def _before_send(self, sender, message, recipient, silent):
        text = message if isinstance(message, str) else str(message.get("content", ""))
        resp = self._run(text)
        if resp.blocked:
            return "[BLOCKED by Pramagent: " + resp.block_reason + "]"
        if isinstance(message, dict):
            new = dict(message)
            new["content"] = resp.output
            return new
        return resp.output

    def _after_receive(self, agent, messages):
        if not messages:
            return messages
        last = messages[-1]
        text = last if isinstance(last, str) else str(last.get("content", ""))
        resp = self._run(text)
        if isinstance(last, dict):
            last = dict(last)
            last["content"] = ("[BLOCKED by Pramagent]" if resp.blocked
                               else resp.output)
            return messages[:-1] + [last]
        return messages[:-1] + [resp.output]

    def _reply_wrapper(self, recipient, messages, sender, config):
        # AutoGen register_reply signature; returning (False, None) lets the
        # agent's normal reply path proceed. We use this purely as a gate.
        if not messages:
            return False, None
        text = messages[-1].get("content", "") if isinstance(messages[-1], dict) else str(messages[-1])
        resp = self._run(text)
        if resp.blocked:
            return True, "[BLOCKED by Pramagent: " + resp.block_reason + "]"
        return False, None


__all__ = ["PramagentHook"]
