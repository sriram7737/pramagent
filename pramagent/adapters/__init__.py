"""
pramagent.adapters
==================
Thin glue that lets people drop Pramagent into an existing agent framework
without rewriting their graph / hook / crew.

Every adapter does the same three things:
  1. Take a ``Pramagent`` instance you've already configured.
  2. Run the incoming prompt (or tool call) through ``armor.run()`` (or
     ``armor.validate_tool()``).
  3. Honour the verdict: forward, redact, block, or wait for HITL.

Each adapter lazy-imports its host framework, so installing pramagent does
NOT require langgraph / autogen / crewai to be present. If the host framework
is missing when you reach for the adapter, you get a clear ImportError.

Available adapters:

    pramagent.adapters.langgraph.PramagentNode    — node for a LangGraph state graph
    pramagent.adapters.autogen.PramagentHook      — pre-/post-hook for AutoGen agents
    pramagent.adapters.crewai.PramagentGuard      — wraps a CrewAI Tool

Generic helpers (no host framework needed):

    pramagent.adapters.generic.protect            — wrap any async callable
    pramagent.adapters.generic.protect_tool       — wrap any tool function
"""
from __future__ import annotations

from .autogen import PramagentHook
from .crewai import PramagentGuard
from .generic import guarded_tool, protect, protect_tool, ProtectedCallResult
from .langgraph import PramagentNode

__all__ = [
    "PramagentNode",
    "PramagentHook",
    "PramagentGuard",
    "protect",
    "protect_tool",
    "guarded_tool",
    "ProtectedCallResult",
]
