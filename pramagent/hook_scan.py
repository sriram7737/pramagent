"""
pramagent.hook_scan
===================
Single source of truth for the two *content* passes every Pramagent tool-call
hook runs AFTER ``ToolGuardLayer.evaluate()`` clears the structural checks:

  1. Prompt-injection heuristics  (IsolationLayer.scan_for_injection)
  2. PII / PHI regex              (ComplianceLayer.scrub)

Why this module exists
----------------------
The hook adapters (scripts/claude_code_hook.py, scripts/gemini_cli_hook.py,
scripts/codex_tool_hook.py, and the pramagent_guard.py plugin) historically
each reimplemented these passes, and they drifted into three distinct bypasses:

  * ``claude`` and ``gemini`` scanned only a hardcoded field list
    (``command``/``content``/``new_string``/...), so a payload routed through
    any other argument was never content-scanned.
  * the marketplace ``pramagent_guard`` plugin skipped BOTH passes entirely  - 
    it ran only the structural ToolGuard evaluate, i.e. 1 of the 3 defenses.
  * every adapter called ``scan_for_injection`` on the RAW argument text, which
    does not decode base64/hex/unicode runs the way ``evaluate_input`` does  -  so
    an *encoded* instruction-override slipped past the hook layer even though
    IsolationLayer is documented to decode-and-scan.

Centralizing here means every surface scans EVERY string leaf, decodes encoded
runs first, and reports the same de-duplicated finding shape. These remain
heuristics (a signal, not a boundary  -  see IsolationLayer's own docstring); the
structural allow-list + side-effect escalation in ToolGuardLayer is what
actually holds. This module only makes the *signal* consistent and unbypassable
by field-routing or encoding.
"""
from __future__ import annotations

from typing import Any


def iter_strings(value: Any, path: str = "$") -> list[tuple[str, str]]:
    """Return ``(path, text)`` for every string leaf in an arbitrarily nested
    ``tool_input``.

    Scanning every leaf (not a hardcoded field subset) is what closes the
    field-routing bypass: a prompt-injection or PII payload placed in any
    argument  -  a filename, a nested option, a list element  -  is seen, not just
    one placed in ``command``/``content``.
    """
    if isinstance(value, str):
        return [(path, value)]
    if isinstance(value, dict):
        out: list[tuple[str, str]] = []
        for key, child in value.items():
            out.extend(iter_strings(child, f"{path}.{key}"))
        return out
    if isinstance(value, list):
        out = []
        for index, child in enumerate(value):
            out.extend(iter_strings(child, f"{path}[{index}]"))
        return out
    return []


def _augmented(isolation: Any, text: str) -> str:
    """Text plus its decoded base64/hex/unicode runs, so an encoded payload is
    scanned in decoded form too.

    ``IsolationLayer._augment_decoded`` is the same helper ``evaluate_input``
    uses; calling it here gives the hook layer the same "encoding is not a
    bypass" property. Guarded with ``getattr`` so a stripped-down or future
    IsolationLayer without the helper degrades to scanning the raw text rather
    than raising.
    """
    augment = getattr(isolation, "_augment_decoded", None)
    if callable(augment):
        try:
            return augment(text)
        except Exception:
            return text
    return text


def scan_injection(tool_input: Any, isolation: Any) -> list[str]:
    """Ordered, de-duplicated prompt-injection ``pattern_id``s found across
    every string leaf of ``tool_input`` (decoded runs included).

    Empty means no heuristic fired  -  not a proof of safety.
    """
    pattern_ids: list[str] = []
    for _path, text in iter_strings(tool_input):
        if not text:
            continue
        for hit in isolation.scan_for_injection(_augmented(isolation, text)):
            pid = str(hit.get("pattern_id", "prompt_injection"))
            if pid not in pattern_ids:
                pattern_ids.append(pid)
    return pattern_ids


def scan_pii(tool_input: Any, compliance: Any) -> list[str]:
    """Sorted, de-duplicated PII/PHI labels found across every string leaf of
    ``tool_input``. Empty means no PII pattern matched.
    """
    labels: list[str] = []
    for _path, text in iter_strings(tool_input):
        if not text:
            continue
        _scrubbed, redactions = compliance.scrub(text)
        labels.extend(str(label) for label in redactions)
    return sorted(set(labels))
