"""
pramagent.rules.jailbreak
=========================
Jailbreak / prompt-override pattern corpus.

Sources (all open):
  - JailbreakBench (Chao et al., 2024) https://github.com/JailbreakBench/jailbreakbench
  - HarmBench (Mazeika et al., 2024)   https://github.com/centerforaisafety/HarmBench
  - Garak                              https://github.com/NVIDIA/garak
  - Anthropic red-team write-ups, OWASP LLM01 examples

Each rule has a ``rule_id`` that starts with ``jb_`` so they're easy to filter
in the audit trace, and a ``detail`` field that names the source family. No
classifier is required: every detection is a literal regex an auditor can read.
"""
from __future__ import annotations

from ..layers import Rule
from ..types import Verdict


# Each tuple is (rule_id, pattern, detail).
# Patterns are case-insensitive (Rule compiles with re.IGNORECASE).
_PATTERNS: list[tuple[str, str, str]] = [
    # ignore-prior-instructions family
    ("jb_ignore_previous",
     r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|messages|directives|rules)",
     "JailbreakBench/HarmBench: ignore-previous-instructions"),
    ("jb_disregard_above",
     r"(?:disregard|forget|override|bypass)\s+(?:all|any|the)?\s*(?:above|previous|prior|earlier|system)\s*(?:instructions|prompts|messages|rules|guidelines)",
     "OWASP LLM01: instruction-override"),
    ("jb_new_instructions",
     r"(?:here\s+are|these\s+are)\s+(?:your\s+)?new\s+(?:instructions|rules|directives)",
     "Garak: instruction-replacement"),
    ("jb_system_override",
     r"<\s*(?:system|admin|root)\s*>\s*[^<]{0,200}(?:override|reset|new\s+rules)",
     "OWASP LLM01: fake-system-tag override"),

    # persona / jailbreak named modes
    ("jb_dan",
     r"\b(?:do\s+anything\s+now|d\.?a\.?n\.?\s+mode|act\s+as\s+dan)\b",
     "JailbreakBench: DAN persona"),
    ("jb_developer_mode",
     r"\b(?:developer|debug|jailbreak|unrestricted|godmode|root)\s+mode\s+(?:enabled|on|activated)\b",
     "Garak: developer-mode prompt"),
    ("jb_evil_twin",
     r"\b(?:evil|opposite|anti)\s+(?:twin|version|persona)\b.{0,80}(?:no\s+restrictions|no\s+rules|no\s+filters)",
     "HarmBench: evil-twin persona"),
    ("jb_pretend_no_rules",
     r"pretend\s+(?:you\s+(?:are|have)|to\s+(?:be|have))\s+(?:no\s+(?:rules|restrictions|filters|guidelines)|an?\s+(?:unrestricted|uncensored)\s+(?:ai|assistant|model))",
     "OWASP LLM01: persona-bypass"),
    ("jb_aim",
     r"\baim\s+(?:mode|prompt|character)\b|always\s+intelligent\s+and\s+machiavellian",
     "JailbreakBench: AIM jailbreak"),
    ("jb_stan",
     r"\bstan\s+mode\b|strive\s+to\s+avoid\s+norms",
     "JailbreakBench: STAN jailbreak"),

    # "as <role>" social engineering
    ("jb_as_admin",
     r"\bas\s+(?:an?\s+)?(?:admin|administrator|developer|engineer|moderator|owner|superuser|sysadmin)\b.{0,120}(?:disable|turn\s+off|bypass|ignore)",
     "Garak: privilege-escalation framing"),
    ("jb_grandma_exploit",
     r"(?:my\s+)?(?:grand(?:ma|mother)|grandpa|grandfather)\s+(?:used\s+to|would|always)\s+(?:tell|read|sing)",
     "Reddit r/ChatGPT: grandma-exploit (CVE-style)"),

    # encoding / obfuscation prompts
    ("jb_base64_decode",
     r"(?:decode|interpret|run)\s+(?:the\s+following|this)\s+(?:base64|hex|rot13|binary|ascii)\b",
     "HarmBench: encoded-payload bypass"),
    ("jb_leetspeak",
     r"(?:respond|reply|answer)\s+in\s+(?:leet(?:speak)?|l33t|1337)",
     "HarmBench: leetspeak channel"),
    ("jb_zero_width",
     r"[​‌‍⁠﻿]{3,}",
     "OWASP LLM01: zero-width injection"),

    # "for educational purposes" framings
    ("jb_educational",
     r"(?:purely\s+)?(?:for\s+)?(?:educational|academic|research|hypothetical)\s+purposes?\s+(?:only|,)?.{0,80}(?:how\s+(?:to|do)|provide|explain|step.{0,5}by.{0,5}step)",
     "HarmBench: educational framing"),
    ("jb_writing_a_book",
     r"(?:i'?m\s+)?writing\s+(?:a\s+)?(?:book|novel|story|article|paper)\s+(?:about|on)\s+(?:how\s+to|the\s+process\s+of)",
     "HarmBench: fiction-cover framing"),
    ("jb_thought_experiment",
     r"\bthought\s+experiment\b.{0,80}(?:how\s+(?:to|would)|step.{0,5}by.{0,5}step)",
     "Garak: hypothetical framing"),

    # direct policy-bypass keywords
    ("jb_no_warnings",
     r"(?:do\s+not|don'?t|never)\s+(?:include|add|give)\s+(?:any\s+)?(?:warnings?|disclaimers?|caveats?|safety\s+notes?)",
     "JailbreakBench: warning-suppression"),
    ("jb_no_apologies",
     r"(?:do\s+not|don'?t|never)\s+(?:apologi[sz]e|say\s+sorry|refuse)",
     "JailbreakBench: refusal-suppression"),
    ("jb_unfiltered",
     r"\b(?:unfiltered|unrestricted|uncensored|jailbroken)\s+(?:response|answer|reply|output|version)\b",
     "OWASP LLM01: filter-bypass keyword"),
    ("jb_opposite_day",
     r"\bopposite\s+day\b|reverse\s+(?:all\s+)?(?:your\s+)?(?:rules|instructions)",
     "JailbreakBench: opposite-day"),

    # prompt-injection via tool / document content
    ("jb_indirect_injection_marker",
     r"(?:IMPORTANT|URGENT|SYSTEM\s+NOTE)[: ]+\s*(?:assistant|model|ai)\s*[:,]\s*(?:ignore|disregard|new\s+instructions)",
     "OWASP LLM01: indirect prompt injection marker"),
    ("jb_injected_role",
     r"\[\s*(?:system|user|assistant)\s*\]\s*:?\s*(?:you\s+are\s+now|new\s+task|override)",
     "Garak: injected-role tag"),
    ("jb_pii_exfil_request",
     r"(?:list|show|print|reveal|dump|leak)\s+(?:all|every|the)\s+(?:system\s+prompt|hidden\s+instructions|api\s+keys|secrets|env(?:ironment)?\s+vars?)",
     "OWASP LLM06: sensitive-info disclosure"),

    # chain-of-thought extraction
    ("jb_reveal_system_prompt",
     r"(?:repeat|reveal|show|print)\s+(?:the|your)\s+(?:initial|system|original|first)\s+(?:prompt|instructions|message)",
     "OWASP LLM06: system-prompt extraction"),
    ("jb_reveal_above",
     r"(?:repeat|echo|print)\s+(?:everything|all\s+the\s+text)\s+(?:above|before\s+this|so\s+far)",
     "OWASP LLM06: prompt-leak"),

    # DAN-style "two responses"
    ("jb_two_responses",
     r"(?:give|provide|respond\s+with)\s+two\s+(?:responses|answers|versions).{0,80}(?:normal|standard|safe).{0,40}(?:jailbroken|uncensored|dan|unrestricted)",
     "JailbreakBench: dual-output DAN"),
    # Dangerous capability requests are broad escalation signals.
    ("jb_make_weapon",
     r"\bhow\s+(?:to|do\s+i|can\s+i)\s+(?:make|build|synthesi[sz]e|construct)\s+(?:a\s+)?(?:bomb|explosive|nerve\s+agent|bio(?:logical)?\s+weapon|nuclear\s+(?:bomb|device))",
     "HarmBench: harmful-capability request"),
    ("jb_malware",
     r"\b(?:write|generate|build)\s+(?:me\s+)?(?:a\s+)?(?:keylogger|ransomware|trojan|rootkit|botnet|RAT)\b",
     "HarmBench: malware-authoring request"),
    ("jb_synthesize_drug",
     r"\bsynthesi[sz]e\s+(?:methamphetamine|fentanyl|cocaine|heroin|lsd|mdma)\b",
     "HarmBench: drug-synthesis request"),

    # token-smuggling / homoglyph
    ("jb_homoglyph_ignore",
     r"[іі]gnore|іgnore|ignоre|іgnоre",   # cyrillic-i / cyrillic-o substitutions
     "Garak: homoglyph substitution"),

    # refusal-test probes
    ("jb_refusal_test",
     r"will\s+you\s+(?:refuse|decline|say\s+no)\s+if\s+i\s+ask",
     "JailbreakBench: refusal-probe"),

    # plain "ignore safety"
    ("jb_ignore_safety",
     r"(?:ignore|bypass|disable|turn\s+off)\s+(?:your\s+)?(?:safety|content|moderation)\s+(?:guidelines|filter|policy|rules)",
     "OWASP LLM01: safety-rule bypass"),
]


JAILBREAK_PATTERNS: list[Rule] = [
    Rule(rule_id=rid, action=Verdict.BLOCK, pattern=pat, detail=detail)
    for rid, pat, detail in _PATTERNS
]

__all__ = ["JAILBREAK_PATTERNS"]
