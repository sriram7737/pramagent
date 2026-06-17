# Google Dev Library Submission Draft

Pramagent's Google-tech hook is the Gemini trust-layer recipe:

- Code: `examples/gemini_trust_layer.py`
- Package: `https://pypi.org/project/pramagent/`
- Repository: `https://github.com/sriram7737/pramagent`
- Live demo: `https://web-production-015e6.up.railway.app/`

## Proposed Entry

**Title:** Adding deterministic trust controls to Gemini agent calls with Pramagent

**Category:** Machine Learning / AI

**Google technology used:** Gemini API through `GeminiProvider`

**Summary:**

Pramagent is an open-source Python trust layer for LLM agents. This recipe shows
how to wrap Gemini calls with deterministic controls that run outside the model:
PII scrubbing before provider contact, prompt-injection isolation, safety
escalation for consequential actions, reliability fail-closed behavior, and
tamper-evident audit hashes for each run.

## Why It Fits

Google Dev Library features open-source projects and technical content built
with Google technologies. This submission is not a generic package listing; it
is a Gemini-specific implementation recipe that demonstrates a production AI
safety pattern.

## Repro Steps

```powershell
pip install "pramagent[api]"
$env:GEMINI_API_KEY="..."
python examples/gemini_trust_layer.py
```

Expected evidence:

- Allowed Gemini call includes provider/model fields.
- PII scenario redacts SSN/email before model contact.
- Injection scenario blocks before provider contact.
- Wire-transfer scenario idles through HITL and does not execute silently.
- Each scenario prints `this_hash`; final line prints `audit_chain_valid: True`.

## Honest Scope

Pramagent does not claim to solve prompt injection. The realistic claim is
defense-in-depth: deterministic pre-model controls, optional semantic
classifiers/judges, source provenance, HITL gates, and auditable fail-closed
behavior around Gemini or any other provider.

## Suggested Submission Links

- README: `https://github.com/sriram7737/pramagent#readme`
- Implementation status:
  `https://github.com/sriram7737/pramagent/blob/main/docs/IMPLEMENTATION_STATUS.md`
- Live test results:
  `https://github.com/sriram7737/pramagent/blob/main/docs/LIVE_TEST_RESULTS.md`
- Hardening guide:
  `https://github.com/sriram7737/pramagent/blob/main/docs/HARDENING_GUIDE.md`

## Suggested Tags

`gemini`, `ai-agents`, `llm-security`, `guardrails`, `audit-logging`,
`human-in-the-loop`, `python`, `open-source`
