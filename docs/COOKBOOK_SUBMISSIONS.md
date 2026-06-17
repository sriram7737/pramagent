# Cookbook Submission Plan

This file tracks vendor-affiliated distribution paths for Pramagent. The goal is
not to advertise the package directly; it is to contribute useful, runnable
recipes that show trust middleware around real provider calls.

## 1. Anthropic Claude Cookbook

**Target repository:** `anthropics/claude-cookbooks`

**Proposed path:** `patterns/agents/trust_middleware_guardrails.ipynb`

**Working title:** Adding a trust layer to Claude agent loops

**Recipe angle:**

Show a minimal Claude tool-agent loop, then wrap the same loop with Pramagent so
the model is not the final authority. The recipe should demonstrate:

- PII scrubbing before the Claude call.
- Prompt-injection blocking before provider contact.
- ToolGuard validation before any side-effect tool executes.
- HITL idle-on-silence for consequential actions.
- A printed trace hash and layer-event table.

**PR framing:**

This is a guardrails-as-code pattern for Claude agents. Pramagent is the
example middleware, but the recipe should teach the pattern more than the
package.

**Draft PR body:**

```markdown
## Summary

Adds a Claude agent-safety recipe showing how to wrap an agent loop with a
deterministic trust layer outside the model. The notebook demonstrates PII
scrubbing, prompt-injection isolation, HITL escalation, ToolGuard policy, and
tamper-evident trace hashes.

## Why

Claude can refuse unsafe requests, but production agent systems still need
external control boundaries for tools, approvals, and audit evidence. This
recipe gives developers a small runnable pattern.

## Validation

- Notebook runs with `ANTHROPIC_API_KEY` from the environment.
- No API keys or secrets are committed.
- Outputs retained only for safe demo prompts.
```

## 2. OpenAI Cookbook

**Target repository:** `openai/openai-cookbook`

**Proposed path:** `examples/Pramagent_trust_layer_for_responses_api.ipynb`

**Working title:** Adding a trust layer around Responses API agent calls

**Recipe angle:**

Use the OpenAI Responses API for a small tool-calling agent, then validate the
tool proposal through Pramagent before execution. Keep the recipe focused on the
developer pattern:

- Let the model propose a tool call.
- Validate tool name, JSON schema, tenant scope, and side-effect policy outside
  the model.
- Escalate high-risk tools to HITL.
- Persist a trace hash for the decision.

**Important review note:**

OpenAI Cookbook contributions are community reviewed on a best-effort basis and
are not guaranteed to merge. Treat the PR as credibility and feedback, not as a
traffic guarantee.

## 3. Google Dev Library

**Submission artifact:** `docs/GOOGLE_DEV_LIBRARY_SUBMISSION.md`

**Runnable hook:** `examples/gemini_trust_layer.py`

**Recipe angle:**

Show Gemini wrapped by deterministic trust controls: PII scrubbing, isolation,
HITL escalation, reliability safe default, and tamper-evident audit hashes.

## Launch Order

1. Publish the Gemini example and Google Dev Library draft in this repo.
2. Prepare the Claude notebook because it is the clearest agent-loop story.
3. Port the same pattern to OpenAI Responses API after the Claude draft is clean.
4. Submit the strongest provider recipe to Google Dev Library.

## Non-Negotiables

- No hardcoded API keys.
- No claims that prompt injection is solved.
- Keep each recipe runnable in under five minutes.
- Show both positive and negative cases.
- Print a trace hash in the final cell/output.
