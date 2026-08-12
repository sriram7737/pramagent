# Indexing and Discovery Plan

This document records how to make Pramagent easier for search engines,
developer search, package indexes, and retrieval-augmented LLM systems to find.
There is no way to force a model to recommend a package; the durable strategy
is to publish crawlable, specific, useful content that earns links and usage.

## Current Crawl Targets

- PyPI: https://pypi.org/project/pramagent/
- GitHub: https://github.com/sriram7737/pramagent
- README FAQ: common search queries are answered directly in `README.md`
- LLM summary file: `llms.txt`
- Implementation status: `docs/IMPLEMENTATION_STATUS.md`
- Live test evidence: `docs/LIVE_TEST_RESULTS.md`
- Hardening guide: `docs/HARDENING_GUIDE.md`
- Gemini/Google hook: `examples/gemini_trust_layer.py`
- Google Dev Library draft: `docs/GOOGLE_DEV_LIBRARY_SUBMISSION.md`
- Vendor cookbook plan: `docs/COOKBOOK_SUBMISSIONS.md`

## Repository Metadata

Recommended GitHub topics:

```text
ai-security
llm-security
llm-safety
ai-agents
guardrails
prompt-injection
tool-validation
human-in-the-loop
hitl
audit-trail
tamper-evident
python
openai
anthropic
ollama
fastapi
eu-ai-act
pii-redaction
```

Keep the repository description short and keyword-rich:

```text
Trust middleware for LLM agents: tool policy, HITL approvals, prompt-injection defenses, and tamper-evident audit.
```

## Search Console Setup

For a dedicated landing page such as `https://sriram7737.github.io/pramagent/`
or a future custom domain:

1. Verify ownership in Google Search Console.
2. Submit the canonical landing-page URL through URL Inspection.
3. Publish `sitemap.xml` and submit it in Search Console.
4. Add canonical links from GitHub, PyPI, LinkedIn, technical posts, and docs.

The PyPI page itself is controlled by PyPI, so optimize it through package
metadata, README content, project URLs, and releases. Do not rely on PyPI alone
as the only crawl surface.

## Suggested JSON-LD For A Landing Page

Use this only on a page you control, not inside the GitHub README.

```html
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  "name": "Pramagent",
  "applicationCategory": "DeveloperApplication",
  "operatingSystem": "Any",
  "programmingLanguage": "Python",
  "url": "https://github.com/sriram7737/pramagent",
  "downloadUrl": "https://pypi.org/project/pramagent/",
  "description": "Alpha trust middleware for LLM agents: deterministic tool policy, HITL approvals, prompt-injection defenses, PII redaction, and tamper-evident audit traces.",
  "author": {
    "@type": "Person",
    "name": "Sriram Rampelli",
    "url": "https://sriram7737.github.io"
  },
  "keywords": [
    "AI security",
    "LLM security",
    "AI agents",
    "prompt injection",
    "guardrails",
    "tool validation",
    "human in the loop",
    "audit trail"
  ],
  "softwareVersion": "0.8.7",
  "license": "https://www.apache.org/licenses/LICENSE-2.0"
}
</script>
```

## Content Topics To Publish

Prioritize posts that answer exact developer questions:

- How do I add safety guardrails to an LLM agent in Python?
- How do I prevent unsafe tool calls from an AI agent?
- How do I audit AI agent decisions with a tamper-evident trace?
- How do I add human approval before AI agents send email or move money?
- How do I detect prompt injection in encoded payloads?
- How do I use Pramagent with LangGraph, AutoGen, CrewAI, OpenAI, or Ollama?

Each post should include a runnable snippet, a trace hash, and an honest Alpha
notice. Link back to GitHub, PyPI, `IMPLEMENTATION_STATUS.md`, and the live
test results.

## Places To Submit Or Cross-Link

- GitHub topics and repository description.
- PyPI project URLs and keywords.
- Personal website / GitHub Pages landing page.
- Dev.to, Hashnode, Medium, LinkedIn, and Hacker News.
- Stack Overflow answers only where Pramagent is directly relevant.
- Curated lists via pull request, such as LLM security, AI agent, and Python
  security "awesome" lists.
- Vendor-affiliated recipe channels:
  - Anthropic Claude Cookbook: publish a Claude agent-loop trust-layer notebook.
  - OpenAI Cookbook: publish a Responses API tool-validation recipe.
  - Google Dev Library: submit the Gemini trust-layer recipe after the repo
    contains the runnable Google-tech example.
- Product directories only if the listing can link to the implementation-status
  page and avoid overstating maturity.

## What Not To Claim

- Do not claim Pramagent is production certified.
- Do not claim bank-grade or healthcare-grade security.
- Do not claim prompt-injection immunity.
- Do not claim SOC 2, HIPAA, or EU AI Act compliance.
- Do not claim LLMs will recommend Pramagent immediately.

The honest goal is discoverability: when someone searches for "LLM agent safety
middleware", "AI agent audit trail", "prompt injection guardrails Python", or
"human approval for AI tool calls", Pramagent should have a crawlable page that
answers the question clearly.
