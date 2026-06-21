"""
pramagent.providers
===================
The ProviderAdapter is the universal LLM interface. Every concrete provider
implements the same `complete()` contract, so the trust layers never know or
care which model is underneath. This is what makes Pramagent plug-and-play.

Add a new provider by subclassing BaseProvider and implementing `complete()`.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Optional
import urllib.error
import urllib.request

from ..security import validate_http_url, validate_urllib_request


@dataclass
class ProviderResult:
    text: str
    model: str
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    # True when a FallbackProvider satisfied the call with a non-primary
    # provider. A structured field — never inferred from the model name.
    used_fallback: bool = False


class BaseProvider:
    """Abstract provider. Subclass and implement `complete`."""
    name: str = "base"

    async def complete(self, prompt: str, **kwargs) -> ProviderResult:
        raise NotImplementedError


class MockProvider(BaseProvider):
    """
    Deterministic provider for tests, demos, and offline development.
    Given the same prompt it returns the same output -> makes the whole
    pipeline reproducible, which is exactly what RCA decision-replay needs.
    """
    name = "mock"

    def __init__(self, model: str = "mock-1", scripted: dict[str, str] | None = None):
        self.model = model
        self.scripted = scripted or {}

    async def complete(self, prompt: str, **kwargs) -> ProviderResult:
        t0 = time.perf_counter()
        await asyncio.sleep(0.01)  # simulate network
        if prompt in self.scripted:
            text = self.scripted[prompt]
        else:
            text = f"[mock-{self.model}] Acknowledged: {prompt[:120]}"
        return ProviderResult(
            text=text,
            model=self.model,
            cost_usd=0.0,
            latency_ms=(time.perf_counter() - t0) * 1000,
        )


class AnthropicProvider(BaseProvider):
    """
    Production adapter for the Anthropic API.
    Requires `pip install anthropic` and ANTHROPIC_API_KEY in the environment.
    Left importable but not invoked in the offline demo.
    """
    name = "anthropic"

    def __init__(self, model: str = "claude-sonnet-4-20250514", max_tokens: int = 1024):
        self.model = model
        self.max_tokens = max_tokens

    async def complete(self, prompt: str, **kwargs) -> ProviderResult:
        from anthropic import AsyncAnthropic  # lazy import
        client = AsyncAnthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        t0 = time.perf_counter()
        msg = await client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
        # cost is illustrative; real pricing depends on token counts
        cost = (msg.usage.input_tokens * 3e-6) + (msg.usage.output_tokens * 15e-6)
        return ProviderResult(text=text, model=self.model, cost_usd=cost,
                              latency_ms=(time.perf_counter() - t0) * 1000)


class OpenAICompatibleProvider(BaseProvider):
    """
    Provider for OpenAI-compatible chat-completions APIs.

    Works with OpenAI itself, vLLM, LM Studio, llama.cpp server, Together,
    Groq-style compatible gateways, and many locally deployed inference stacks
    that expose `/v1/chat/completions`.
    """
    name = "openai-compatible"

    def __init__(
        self,
        *,
        model: str,
        base_url: str = "https://api.openai.com/v1",
        api_key: Optional[str] = None,
        timeout_s: float = 60.0,
        max_tokens: int = 1024,
        temperature: float = 0.0,
        headers: Optional[dict[str, str]] = None,
    ):
        self.model = model
        self.base_url = validate_http_url(
            base_url.rstrip("/"),
            allow_http_localhost=True,
            context="OpenAI-compatible base URL",
        )
        self.api_key = api_key
        self.timeout_s = timeout_s
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.headers = headers or {}

    async def complete(self, prompt: str, **kwargs) -> ProviderResult:
        return await asyncio.to_thread(self._complete_sync, prompt, **kwargs)

    def _complete_sync(self, prompt: str, **kwargs) -> ProviderResult:
        t0 = time.perf_counter()
        body = {
            "model": kwargs.get("model", self.model),
            "messages": kwargs.get("messages") or [{"role": "user", "content": prompt}],
            "max_tokens": int(kwargs.get("max_tokens", self.max_tokens)),
            "temperature": float(kwargs.get("temperature", self.temperature)),
        }
        payload = self._request_with_openai_compat_fallback(body)
        text = _extract_openai_text(payload)
        usage = payload.get("usage") or {}
        prompt_tokens = int(usage.get("prompt_tokens") or 0)
        completion_tokens = int(usage.get("completion_tokens") or 0)
        model = str(payload.get("model") or body["model"])
        return ProviderResult(
            text=text,
            model=model,
            cost_usd=_estimate_chat_completion_cost_usd(
                model,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
            ),
            latency_ms=(time.perf_counter() - t0) * 1000,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

    def _request_with_openai_compat_fallback(self, body: dict[str, Any]) -> dict[str, Any]:
        # Some newer OpenAI models reject the legacy chat-completions
        # `max_tokens` parameter and require `max_completion_tokens` instead.
        # Local OpenAI-compatible servers often still expect `max_tokens`, so
        # try the broad-compatible shape first and only mutate on explicit 400s.
        request_body = dict(body)
        last_error: Optional[RuntimeError] = None
        for _ in range(3):
            try:
                return self._post_chat_completion(request_body)
            except RuntimeError as exc:
                message = str(exc)
                last_error = exc
                if (
                    "max_tokens" in message
                    and "max_completion_tokens" in message
                    and "max_tokens" in request_body
                ):
                    request_body["max_completion_tokens"] = request_body.pop("max_tokens")
                    continue
                if (
                    "temperature" in message.lower()
                    and "unsupported" in message.lower()
                    and "temperature" in request_body
                ):
                    request_body.pop("temperature", None)
                    continue
                raise
        raise last_error or RuntimeError("provider request failed")

    def _post_chat_completion(self, body: dict[str, Any]) -> dict[str, Any]:
        data = json.dumps(body).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            **self.headers,
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=data,
            headers=headers,
            method="POST",
        )
        return _json_request(req, timeout=self.timeout_s)


class OpenAIProvider(OpenAICompatibleProvider):
    """OpenAI-hosted adapter using the OpenAI-compatible endpoint."""
    name = "openai"

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        *,
        api_key: Optional[str] = None,
        base_url: str = "https://api.openai.com/v1",
        max_tokens: int = 1024,
        temperature: float = 0.0,
        timeout_s: float = 60.0,
    ):
        super().__init__(
            model=model,
            base_url=base_url,
            api_key=api_key or os.environ.get("OPENAI_API_KEY"),
            max_tokens=max_tokens,
            temperature=temperature,
            timeout_s=timeout_s,
        )


class NvidiaProvider(OpenAICompatibleProvider):
    """NVIDIA NIM adapter using its OpenAI-compatible chat API.

    Users can get an ``nvapi-...`` key from https://build.nvidia.com. The key is
    supplied per request in the public demo flow and is never read from logs or
    persisted traces by this provider.
    """
    name = "nvidia"
    BASE_URL = "https://integrate.api.nvidia.com/v1"

    def __init__(
        self,
        model: str = "meta/llama-3.3-70b-instruct",
        *,
        api_key: str = "",
        max_tokens: int = 1024,
        temperature: float = 0.0,
        timeout_s: float = 60.0,
    ):
        super().__init__(
            model=model,
            base_url=self.BASE_URL,
            api_key=api_key,
            max_tokens=max_tokens,
            temperature=temperature,
            timeout_s=timeout_s,
        )


class GeminiProvider(BaseProvider):
    """Google Gemini adapter using the public generateContent REST endpoint."""
    name = "gemini"

    def __init__(
        self,
        model: str = "gemini-1.5-flash",
        *,
        api_key: Optional[str] = None,
        base_url: str = "https://generativelanguage.googleapis.com/v1beta",
        max_tokens: int = 1024,
        temperature: float = 0.0,
        timeout_s: float = 60.0,
    ):
        self.model = model
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.base_url = validate_http_url(
            base_url.rstrip("/"),
            allow_http_localhost=True,
            context="Gemini base URL",
        )
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout_s = timeout_s

    async def complete(self, prompt: str, **kwargs) -> ProviderResult:
        return await asyncio.to_thread(self._complete_sync, prompt, **kwargs)

    def _complete_sync(self, prompt: str, **kwargs) -> ProviderResult:
        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY is required for GeminiProvider")
        t0 = time.perf_counter()
        model = kwargs.get("model", self.model)
        body = {
            "contents": kwargs.get("contents") or [
                {"role": "user", "parts": [{"text": prompt}]}
            ],
            "generationConfig": {
                "maxOutputTokens": int(kwargs.get("max_tokens", self.max_tokens)),
                "temperature": float(kwargs.get("temperature", self.temperature)),
            },
        }
        data = json.dumps(body).encode("utf-8")
        # API key travels as a header, never in the URL — query strings end up
        # in proxy logs, error reprs, and tracing systems (T2-7/P2-6).
        req = urllib.request.Request(
            f"{self.base_url}/models/{model}:generateContent",
            data=data,
            headers={"Content-Type": "application/json",
                     "x-goog-api-key": self.api_key},
            method="POST",
        )
        payload = _json_request(req, timeout=self.timeout_s)
        return ProviderResult(
            text=_extract_gemini_text(payload),
            model=str(model),
            cost_usd=0.0,
            latency_ms=(time.perf_counter() - t0) * 1000,
        )


class OllamaProvider(BaseProvider):
    """
    Production adapter for a local Ollama server (offline / edge / air-gapped).
    Requires a running Ollama daemon. Demonstrates that the same trust stack
    works with a 1B local model exactly as it does with a frontier API.
    """
    name = "ollama"

    def __init__(self, model: str = "llama3.2:1b", host: str = "http://localhost:11434"):
        self.model = model
        # Validated like every other provider URL; private/loopback targets
        # are expected for a local daemon, so allow them explicitly (P3-7).
        self.host = validate_http_url(
            host.rstrip("/"),
            allow_http_localhost=True,
            allow_private=True,
            context="Ollama host URL",
        )

    async def complete(self, prompt: str, **kwargs) -> ProviderResult:
        import aiohttp  # lazy import
        t0 = time.perf_counter()
        # bounded like every other provider call — a hung local daemon must
        # not hold the request forever (P3-7)
        timeout = aiohttp.ClientTimeout(total=60)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.post(f"{self.host}/api/generate",
                              json={"model": self.model, "prompt": prompt, "stream": False}) as r:
                data = await r.json()
        return ProviderResult(text=data.get("response", ""), model=self.model, cost_usd=0.0,
                              latency_ms=(time.perf_counter() - t0) * 1000)


def _json_request(req: urllib.request.Request, *, timeout: float) -> dict[str, Any]:
    validate_urllib_request(
        req,
        allow_http_localhost=True,
        context="provider request URL",
    )
    max_retries = 5
    backoff = 1.0
    for attempt in range(max_retries):
        try:
            # Provider URL is validated before the request is sent.
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                raw = resp.read().decode("utf-8")
            break
        except urllib.error.HTTPError as exc:
            # Retry on rate limit (429) or transient server errors (500, 502, 503, 504)
            if exc.code in (429, 500, 502, 503, 504) and attempt < max_retries - 1:
                # Read Retry-After if present, otherwise use exponential backoff
                retry_after = exc.headers.get("Retry-After")
                sleep_time = backoff
                if retry_after and retry_after.isdigit():
                    sleep_time = max(sleep_time, float(retry_after))
                time.sleep(sleep_time)
                backoff *= 2.0
                continue
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"provider HTTP {exc.code}: {detail[:400]}") from exc
        except urllib.error.URLError as exc:
            if attempt < max_retries - 1:
                time.sleep(backoff)
                backoff *= 2.0
                continue
            raise RuntimeError(f"provider request failed: {exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"provider returned non-JSON response: {raw[:200]}") from exc


def _extract_openai_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices") or []
    if not choices:
        return ""
    message = choices[0].get("message") or {}
    content = message.get("content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                parts.append(str(item.get("text", "")))
        return "".join(parts)
    return str(content)


def _estimate_chat_completion_cost_usd(
    model: str,
    *,
    prompt_tokens: int,
    completion_tokens: int,
) -> float:
    """Best-effort chat-completion cost estimate from API usage tokens.

    Prices can change and OpenAI-compatible local gateways may not bill at all.
    Set PRAMAGENT_OPENAI_INPUT_PRICE_PER_MTOK and
    PRAMAGENT_OPENAI_OUTPUT_PRICE_PER_MTOK to override the built-in public
    model defaults.
    """
    if prompt_tokens <= 0 and completion_tokens <= 0:
        return 0.0

    override_in = os.environ.get("PRAMAGENT_OPENAI_INPUT_PRICE_PER_MTOK")
    override_out = os.environ.get("PRAMAGENT_OPENAI_OUTPUT_PRICE_PER_MTOK")
    if override_in is not None and override_out is not None:
        return (
            (prompt_tokens / 1_000_000) * float(override_in)
            + (completion_tokens / 1_000_000) * float(override_out)
        )

    name = model.lower()
    # USD per 1M tokens. Best-effort defaults for common OpenAI hosted models;
    # unknown/local OpenAI-compatible models intentionally report zero.
    price_table = [
        ("gpt-5.5-pro", 30.00, 180.00),
        ("gpt-5.5", 5.00, 30.00),
        ("gpt-4o-mini", 0.15, 0.60),
        ("gpt-4.1-mini", 0.40, 1.60),
        ("gpt-4.1-nano", 0.10, 0.40),
        ("gpt-4.1", 2.00, 8.00),
        ("gpt-4o", 2.50, 10.00),
    ]
    for prefix, input_per_mtok, output_per_mtok in price_table:
        if name.startswith(prefix):
            return (
                (prompt_tokens / 1_000_000) * input_per_mtok
                + (completion_tokens / 1_000_000) * output_per_mtok
            )
    return 0.0


def _extract_gemini_text(payload: dict[str, Any]) -> str:
    candidates = payload.get("candidates") or []
    if not candidates:
        return ""
    content = candidates[0].get("content") or {}
    parts = content.get("parts") or []
    return "".join(str(part.get("text", "")) for part in parts if isinstance(part, dict))


class FallbackProvider(BaseProvider):
    """
    Wraps an ordered list of providers. Tries each in turn until one succeeds.
    This is the ProviderAdapter's fallback chain -- continuity during outages.
    """
    name = "fallback"

    def __init__(self, providers: list[BaseProvider]):
        if not providers:
            raise ValueError("FallbackProvider needs at least one provider")
        self.providers = providers

    async def complete(self, prompt: str, **kwargs) -> ProviderResult:
        last_err: Exception | None = None
        for i, p in enumerate(self.providers):
            try:
                res = await p.complete(prompt, **kwargs)
                if i > 0:
                    res.model = f"{res.model} (fallback#{i})"
                    res.used_fallback = True
                return res
            except Exception as e:  # noqa: BLE001  (we genuinely want to try the next)
                last_err = e
                continue
        raise RuntimeError(f"all providers failed; last error: {last_err}")
