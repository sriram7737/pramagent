import json
import io
import urllib.error

import pytest

from pramagent.providers import (AnthropicProvider, GeminiProvider, NvidiaProvider,
                                 OllamaProvider,
                                 OpenAICompatibleProvider,
                                 OpenAIProvider)


class FakeHTTPResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


class FakeAioHTTPResponse:
    def __init__(self, payload, status=200):
        self.payload = payload
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        if isinstance(self.payload, str):
            return self.payload
        return json.dumps(self.payload)


class FakeAioHTTPSession:
    last_json = None
    response = FakeAioHTTPResponse({"response": "hello from ollama", "model": "qwen"})

    def __init__(self, timeout):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, json):
        self.__class__.last_json = json
        return self.__class__.response


class FakeAioHTTPModule:
    class ClientTimeout:
        def __init__(self, total):
            self.total = total

    ClientSession = FakeAioHTTPSession


@pytest.mark.asyncio
async def test_openai_compatible_provider_parses_chat_completion(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"] = req.full_url
        seen["body"] = json.loads(req.data.decode("utf-8"))
        return FakeHTTPResponse({
            "model": "local-llama",
            "choices": [{"message": {"content": "hello from local"}}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 4},
        })

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    provider = OpenAICompatibleProvider(
        model="local-llama",
        base_url="http://localhost:8001/v1",
        api_key=None,
    )

    result = await provider.complete("hi")

    assert seen["url"] == "http://localhost:8001/v1/chat/completions"
    assert seen["body"]["messages"][0]["content"] == "hi"
    assert result.text == "hello from local"
    assert result.model == "local-llama"
    assert result.prompt_tokens == 3
    assert result.completion_tokens == 4
    assert result.cost_usd == 0.0


@pytest.mark.asyncio
async def test_openai_provider_records_usage_cost(monkeypatch):
    def fake_urlopen(req, timeout):
        return FakeHTTPResponse({
            "model": "gpt-4o-mini-2024-07-18",
            "choices": [{"message": {"content": "priced response"}}],
            "usage": {"prompt_tokens": 1_000, "completion_tokens": 500},
        })

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    provider = OpenAIProvider(model="gpt-4o-mini", api_key="sk-test")

    result = await provider.complete("hi")

    assert result.text == "priced response"
    assert result.prompt_tokens == 1_000
    assert result.completion_tokens == 500
    assert result.cost_usd == pytest.approx(0.00045)


@pytest.mark.asyncio
async def test_openai_provider_records_gpt55_usage_cost(monkeypatch):
    def fake_urlopen(req, timeout):
        return FakeHTTPResponse({
            "model": "gpt-5.5-2026-04-24",
            "choices": [{"message": {"content": "priced response"}}],
            "usage": {"prompt_tokens": 1_000, "completion_tokens": 500},
        })

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    provider = OpenAIProvider(model="gpt-5.5", api_key="sk-test")

    result = await provider.complete("hi")

    assert result.prompt_tokens == 1_000
    assert result.completion_tokens == 500
    assert result.cost_usd == pytest.approx(0.02)


@pytest.mark.asyncio
async def test_openai_provider_retries_with_max_completion_tokens(monkeypatch):
    calls = []

    def fake_urlopen(req, timeout):
        body = json.loads(req.data.decode("utf-8"))
        calls.append(body)
        if len(calls) == 1:
            payload = json.dumps({
                "error": {
                    "message": (
                        "Unsupported parameter: 'max_tokens' is not supported "
                        "with this model. Use 'max_completion_tokens' instead."
                    )
                }
            }).encode("utf-8")
            raise urllib.error.HTTPError(
                req.full_url,
                400,
                "Bad Request",
                {},
                io.BytesIO(payload),
            )
        return FakeHTTPResponse({
            "model": "gpt-new",
            "choices": [{"message": {"content": "hello from new model"}}],
        })

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    provider = OpenAIProvider(model="gpt-new", api_key="sk-test", max_tokens=12)

    result = await provider.complete("hi")

    assert result.text == "hello from new model"
    assert calls[0]["max_tokens"] == 12
    assert "max_completion_tokens" not in calls[0]
    assert calls[1]["max_completion_tokens"] == 12
    assert "max_tokens" not in calls[1]


def test_openai_provider_uses_openai_defaults(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    provider = OpenAIProvider(model="gpt-test")

    assert provider.name == "openai"
    assert provider.base_url == "https://api.openai.com/v1"
    assert provider.model == "gpt-test"
    assert provider.api_key == "sk-test"


@pytest.mark.asyncio
async def test_anthropic_provider_missing_extra_has_actionable_error(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "anthropic":
            raise ImportError("missing optional dependency")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    provider = AnthropicProvider(model="claude-test")

    with pytest.raises(RuntimeError, match=r"pip install .*pramagent\[anthropic\]"):
        await provider.complete("hello")


@pytest.mark.asyncio
async def test_ollama_provider_sends_bounded_generation_options(monkeypatch):
    import sys

    FakeAioHTTPSession.response = FakeAioHTTPResponse({
        "response": "short local answer",
        "model": "qwen2.5:1.5b",
    })
    FakeAioHTTPSession.last_json = None
    monkeypatch.setitem(sys.modules, "aiohttp", FakeAioHTTPModule)
    provider = OllamaProvider(
        model="qwen2.5:1.5b",
        max_tokens=7,
        temperature=0.2,
        timeout_s=3,
    )

    result = await provider.complete("say hi")

    assert result.text == "short local answer"
    assert result.model == "qwen2.5:1.5b"
    assert FakeAioHTTPSession.last_json["stream"] is False
    assert FakeAioHTTPSession.last_json["options"]["num_predict"] == 7
    assert FakeAioHTTPSession.last_json["options"]["temperature"] == 0.2


@pytest.mark.asyncio
async def test_ollama_provider_reports_error_payload(monkeypatch):
    import sys

    FakeAioHTTPSession.response = FakeAioHTTPResponse({
        "error": "model not found"
    })
    monkeypatch.setitem(sys.modules, "aiohttp", FakeAioHTTPModule)
    provider = OllamaProvider(model="missing-model", timeout_s=3)

    with pytest.raises(RuntimeError, match="ollama error: model not found"):
        await provider.complete("say hi")


@pytest.mark.asyncio
async def test_nvidia_provider_uses_nim_openai_compatible_endpoint(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"] = req.full_url
        seen["headers"] = dict(req.header_items())
        seen["body"] = json.loads(req.data.decode("utf-8"))
        return FakeHTTPResponse({
            "model": "meta/llama-3.3-70b-instruct",
            "choices": [{"message": {"content": "hello from nim"}}],
            "usage": {"prompt_tokens": 9, "completion_tokens": 3},
        })

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    provider = NvidiaProvider(
        model="meta/llama-3.3-70b-instruct",
        api_key="nvapi-test",
    )

    result = await provider.complete("hi nvidia")

    assert provider.name == "nvidia"
    assert provider.base_url == "https://integrate.api.nvidia.com/v1"
    assert seen["url"] == "https://integrate.api.nvidia.com/v1/chat/completions"
    headers = {key.lower(): value for key, value in seen["headers"].items()}
    assert headers["authorization"] == "Bearer nvapi-test"
    assert seen["body"]["model"] == "meta/llama-3.3-70b-instruct"
    assert seen["body"]["messages"][0]["content"] == "hi nvidia"
    assert result.text == "hello from nim"
    assert result.model == "meta/llama-3.3-70b-instruct"


@pytest.mark.asyncio
async def test_gemini_provider_parses_generate_content(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"] = req.full_url
        seen["headers"] = dict(req.header_items())
        seen["body"] = json.loads(req.data.decode("utf-8"))
        return FakeHTTPResponse({
            "candidates": [{
                "content": {"parts": [{"text": "hello from gemini"}]}
            }]
        })

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    provider = GeminiProvider(
        model="gemini-test",
        api_key="gemini-key",
        base_url="https://gemini.example/v1beta",
    )

    result = await provider.complete("hi gemini")

    # the key travels as a header, never in the URL (T2-7/P2-6)
    assert seen["url"] == "https://gemini.example/v1beta/models/gemini-test:generateContent"
    assert "key=" not in seen["url"]
    header_keys = {k.lower(): v for k, v in seen["headers"].items()}
    assert header_keys["x-goog-api-key"] == "gemini-key"
    assert seen["body"]["contents"][0]["parts"][0]["text"] == "hi gemini"
    assert result.text == "hello from gemini"
    assert result.model == "gemini-test"
