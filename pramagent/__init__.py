r"""
Pramagent - trust middleware for AI agents: deterministic guardrails, HITL,
tool policy, and tamper-evident traces.

Quick start
-----------
    import asyncio
    from pramagent import Pramagent
    from pramagent.layers import SafetyLayer, Rule
    from pramagent.types import Verdict

    armor = Pramagent(
        safety=SafetyLayer(rules=[
            Rule("no_account_disclosure", Verdict.BLOCK, pattern=r"acct[-_ ]?\d{6,}"),
        ])
    )
    resp = asyncio.run(armor.run("Hello", tenant_id="acme", session_id="s1"))
    print(resp.output)
    print(resp.trace.this_hash)
"""
from .core import Pramagent
from .layers import (ComplianceLayer, HITLLayer, IsolationLayer,
                     ObservabilityLayer, ReliabilityLayer, Rule, SafetyLayer,
                     ToolDecision, ToolGuardLayer, ToolPolicy)
from .providers import (AnthropicProvider, BaseProvider, FallbackProvider,
                        GeminiProvider, MockProvider, OllamaProvider,
                        NvidiaProvider,
                        OpenAICompatibleProvider, OpenAIProvider)
from .store import MemoryStore, SQLiteStore
from .auth import APIKeyRegistry, JWTManager, PostgresAPIKeyRegistry
from .otel import OpenTelemetryExporter, OpenTelemetryNotInstalled
from .anchoring import EthereumAnchor, EthereumAnchorReceipt
from .redteam import RedTeamReport, run_injection_benchmark
from .types import (AgentResponse, EscalatePolicy, HITLStatus, TraceEvent,
                    Verdict)
from .usage import (
    InMemoryUsageLedger,
    InMemoryUsageSink,
    UsageLedgerEntry,
    UsageDecision,
    UsageEvent,
    UsageEventSink,
    UsageLimits,
    UsageSnapshot,
    UsageTracker,
    WebhookUsageSink,
)

__version__ = "0.8.2"
__all__ = [
    "Pramagent",
    "AgentResponse",
    "TraceEvent",
    "Verdict",
    "HITLStatus",
    "EscalatePolicy",
    "IsolationLayer",
    "ObservabilityLayer",
    "ComplianceLayer",
    "SafetyLayer",
    "ReliabilityLayer",
    "HITLLayer",
    "ToolGuardLayer",
    "ToolPolicy",
    "ToolDecision",
    "Rule",
    "MemoryStore",
    "SQLiteStore",
    "APIKeyRegistry",
    "PostgresAPIKeyRegistry",
    "JWTManager",
    "UsageTracker",
    "UsageLimits",
    "UsageSnapshot",
    "UsageDecision",
    "UsageEvent",
    "UsageEventSink",
    "UsageLedgerEntry",
    "InMemoryUsageLedger",
    "InMemoryUsageSink",
    "WebhookUsageSink",
    "run_injection_benchmark",
    "RedTeamReport",
    "OpenTelemetryExporter",
    "OpenTelemetryNotInstalled",
    "EthereumAnchor",
    "EthereumAnchorReceipt",
    "BaseProvider",
    "MockProvider",
    "AnthropicProvider",
    "OpenAIProvider",
    "OpenAICompatibleProvider",
    "NvidiaProvider",
    "GeminiProvider",
    "OllamaProvider",
    "FallbackProvider",
    "__version__",
]
from .classifier import (
    build_classifier, build_safety_classifier,
    get_shared_classifier, get_shared_safety_classifier, warm_shared_classifiers,
    EmbeddingInjectionClassifier, KeywordFallbackClassifier,
    INJECTION_EXEMPLARS, BENIGN_EXEMPLARS,
)

# Compliance evidence reporting (extended ComplianceReporter — generate(),
# control mapping, redaction counts, audit-chain attestation).
from .compliance import ComplianceReporter, ConsentRegistry, RetentionPolicy

# Persistent HITL queue stores (optional Postgres / SQLite backends).
# Located under pramagent.queue to avoid coupling to pramagent.hitl's optional
# Slack / workflow imports.
from .queue import (
    HITLQueueStore,
    InMemoryHITLQueue,
    QueuedRequest,
    RequestStatus,
    SQLiteHITLQueue,
    PostgresHITLQueue,
)

__all__ += [
    "build_classifier",
    "build_safety_classifier",
    "get_shared_classifier",
    "get_shared_safety_classifier",
    "warm_shared_classifiers",
    "EmbeddingInjectionClassifier",
    "KeywordFallbackClassifier",
    "INJECTION_EXEMPLARS",
    "BENIGN_EXEMPLARS",
    "ComplianceReporter",
    "ConsentRegistry",
    "RetentionPolicy",
    "HITLQueueStore",
    "InMemoryHITLQueue",
    "QueuedRequest",
    "RequestStatus",
    "SQLiteHITLQueue",
    "PostgresHITLQueue",
]
