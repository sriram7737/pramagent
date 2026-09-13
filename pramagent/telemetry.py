"""
pramagent.telemetry
===================
OpenTelemetry integration for Pramagent.

Usage
-----
Call ``configure_otel(service_name=..., endpoint=...)`` once at startup, then
``trace_layer(layer_name)`` in any layer to get a context manager that creates
a child span for that layer.  W3C TraceContext (traceparent / tracestate) is
propagated automatically.

If the ``opentelemetry-sdk`` package is not installed the module degrades
silently — all helpers become no-ops so the system stays operational.

Example (instrument core.py)
-----------------------------
    from pramagent.telemetry import configure_otel, trace_layer, span_from_headers

    configure_otel(service_name="pramagent", endpoint="http://otel-collector:4317")

    # In Pramagent.run():
    with span_from_headers(incoming_headers) as root_span:
        with trace_layer("ComplianceLayer") as span:
            span.set_attribute("pii.redactions", len(redactions))
            ...
        with trace_layer("IsolationLayer") as span:
            span.set_attribute("input.bytes", iso_meta["input_bytes"])
            ...

Spans hierarchy
---------------
    request (root, traceparent injected by caller)
    ├── ComplianceLayer
    ├── IsolationLayer
    ├── SafetyLayer.pre
    ├── ToolGuardLayer
    ├── ReliabilityLayer  (wraps provider call)
    ├── SafetyLayer.post
    └── HITLLayer
"""
from __future__ import annotations

import contextlib
import logging
from contextlib import contextmanager
from typing import Any, Dict, Generator, Optional

log = logging.getLogger(__name__)

# optional OTel imports
try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.propagate import extract, inject
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False

# module state
_tracer: Optional[Any] = None   # opentelemetry.trace.Tracer or None
_configured = False


def configure_otel(
    *,
    service_name: str = "pramagent",
    endpoint: Optional[str] = None,
    tracer_provider: Optional[Any] = None,
) -> bool:
    """Configure OTel. Returns True if OTel is active, False if no-op.

    Parameters
    ----------
    service_name : str
        The ``service.name`` resource attribute.
    endpoint : str, optional
        OTLP gRPC endpoint, e.g. ``"http://otel-collector:4317"``.
        If omitted, spans are exported to stdout (good for dev).
    tracer_provider : TracerProvider, optional
        Inject a pre-built provider (useful in tests).
    """
    global _tracer, _configured
    if _configured:
        return _OTEL_AVAILABLE

    if not _OTEL_AVAILABLE:
        log.info("opentelemetry-sdk not installed — distributed tracing disabled")
        _configured = True
        return False

    if tracer_provider is not None:
        provider = tracer_provider
    else:
        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)

        if endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                    OTLPSpanExporter,
                )
                exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
                provider.add_span_processor(BatchSpanProcessor(exporter))
                log.info("OTel OTLP exporter → %s", endpoint)
            except ImportError:
                log.warning(
                    "opentelemetry-exporter-otlp not installed; falling back to console export"
                )
                _add_console_exporter(provider)
        else:
            _add_console_exporter(provider)

        trace.set_tracer_provider(provider)

    _tracer = trace.get_tracer(service_name, tracer_provider=provider)
    _configured = True
    log.info("OTel configured: service=%s", service_name)
    return True


def _add_console_exporter(provider: Any) -> None:
    try:
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    except Exception as exc:
        log.debug("Could not add console span exporter: %s", exc)


# public helpers
@contextmanager
def trace_layer(
    layer_name: str,
    *,
    attributes: Optional[Dict[str, Any]] = None,
) -> Generator[Any, None, None]:
    """Context manager that creates an OTel child span for ``layer_name``.

    If OTel is not configured this is a zero-overhead no-op.

    Usage::

        with trace_layer("IsolationLayer", attributes={"tenant": tenant_id}) as span:
            span.set_attribute("input.bytes", size)
            ...
    """
    if _tracer is None:
        yield _NoOpSpan()
        return

    with _tracer.start_as_current_span(
        f"pramagent.{layer_name}",
        kind=trace.SpanKind.INTERNAL if _OTEL_AVAILABLE else None,
    ) as span:
        if attributes:
            for k, v in attributes.items():
                span.set_attribute(k, v)
        try:
            yield span
        except Exception as exc:
            if _OTEL_AVAILABLE:
                span.record_exception(exc)
                span.set_status(trace.StatusCode.ERROR, str(exc))
            raise


@contextmanager
def span_from_headers(
    headers: Dict[str, str],
    span_name: str = "pramagent.request",
) -> Generator[Any, None, None]:
    """Create a root span, extracting W3C traceparent from ``headers``.

    Call this at the entry point of ``Pramagent.run()`` so the entire
    pipeline is subordinate to the caller's trace context.

    Usage::

        with span_from_headers(request.headers) as root:
            root.set_attribute("tenant.id", tenant_id)
            ...pipeline...
    """
    if _tracer is None:
        yield _NoOpSpan()
        return

    ctx = extract(headers)
    with _tracer.start_as_current_span(
        span_name,
        context=ctx,
        kind=trace.SpanKind.SERVER if _OTEL_AVAILABLE else None,
    ) as span:
        yield span


def inject_headers(headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Inject the current span context into a dict as W3C traceparent.

    Use this when making outbound calls (HTTP, gRPC) so downstream services
    can continue the trace.
    """
    out = headers or {}
    if _OTEL_AVAILABLE and _tracer is not None:
        inject(out)
    return out


def current_trace_id() -> Optional[str]:
    """Return the hex trace-id of the currently active span, or None."""
    if not _OTEL_AVAILABLE or _tracer is None:
        return None
    span = trace.get_current_span()
    ctx = span.get_span_context()
    if ctx and ctx.is_valid:
        return format(ctx.trace_id, "032x")
    return None


# no-op span (when OTel is absent)
class _NoOpSpan:
    """Returned by trace_layer when OTel is not configured. All calls are no-ops."""

    def set_attribute(self, *_, **__) -> None:
        pass

    def record_exception(self, *_, **__) -> None:
        pass

    def set_status(self, *_, **__) -> None:
        pass

    def add_event(self, *_, **__) -> None:
        pass
