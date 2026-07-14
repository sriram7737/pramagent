import pytest

from pramagent.usage import (
    InMemoryUsageLedger,
    InMemoryUsageSink,
    UsageLimits,
    UsageTracker,
)


def test_call_quota_blocks_after_limit():
    tracker = UsageTracker(UsageLimits(max_calls=2, window_s=60))

    assert tracker.reserve_call("acme").allowed
    assert tracker.reserve_call("acme").allowed
    blocked = tracker.reserve_call("acme")

    assert not blocked.allowed
    assert "call quota" in blocked.reason
    snap = tracker.snapshot("acme")
    assert snap.calls == 2
    assert snap.remaining_calls() == 0


def test_quota_window_resets():
    now = [100.0]
    tracker = UsageTracker(
        UsageLimits(max_calls=1, window_s=10),
        now_fn=lambda: now[0],
    )

    assert tracker.reserve_call("acme").allowed
    assert not tracker.reserve_call("acme").allowed

    now[0] = 111.0
    assert tracker.reserve_call("acme").allowed
    assert tracker.snapshot("acme").calls == 1


def test_tool_validation_quota_is_separate_from_call_quota():
    tracker = UsageTracker(UsageLimits(max_calls=10, max_tool_validations=1))

    assert tracker.reserve_call("acme").allowed
    assert tracker.reserve_tool_validation("acme").allowed
    blocked = tracker.reserve_tool_validation("acme")

    assert not blocked.allowed
    assert "tool-validation quota" in blocked.reason
    assert tracker.snapshot("acme").calls == 1


def test_cost_quota_blocks_future_work_after_spend_is_recorded():
    tracker = UsageTracker(UsageLimits(max_cost_usd=0.01))

    assert tracker.reserve_call("acme").allowed
    tracker.record_cost("acme", 0.012)
    blocked = tracker.reserve_call("acme")

    assert not blocked.allowed
    assert "cost quota" in blocked.reason
    assert tracker.snapshot("acme").cost_usd == 0.012


def test_disabled_tracker_allows_without_limits():
    tracker = UsageTracker()

    assert tracker.reserve_call("acme").allowed
    assert tracker.reserve_tool_validation("acme").allowed
    assert not tracker.enabled


def test_usage_sink_tracks_without_enforced_quotas():
    sink = InMemoryUsageSink()
    tracker = UsageTracker(event_sinks=[sink])

    assert tracker.reserve_call("acme").allowed
    assert tracker.reserve_tool_validation("acme").allowed
    tracker.record_cost("acme", 0.25)

    assert not tracker.enabled
    assert [e.event_type for e in sink.events] == [
        "call_reserved",
        "tool_validation_reserved",
        "cost_recorded",
    ]
    assert tracker.snapshot("acme").calls == 1
    assert tracker.snapshot("acme").tool_validations == 1
    assert tracker.snapshot("acme").cost_usd == 0.25


def test_usage_events_emit_for_calls_tools_cost_and_blocks():
    sink = InMemoryUsageSink()
    tracker = UsageTracker(
        UsageLimits(max_calls=1, max_tool_validations=1, max_cost_usd=0.01),
        event_sinks=[sink],
    )

    assert tracker.reserve_call("acme").allowed
    assert tracker.reserve_tool_validation("acme").allowed
    tracker.record_cost("acme", 0.005)
    assert not tracker.reserve_call("acme").allowed

    assert [e.event_type for e in sink.events] == [
        "call_reserved",
        "tool_validation_reserved",
        "cost_recorded",
        "quota_blocked",
    ]
    assert sink.events[0].to_dict()["tenant_id"] == "acme"
    assert sink.events[-1].metadata["reason"].startswith("tenant call quota")


def test_usage_sink_failure_does_not_break_quota_path():
    class BrokenSink:
        def emit(self, event):
            raise RuntimeError("billing down")

    tracker = UsageTracker(
        UsageLimits(max_calls=1),
        event_sinks=[BrokenSink()],
    )

    assert tracker.reserve_call("acme").allowed


def test_usage_sink_failure_can_fail_closed():
    class BrokenSink:
        def emit(self, event):
            raise RuntimeError("billing down")

    tracker = UsageTracker(
        UsageLimits(max_calls=1),
        event_sinks=[BrokenSink()],
        fail_open=False,
    )

    with pytest.raises(RuntimeError, match="billing down"):
        tracker.reserve_call("acme")


def test_usage_ledger_chains_and_filters_events():
    ledger = InMemoryUsageLedger()
    tracker = UsageTracker(
        event_sinks=[],
        ledger=ledger,
        now_fn=lambda: 123.0,
    )

    assert tracker.reserve_call("acme").allowed
    assert tracker.reserve_tool_validation("beta").allowed
    tracker.record_cost("acme", 0.25)

    assert ledger.verify_chain() is True
    report = tracker.ledger_report(tenant_id="acme")
    entries = report["entries"]

    assert report["ledger_type"] == "in_memory_hash_chain"
    assert report["chain_valid"] is True
    assert [row["sequence"] for row in entries] == [1, 3]
    assert [row["event"]["event_type"] for row in entries] == [
        "call_reserved",
        "cost_recorded",
    ]
    assert entries[0]["prev_hash"] == "0" * 64
    assert entries[0]["this_hash"] != entries[-1]["this_hash"]


def test_usage_from_env_adds_webhook_sink(monkeypatch):
    monkeypatch.setenv("PRAMAGENT_BILLING_WEBHOOK_URL", "https://billing.example/events")
    monkeypatch.setenv("PRAMAGENT_BILLING_WEBHOOK_SECRET", "secret")
    monkeypatch.setenv("PRAMAGENT_BILLING_WEBHOOK_TIMEOUT_S", "0.25")

    tracker = UsageTracker.from_env()

    assert len(tracker.event_sinks) == 1
    sink = tracker.event_sinks[0]
    assert sink.url == "https://billing.example/events"
    assert sink.secret == "secret"
    assert sink.timeout_s == 0.25


def test_usage_from_env_defaults_to_fail_open(monkeypatch):
    """PRAMAGENT_QUOTA_FAIL_OPEN defaults to fail-open — a quota-store
    outage doesn't 429 every tenant. This is the intentional opposite of
    RedisBackend's rate limiter (fail-closed by default): the rate limiter
    guards against unbounded external abuse, the quota tracker only risks
    a tenant's own spend budget during the outage (ISSUE-9)."""
    monkeypatch.delenv("PRAMAGENT_QUOTA_FAIL_OPEN", raising=False)
    assert UsageTracker.from_env().fail_open is True


def test_usage_from_env_quota_fail_open_can_be_disabled(monkeypatch):
    monkeypatch.setenv("PRAMAGENT_QUOTA_FAIL_OPEN", "0")
    assert UsageTracker.from_env().fail_open is False


def test_usage_from_env_can_enable_hash_chain_ledger(monkeypatch):
    monkeypatch.setenv("PRAMAGENT_USAGE_LEDGER", "memory")

    tracker = UsageTracker.from_env()
    assert isinstance(tracker.ledger, InMemoryUsageLedger)

    tracker.reserve_call("acme")
    report = tracker.ledger_report(tenant_id="acme")

    assert report["chain_valid"] is True
    assert report["entries"][0]["event"]["tenant_id"] == "acme"
