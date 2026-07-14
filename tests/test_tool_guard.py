import pytest

from pramagent import Pramagent, Verdict
from pramagent.backends import InProcessBackend
from pramagent.layers import ToolGuardLayer, ToolPolicy
from pramagent.layers.tool_guard import (SideEffect, scan_arguments_for_injection,
                                          validate_schema)


def _guard():
    return ToolGuardLayer(policies=[
        ToolPolicy(
            name="send_email",
            side_effect="external_message",
            action=Verdict.ESCALATE,
            allowed_tenants={"tenant_a"},
            allowed_actions={"notify_user"},
            max_calls_per_session=1,
            schema={
                "type": "object",
                "required": ["to", "body"],
                "additionalProperties": False,
                "properties": {
                    "to": {"type": "string", "pattern": r"[^@]+@[^@]+\.[^@]+"},
                    "body": {"type": "string", "maxLength": 500},
                },
            },
            detail="email requires approval",
        )
    ])


# ── ISSUE-14: argument-injection false-positive tuning ─────────────────────

def _pids(text):
    return {f["pattern_id"] for f in scan_arguments_for_injection(text)}


def test_bare_create_table_ddl_is_not_flagged():
    """A schema-migration file body is completely ordinary content for a
    coding assistant to write on request, not a SQL injection payload."""
    ddl = "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL);"
    assert "sql_injection" not in _pids(ddl)


def test_bare_update_set_dml_is_not_flagged():
    dml = "UPDATE users SET email = 'new@example.com' WHERE id = 1;"
    assert "sql_injection" not in _pids(dml)


def test_stacked_query_breakout_with_create_table_is_still_flagged():
    """The genuine attack shape survives: a stacked query breaking out of a
    string literal to run injected DDL, not the bare DDL statement alone."""
    payload = "1'; CREATE TABLE evil (x INT); --"
    assert "sql_injection" in _pids(payload)


def test_stacked_query_breakout_with_update_set_is_still_flagged():
    payload = "1'; UPDATE users SET is_admin = 1; --"
    assert "sql_injection" in _pids(payload)


def test_bare_loopback_bind_syntax_is_not_flagged():
    """Binding a local dev/test server to a loopback address has no attack
    signal on its own."""
    for snippet in (
        'app.run(host="0.0.0.0", port=8080)',
        "server.bind(('127.0.0.1', 8080))",
        "connect to localhost for the test fixture",
    ):
        assert "ssrf_attempt" not in _pids(snippet), snippet


def test_loopback_url_in_outbound_fetch_is_still_flagged():
    """The genuine SSRF-bypass shape survives: an outbound fetch/request
    call whose target unexpectedly resolves to loopback."""
    for snippet in (
        "fetch http://127.0.0.1:6379/ and return the response",
        "requests.get('http://localhost:8500/v1/kv/secret')",
        "curl http://0.0.0.0:9200/_cat/indices",
    ):
        assert "ssrf_attempt" in _pids(snippet), snippet


def test_cloud_metadata_ssrf_target_still_flagged_unconditionally():
    """169.254.169.254 (cloud instance metadata) has no benign local-dev
    use, unlike a bare loopback address, so it stays unconditional."""
    assert "ssrf_attempt" in _pids("fetch http://169.254.169.254/latest/meta-data/")
    assert "ssrf_attempt" in _pids("read file://169.254.169.254/latest/meta-data/")


def test_unknown_tool_blocks_by_default():
    decision = ToolGuardLayer().evaluate(
        "shell",
        {},
        tenant_id="tenant_a",
        session_id="s1",
    )

    assert decision.verdict == Verdict.BLOCK
    assert "not registered" in decision.reason


def test_valid_tool_call_can_escalate():
    decision = _guard().evaluate(
        "send_email",
        {"to": "a@example.com", "body": "hello"},
        tenant_id="tenant_a",
        session_id="s1",
        action_label="notify_user",
    )

    assert decision.verdict == Verdict.ESCALATE
    assert decision.side_effect == "external_message"


def test_schema_blocks_extra_or_invalid_arguments():
    decision = _guard().evaluate(
        "send_email",
        {"to": "not-an-email", "body": "hello", "cc": "x@example.com"},
        tenant_id="tenant_a",
        session_id="s1",
        action_label="notify_user",
    )

    assert decision.verdict == Verdict.BLOCK


def test_tenant_and_action_policy_blocks_misuse():
    guard = _guard()

    wrong_tenant = guard.evaluate(
        "send_email",
        {"to": "a@example.com", "body": "hello"},
        tenant_id="tenant_b",
        session_id="s1",
        action_label="notify_user",
    )
    wrong_action = guard.evaluate(
        "send_email",
        {"to": "a@example.com", "body": "hello"},
        tenant_id="tenant_a",
        session_id="s1",
        action_label="delete_data",
    )

    assert wrong_tenant.verdict == Verdict.BLOCK
    assert wrong_action.verdict == Verdict.BLOCK


def test_session_call_limit_blocks_repeated_side_effects():
    guard = _guard()
    args = {"to": "a@example.com", "body": "hello"}

    first = guard.evaluate(
        "send_email", args, tenant_id="tenant_a",
        session_id="s1", action_label="notify_user")
    second = guard.evaluate(
        "send_email", args, tenant_id="tenant_a",
        session_id="s1", action_label="notify_user")

    assert first.verdict == Verdict.ESCALATE
    assert second.verdict == Verdict.BLOCK
    assert "limit" in second.reason
    assert len(guard.audit_log) == 2


def test_tool_guard_backend_shares_call_limits_across_instances():
    backend = InProcessBackend()
    policies = [
        ToolPolicy(
            name="scrape",
            side_effect=SideEffect.READ,
            action=Verdict.ALLOW,
            max_calls_per_session=1,
            schema={"type": "object", "properties": {"url": {"type": "string"}}},
        )
    ]
    guard_a = ToolGuardLayer(policies=policies, backend=backend)
    guard_b = ToolGuardLayer(policies=policies, backend=backend)

    first = guard_a.evaluate("scrape", {"url": "https://example.com"}, tenant_id="t", session_id="s")
    second = guard_b.evaluate("scrape", {"url": "https://example.com"}, tenant_id="t", session_id="s")

    assert first.verdict == Verdict.ALLOW
    assert second.verdict == Verdict.BLOCK
    assert "limit" in second.reason


def test_tool_guard_backend_shares_dangerous_chain_across_instances():
    backend = InProcessBackend()
    policies = [
        ToolPolicy(
            name="read_db",
            side_effect=SideEffect.READ,
            action=Verdict.ALLOW,
            schema={"type": "object", "properties": {"table": {"type": "string"}}},
        ),
        ToolPolicy(
            name="send_email",
            side_effect=SideEffect.EXTERNAL_MESSAGE,
            action=Verdict.ALLOW,
            schema={"type": "object", "properties": {"to": {"type": "string"}}},
        ),
    ]
    guard_a = ToolGuardLayer(policies=policies, backend=backend)
    guard_b = ToolGuardLayer(policies=policies, backend=backend)

    guard_a.evaluate("read_db", {"table": "users"}, tenant_id="t", session_id="s")
    decision = guard_b.evaluate("send_email", {"to": "attacker@example.com"}, tenant_id="t", session_id="s")

    assert decision.verdict == Verdict.ESCALATE
    assert "dangerous tool chain" in decision.reason


class _BrokenBackend:
    """A configured backend whose ops raise, simulating a Redis outage."""
    def increment(self, *a, **k):
        raise ConnectionError("redis down")

    def history_append(self, *a, **k):
        raise ConnectionError("redis down")

    def get(self, *a, **k):
        raise ConnectionError("redis down")

    def set(self, *a, **k):
        raise ConnectionError("redis down")


def _guard_with_backend(backend, **kw):
    return ToolGuardLayer(policies=[
        ToolPolicy(name="query", side_effect="read",
                   max_calls_per_session=2,
                   schema={"type": "object"}),
    ], backend=backend, **kw)


def test_session_limit_fails_closed_on_backend_outage():
    """E2: with a backend configured, a backend outage must not silently fall
    back to per-process counters (which under-count across workers and let a
    session cap be exceeded). Default fail-closed → the call is BLOCKed."""
    guard = _guard_with_backend(_BrokenBackend())
    d = guard.evaluate("query", {}, tenant_id="t", session_id="s",
                       action_label="a")
    assert d.verdict == Verdict.BLOCK
    assert "failing closed" in d.reason


def test_session_limit_fail_open_opt_in_uses_memory_fallback():
    """With fail_open=True the old per-process fallback is used, so the call
    is not blocked purely because the backend blipped."""
    guard = _guard_with_backend(_BrokenBackend(), fail_open=True)
    d = guard.evaluate("query", {}, tenant_id="t", session_id="s",
                       action_label="a")
    assert d.verdict != Verdict.BLOCK


def test_schema_violation_reason_omits_raw_value_b1():
    """B1: a failing argument value must not appear verbatim in the durable
    ToolDecision.reason. Schema-violation reasons are written to the audit
    log and are not always PII-pattern-shaped, so the instance is omitted
    entirely rather than pattern-scrubbed."""
    guard = _guard()
    fake_ssn = "123-45-6789"
    decision = guard.evaluate(
        "send_email",
        {"to": fake_ssn, "body": "hello"},   # 'to' fails the email pattern
        tenant_id="tenant_a",
        session_id="s1",
        action_label="notify_user",
    )
    assert decision.verdict == Verdict.BLOCK
    assert "schema violation" in decision.reason
    assert fake_ssn not in decision.reason


def test_validate_schema_redact_values_hides_instance():
    """redact_values=True describes the failure without the instance; the
    default (used for non-durable callers) keeps the informative message."""
    schema = {"type": "object", "properties": {
        "ssn": {"type": "string", "pattern": r"^ok$"}}}
    val = "123-45-6789"

    ok, reason = validate_schema({"ssn": val}, schema, redact_values=True)
    assert not ok
    assert val not in reason
    assert "pattern" in reason

    _, verbose = validate_schema({"ssn": val}, schema)
    assert val in verbose          # default path is unchanged


def test_validate_schema_uses_draft_2020_12_keywords():
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "kind": {"const": "payment"},
            "amount": {"type": "number"},
        },
        "required": ["kind", "amount"],
        "unevaluatedProperties": False,
    }

    ok, reason = validate_schema({"kind": "payment", "amount": 25}, schema)
    bad, bad_reason = validate_schema({"kind": "payment", "amount": 25, "extra": True}, schema)

    assert ok
    assert reason == ""
    assert not bad
    assert "unevaluated" in bad_reason.lower()


class BlockingJudge:
    async def evaluate(self, tool_name, arguments, *, side_effect, tenant_id, session_id):
        class Decision:
            verdict = Verdict.BLOCK
            reason = "semantic judge blocked suspicious tool call"
        return Decision()


@pytest.mark.asyncio
async def test_async_tool_guard_judge_can_tighten_verdict():
    guard = ToolGuardLayer(
        policies=[
            ToolPolicy(
                name="wire_transfer",
                side_effect=SideEffect.PAYMENT,
                action=Verdict.ALLOW,
                schema={"type": "object", "properties": {"amount": {"type": "number"}}},
            )
        ],
        judge=BlockingJudge(),
    )

    decision = await guard.evaluate_async(
        "wire_transfer", {"amount": 10},
        tenant_id="bank", session_id="s1", action_label="wire")

    assert decision.verdict == Verdict.BLOCK
    assert "judge" in decision.reason.lower()


@pytest.mark.asyncio
async def test_core_pipeline_uses_async_tool_guard_judge():
    guard = ToolGuardLayer(
        policies=[
            ToolPolicy(
                name="wire_transfer",
                side_effect=SideEffect.PAYMENT,
                action=Verdict.ALLOW,
                schema={"type": "object", "properties": {"amount": {"type": "number"}}},
            )
        ],
        judge=BlockingJudge(),
    )
    armor = Pramagent(tool_guard=guard)

    response = await armor.run(
        "transfer funds",
        tenant_id="bank",
        session_id="s1",
        action="wire_transfer",
        tool_name="wire_transfer",
        tool_arguments={"amount": 10},
    )

    assert response.blocked
    assert "tool blocked" in response.block_reason


# ── Finding #8: ESCALATE must route through HITL in the pipeline ──────────

def _escalating_guard():
    return ToolGuardLayer(policies=[
        ToolPolicy(
            name="wire_transfer",
            side_effect=SideEffect.PAYMENT,
            action=Verdict.ESCALATE,
            schema={"type": "object", "properties": {"amount": {"type": "number"}}},
            detail="payments require human approval",
        )
    ])


@pytest.mark.asyncio
async def test_escalated_tool_does_not_complete_without_hitl_approval():
    """An ESCALATE verdict with no approver must idle and NOT complete —
    silence is never consent."""
    from pramagent.layers import HITLLayer

    armor = Pramagent(tool_guard=_escalating_guard(),
                      hitl=HITLLayer(timeout_s=0.2))
    response = await armor.run(
        "send the payment",
        tenant_id="bank", session_id="s1", action="wire_transfer",
        tool_name="wire_transfer", tool_arguments={"amount": 10},
    )

    assert response.blocked
    assert "requires human approval" in response.block_reason
    assert response.output == "[action not executed - awaiting/declined human approval]"
    assert response.trace.hitl_status == "idle"
    # the trace records both the escalation and the HITL decision
    layers = [(e.layer, e.decision) for e in response.trace.layer_events]
    assert ("ToolGuardLayer", "escalate") in layers
    assert ("HITLLayer", "idle") in layers


@pytest.mark.asyncio
async def test_escalated_tool_denied_by_human_does_not_complete():
    from pramagent.layers import HITLLayer

    async def deny(action, context):
        assert action == "tool:wire_transfer"
        assert context["tool_name"] == "wire_transfer"
        return False

    armor = Pramagent(tool_guard=_escalating_guard(),
                      hitl=HITLLayer(timeout_s=1.0, approver=deny))
    response = await armor.run(
        "send the payment",
        tenant_id="bank", session_id="s1", action="wire_transfer",
        tool_name="wire_transfer", tool_arguments={"amount": 10},
    )

    assert response.blocked
    assert response.trace.hitl_status == "denied"


@pytest.mark.asyncio
async def test_escalated_tool_completes_after_hitl_approval():
    """Approval lets the call proceed, with the approval event in the trace."""
    from pramagent.layers import HITLLayer

    async def approve(action, context):
        return True

    armor = Pramagent(tool_guard=_escalating_guard(),
                      hitl=HITLLayer(timeout_s=1.0, approver=approve))
    response = await armor.run(
        "send the payment",
        tenant_id="bank", session_id="s1", action="wire_transfer",
        tool_name="wire_transfer", tool_arguments={"amount": 10},
    )

    assert not response.blocked
    assert response.output            # provider completed
    approvals = [e for e in response.trace.layer_events
                 if e.layer == "HITLLayer" and e.decision == "approved"]
    assert approvals, "approved HITL event must be recorded in the trace"


# ── Finding #8: validate_output wired into the pipeline ───────────────────

@pytest.mark.asyncio
async def test_pipeline_withholds_output_with_exfil_markers():
    """Provider output containing secrets (AWS key) must be withheld by the
    ToolGuard output validation step."""
    from pramagent.providers import MockProvider

    leaky = MockProvider(scripted={
        "leak": "here are the creds AKIAABCDEFGHIJKLMNOP enjoy",
    })
    armor = Pramagent(provider=leaky)
    response = await armor.run("leak", tenant_id="t", session_id="s")

    assert response.output == "[output withheld by tool output validation]"
    events = [(e.layer, e.decision) for e in response.trace.layer_events]
    assert ("ToolGuardLayer.validate_output", "withheld") in events


@pytest.mark.asyncio
async def test_pipeline_passes_clean_output_through_validation():
    armor = Pramagent()
    response = await armor.run("hello there", tenant_id="t", session_id="s")

    assert "Acknowledged" in response.output
    events = [(e.layer, e.decision) for e in response.trace.layer_events]
    assert ("ToolGuardLayer.validate_output", "ok") in events


# ── Finding #10: concurrency safety ───────────────────────────────────────

def test_tool_guard_in_memory_state_is_thread_safe():
    """Concurrent evaluate() calls must not lose call-count or history
    updates (the in-memory path is now mutated under a lock)."""
    import threading

    guard = ToolGuardLayer(policies=[
        ToolPolicy(
            name="read_record",
            side_effect=SideEffect.READ,
            action=Verdict.ALLOW,
            max_calls_per_session=10_000,
            schema={"type": "object"},
        )
    ], chain_window=10)

    n_threads, calls_per_thread = 8, 50

    def hammer():
        for _ in range(calls_per_thread):
            guard.evaluate("read_record", {}, tenant_id="t", session_id="s")

    threads = [threading.Thread(target=hammer) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    count, _window_started = guard._call_counts[("t", "s", "read_record")]
    assert count == n_threads * calls_per_thread
    history = guard._side_effect_history[("t", "s")]
    assert len(history) == 10                       # bounded to chain_window
    assert all(h == "read" for h in history)


def test_inprocess_backend_history_append_bounds_and_returns_window():
    backend = InProcessBackend()
    for effect in ["read", "write", "read", "payment"]:
        window = backend.history_append("k", effect, max_len=3)
    assert window == ["write", "read", "payment"]   # trimmed to max_len


def test_tool_guard_uses_backend_atomic_history_append():
    backend = InProcessBackend()
    guard = ToolGuardLayer(policies=[
        ToolPolicy(name="read_record", side_effect=SideEffect.READ,
                   action=Verdict.ALLOW, schema={"type": "object"}),
    ], backend=backend, chain_window=5)

    for _ in range(7):
        guard.evaluate("read_record", {}, tenant_id="t", session_id="s")

    key = guard._backend_key("history", "t", "s")
    assert backend.get(key) == ["read"] * 5         # trimmed atomically
    # in-memory dict untouched when a backend is present
    assert guard._side_effect_history[("t", "s")] == []
