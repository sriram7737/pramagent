from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from pramagent import (
    ActionEffect,
    ActionRequest,
    DecisionCode,
    ExecutionState,
    Pramagent,
    SQLiteActionController,
    TaskPermission,
)
from pramagent.layers import SideEffect, ToolGuardLayer, ToolPolicy
from pramagent.types import Verdict
from pramagent.adapters.generic import mediated_tool


TOKEN = "operator-token-long-enough"
NOW = 1_900_000_000_000_000


def permission(**changes):
    values = {
        "task_id": "task-1",
        "tenant_id": "tenant-a",
        "policy_version": 1,
        "expires_at_us": NOW + 1_000_000,
        "allowed_operations": ("account.read", "payment.send", "deploy.apply"),
        "allowed_tools": ("bank", "deployer"),
        "allowed_resources": ("account:a-main", "repo:site"),
        "allowed_destinations": ("account:a-vendor", "env:production"),
        "approval_required_operations": ("payment.send", "deploy.apply"),
        "max_spend_minor_units": 10_000,
        "max_actions": 4,
        "max_affected_records": 20,
    }
    values.update(changes)
    return TaskPermission(**values)


def action(execution_id="op-1", **changes):
    values = {
        "execution_id": execution_id,
        "task_id": "task-1",
        "tenant_id": "tenant-a",
        "policy_version": 1,
        "tool_name": "bank",
        "operation": "payment.send",
        "arguments": {"amount": 1000, "destination": "a-vendor"},
        "resources": ("account:a-main",),
        "destinations": ("account:a-vendor",),
        "spend_minor_units": 1000,
        "affected_records": 1,
        "effect": ActionEffect.PAYMENT,
        "created_at_us": NOW,
    }
    values.update(changes)
    return ActionRequest.create(**values)


@pytest.fixture
def controller(tmp_path):
    instance = SQLiteActionController(
        tmp_path / "actions.db", operator_token=TOKEN, clock_us=lambda: NOW
    )
    instance.put_permission(permission(), token=TOKEN)
    yield instance
    instance.close()


def test_task_permission_is_default_deny(tmp_path):
    controller = SQLiteActionController(
        tmp_path / "actions.db", operator_token=TOKEN, clock_us=lambda: NOW
    )
    controller.put_permission(TaskPermission(
        task_id="task-1", tenant_id="tenant-a", policy_version=1,
        expires_at_us=NOW + 1_000_000,
    ), token=TOKEN)
    decision = controller.submit(action())
    assert decision.reason_code == DecisionCode.OPERATION_NOT_ALLOWED
    assert decision.state == ExecutionState.DENIED
    controller.close()


def test_action_snapshot_is_immutable_and_digest_binds_arguments():
    arguments = {"amount": 1000, "nested": {"approved": False}}
    request = action(arguments=arguments)
    arguments["amount"] = 9999
    arguments["nested"]["approved"] = True
    assert request.arguments == {"amount": 1000, "nested": {"approved": False}}
    detached = request.arguments
    detached["amount"] = 5000
    assert request.arguments["amount"] == 1000
    assert request.digest != action(arguments={"amount": 1001}).digest


def test_exact_approval_executes_once(controller):
    calls = []
    controller.register_executor(
        "bank", lambda args, request: calls.append(args) or {"receipt": request.execution_id},
        token=TOKEN,
    )
    pending = controller.submit(action())
    assert pending.state == ExecutionState.AWAITING_APPROVAL
    assert not calls
    completed = controller.approve(
        "op-1", pending.action_digest, reviewer="human-1", token=TOKEN
    )
    assert completed.state == ExecutionState.COMPLETED
    assert completed.result == {"receipt": "op-1"}
    replay = controller.submit(action())
    assert replay.replayed is True
    assert len(calls) == 1


def test_changed_arguments_cannot_reuse_execution_id(controller):
    pending = controller.submit(action())
    changed = controller.submit(action(arguments={"amount": 9000}))
    assert pending.state == ExecutionState.AWAITING_APPROVAL
    assert changed.reason_code == DecisionCode.IDEMPOTENCY_CONFLICT
    mismatch = controller.approve("op-1", "0" * 64, reviewer="human", token=TOKEN)
    assert mismatch.reason_code == DecisionCode.APPROVAL_MISMATCH


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"tenant_id": "tenant-b"}, DecisionCode.RESOURCE_NOT_ALLOWED),
        ({"policy_version": 2}, DecisionCode.POLICY_VERSION_MISMATCH),
        ({"resources": ("account:b-main",)}, DecisionCode.RESOURCE_NOT_ALLOWED),
        ({"destinations": ("account:attacker",)}, DecisionCode.DESTINATION_NOT_ALLOWED),
        ({"tool_name": "shell"}, DecisionCode.TOOL_NOT_ALLOWED),
        ({"operation": "records.delete"}, DecisionCode.OPERATION_NOT_ALLOWED),
    ],
)
def test_scope_is_bound_to_exact_task(changes, code, controller):
    assert controller.submit(action(**changes)).reason_code == code


def test_pending_actions_cannot_overbook_cumulative_spend(tmp_path):
    controller = SQLiteActionController(
        tmp_path / "actions.db", operator_token=TOKEN, clock_us=lambda: NOW
    )
    controller.put_permission(permission(
        max_spend_minor_units=3000, max_actions=20,
    ), token=TOKEN)

    def propose(index):
        return controller.submit(action(f"op-{index}"))

    with ThreadPoolExecutor(max_workers=10) as pool:
        decisions = list(pool.map(propose, range(10)))
    assert sum(d.state == ExecutionState.AWAITING_APPROVAL for d in decisions) == 3
    assert sum(d.reason_code == DecisionCode.SPEND_LIMIT_EXCEEDED for d in decisions) == 7
    assert controller.usage("task-1")["spend_minor_units"] == 3000
    controller.close()


def test_policy_change_invalidates_pending_approval(controller):
    pending = controller.submit(action())
    controller.put_permission(permission(policy_version=2), token=TOKEN)
    decision = controller.approve(
        "op-1", pending.action_digest, reviewer="human", token=TOKEN
    )
    assert decision.state == ExecutionState.DENIED
    assert decision.reason_code == DecisionCode.POLICY_VERSION_MISMATCH
    assert controller.usage("task-1")["spend_minor_units"] == 0


def test_trusted_cancellation_releases_pending_reservation(controller):
    pending = controller.submit(action())
    assert controller.usage("task-1")["spend_minor_units"] == 1000
    cancelled = controller.cancel("op-1", reviewer="human", token=TOKEN)
    assert cancelled.state == ExecutionState.CANCELLED
    assert cancelled.reason_code == DecisionCode.CANCELLED
    assert controller.usage("task-1") == {
        "actions": 0, "spend_minor_units": 0, "affected_records": 0,
    }


def test_expiry_between_proposal_and_approval_blocks_dispatch_and_releases(tmp_path):
    now = [NOW]
    controller = SQLiteActionController(
        tmp_path / "actions.db", operator_token=TOKEN, clock_us=lambda: now[0]
    )
    controller.put_permission(permission(expires_at_us=NOW + 10), token=TOKEN)
    calls = []
    controller.register_executor(
        "bank", lambda args, request: calls.append(request.execution_id),
        token=TOKEN,
    )
    pending = controller.submit(action())
    now[0] += 10
    decision = controller.approve(
        "op-1", pending.action_digest, reviewer="human", token=TOKEN
    )
    assert decision.reason_code == DecisionCode.TASK_EXPIRED
    assert not calls
    assert controller.usage("task-1")["actions"] == 0
    controller.close()


class _FailingAudit:
    def __init__(self, fail_at):
        self.fail_at = fail_at
        self.calls = 0

    def append(self, event):
        self.calls += 1
        if self.calls >= self.fail_at:
            raise OSError("audit unavailable")


def test_audit_failure_before_dispatch_fails_closed(tmp_path):
    audit = _FailingAudit(fail_at=1)
    controller = SQLiteActionController(
        tmp_path / "actions.db", operator_token=TOKEN, audit=audit,
        clock_us=lambda: NOW,
    )
    controller.put_permission(permission(), token=TOKEN)
    calls = []
    controller.register_executor(
        "bank", lambda args, request: calls.append(request.execution_id),
        token=TOKEN,
    )
    decision = controller.submit(action())
    assert decision.reason_code == DecisionCode.AUDIT_UNAVAILABLE
    assert calls == []
    assert controller.get_decision("op-1") is None
    controller.close()


def test_audit_failure_after_dispatch_requires_reconciliation(tmp_path):
    audit = _FailingAudit(fail_at=3)
    controller = SQLiteActionController(
        tmp_path / "actions.db", operator_token=TOKEN, audit=audit,
        clock_us=lambda: NOW,
    )
    controller.put_permission(permission(
        allowed_operations=("account.read",),
        approval_required_operations=(),
        max_spend_minor_units=0,
    ), token=TOKEN)
    calls = []
    controller.register_executor(
        "bank", lambda args, request: calls.append(request.execution_id) or {"balance": 42},
        token=TOKEN,
    )
    decision = controller.submit(action(
        operation="account.read", arguments={"account": "a-main"},
        destinations=(), spend_minor_units=0, effect=ActionEffect.READ,
    ))
    assert calls == ["op-1"]
    assert decision.state == ExecutionState.OUTCOME_UNKNOWN
    assert decision.reason_code == DecisionCode.RECONCILIATION_REQUIRED
    assert controller.submit(action(
        operation="account.read", arguments={"account": "a-main"},
        destinations=(), spend_minor_units=0, effect=ActionEffect.READ,
    )).state == ExecutionState.OUTCOME_UNKNOWN
    assert calls == ["op-1"]
    controller.close()


def test_executor_exception_is_unknown_and_never_automatically_retried(controller):
    calls = []

    def uncertain(args, request):
        calls.append(request.execution_id)
        raise TimeoutError("response lost after dispatch")

    controller.register_executor("bank", uncertain, token=TOKEN)
    pending = controller.submit(action())
    result = controller.approve("op-1", pending.action_digest, reviewer="human", token=TOKEN)
    assert result.state == ExecutionState.OUTCOME_UNKNOWN
    assert result.reason_code == DecisionCode.RECONCILIATION_REQUIRED
    retry = controller.submit(action())
    assert retry.state == ExecutionState.OUTCOME_UNKNOWN
    assert len(calls) == 1
    reconciled = controller.reconcile(
        "op-1", completed=True, result={"receipt": "found"},
        reviewer="operator", token=TOKEN,
    )
    assert reconciled.state == ExecutionState.COMPLETED
    assert reconciled.result == {"receipt": "found"}


def test_restart_preserves_terminal_result_and_usage(tmp_path):
    path = tmp_path / "actions.db"
    first = SQLiteActionController(path, operator_token=TOKEN, clock_us=lambda: NOW)
    first.put_permission(permission(
        approval_required_operations=(), allowed_operations=("account.read",),
        max_spend_minor_units=0,
    ), token=TOKEN)
    first.register_executor("bank", lambda args, request: {"balance": 42}, token=TOKEN)
    read = action(
        operation="account.read", arguments={"account": "a-main"},
        destinations=(), spend_minor_units=0, effect=ActionEffect.READ,
    )
    completed = first.submit(read)
    assert completed.state == ExecutionState.COMPLETED
    first.close()

    second = SQLiteActionController(path, operator_token=TOKEN, clock_us=lambda: NOW)
    replay = second.submit(read)
    assert replay.replayed is True
    assert replay.result == {"balance": 42}
    assert second.usage("task-1")["actions"] == 1
    second.close()


def test_required_sequence_is_enforced(tmp_path):
    controller = SQLiteActionController(
        tmp_path / "actions.db", operator_token=TOKEN, clock_us=lambda: NOW
    )
    controller.put_permission(permission(
        approval_required_operations=(),
        required_predecessors=(("deploy.apply", "account.read"),),
    ), token=TOKEN)
    controller.register_executor("bank", lambda args, request: {"ok": True}, token=TOKEN)
    controller.register_executor("deployer", lambda args, request: {"ok": True}, token=TOKEN)
    deploy = action(
        operation="deploy.apply", tool_name="deployer", resources=("repo:site",),
        destinations=("env:production",), effect=ActionEffect.WRITE,
    )
    assert controller.submit(deploy).reason_code == DecisionCode.SEQUENCE_NOT_ALLOWED
    read = action(
        "read-1", operation="account.read", arguments={}, destinations=(),
        spend_minor_units=0, effect=ActionEffect.READ,
    )
    assert controller.submit(read).state == ExecutionState.COMPLETED
    assert controller.submit(action(
        "deploy-2", operation="deploy.apply", tool_name="deployer",
        resources=("repo:site",), destinations=("env:production",),
        effect=ActionEffect.WRITE,
    )).state == ExecutionState.COMPLETED
    controller.close()


def test_tool_guard_cannot_be_bypassed_by_task_permission(tmp_path):
    guard = ToolGuardLayer(policies=[ToolPolicy(
        name="bank", schema={"type": "object", "additionalProperties": False},
        side_effect=SideEffect.DESTRUCTIVE, action=Verdict.BLOCK,
    )])
    controller = SQLiteActionController(
        tmp_path / "actions.db", operator_token=TOKEN, tool_guard=guard,
        clock_us=lambda: NOW,
    )
    controller.put_permission(permission(), token=TOKEN)
    decision = controller.submit(action(arguments={}))
    assert decision.reason_code == DecisionCode.TOOL_GUARD_BLOCKED
    controller.close()


def test_pramagent_has_no_direct_execution_fallback(controller):
    armor = Pramagent(action_controller=controller)
    pending = armor.execute_action(action())
    assert pending.state == ExecutionState.AWAITING_APPROVAL
    with pytest.raises(RuntimeError, match="no action controller"):
        Pramagent().execute_action(action("op-2"))


def test_summaries_are_generated_from_structured_facts(controller):
    decision = controller.submit(action())
    assert "1000 minor units" in decision.summary
    assert "account:a-main" in decision.summary
    assert "account:a-vendor" in decision.summary
    assert "safe" not in decision.summary.lower()


def test_mediated_tool_has_no_direct_function_fallback(controller):
    armor = Pramagent(action_controller=controller)
    calls = []

    def request_factory(args, kwargs):
        return action(
            arguments={"args": list(args), "kwargs": kwargs},
        )

    @mediated_tool(
        armor, request_factory=request_factory, tool_name="bank",
        operator_token=TOKEN,
    )
    def send(amount, destination):
        calls.append((amount, destination))
        return {"sent": amount}

    pending = send(1000, "a-vendor")
    assert pending.state == ExecutionState.AWAITING_APPROVAL
    assert calls == []
    completed = controller.approve(
        pending.execution_id, pending.action_digest, reviewer="human", token=TOKEN
    )
    assert completed.result == {"sent": 1000}
    assert calls == [(1000, "a-vendor")]


def test_crewai_wrapper_stops_escalation_instead_of_executing():
    from pramagent.adapters.crewai import PramagentGuard

    guard = ToolGuardLayer(policies=[ToolPolicy(
        name="deploy",
        schema={"type": "object", "properties": {
            "args": {"type": "array"},
            "kwargs": {"type": "object"},
        }, "required": ["args", "kwargs"], "additionalProperties": False},
        action=Verdict.ESCALATE,
    )])
    armor = Pramagent(tool_guard=guard)
    calls = []

    @PramagentGuard(armor).wrap_tool(name="deploy")
    def deploy():
        calls.append(True)

    with pytest.raises(PermissionError, match="not authorized"):
        deploy()
    assert calls == []
