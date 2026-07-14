"""Dedicated tests for HITLWorkflowLayer, ApproverChain, and QuorumApprover
(audit Finding #7: these workflow primitives had no test coverage)."""
import asyncio

import pytest

from pramagent.hitl.workflow import (ApprovalAuditLog, ApproverChain,
                                     HITLWorkflowLayer, QuorumApprover,
                                     _ApproverSlot)
from pramagent.types import HITLStatus


def _slot(approver_id, fn, timeout_s=1.0):
    return _ApproverSlot(approver_id=approver_id, fn=fn, timeout_s=timeout_s)


async def _approve(action, context):
    return True


async def _deny(action, context):
    return False


async def _never(action, context):
    await asyncio.sleep(60)


async def _abstain(action, context):
    return None


# ───────────────────────── tenant-scoped audit log ────────────────────────

@pytest.mark.asyncio
async def test_approval_record_derives_tenant_id_from_context():
    log = ApprovalAuditLog()
    chain = ApproverChain([_slot("oncall", _approve)], audit_log=log)
    await chain("wire", {"tenant": "acme"})
    assert log.all()[0].tenant_id == "acme"


@pytest.mark.asyncio
async def test_approval_record_prefers_explicit_tenant_id_key_over_tenant():
    log = ApprovalAuditLog()
    chain = ApproverChain([_slot("oncall", _approve)], audit_log=log)
    await chain("wire", {"tenant_id": "acme", "tenant": "ignored"})
    assert log.all()[0].tenant_id == "acme"


@pytest.mark.asyncio
async def test_audit_log_all_scopes_by_tenant():
    """`_GLOBAL_AUDIT_LOG` is a process-wide singleton shared across every
    workflow instance that doesn't supply its own audit_log= — an unscoped
    `.all()` therefore mixes every tenant's approval history. Passing
    tenant_id must return only that tenant's records (ISSUE-11)."""
    log = ApprovalAuditLog()
    chain = ApproverChain([_slot("oncall", _approve)], audit_log=log)
    await chain("wire", {"tenant": "acme"})
    await chain("wire", {"tenant": "beta"})

    assert len(log.all()) == 2
    acme_only = log.all(tenant_id="acme")
    assert len(acme_only) == 1
    assert acme_only[0].tenant_id == "acme"
    assert log.all(tenant_id="nonexistent") == []


@pytest.mark.asyncio
async def test_audit_log_for_action_scopes_by_tenant():
    log = ApprovalAuditLog()
    chain = ApproverChain([_slot("oncall", _approve)], audit_log=log)
    await chain("wire_transfer", {"tenant": "acme"})
    await chain("wire_transfer", {"tenant": "beta"})

    assert len(log.for_action("wire_transfer")) == 2
    scoped = log.for_action("wire_transfer", tenant_id="beta")
    assert len(scoped) == 1
    assert scoped[0].tenant_id == "beta"


# ───────────────────────────── ApproverChain ──────────────────────────────

@pytest.mark.asyncio
async def test_chain_first_approver_decides():
    log = ApprovalAuditLog()
    chain = ApproverChain([_slot("oncall", _approve)], audit_log=log)
    assert await chain("wire", {}) is True
    assert log.all()[0].approver_id == "oncall"
    assert log.all()[0].decision is True


@pytest.mark.asyncio
async def test_chain_escalates_on_timeout():
    log = ApprovalAuditLog()
    chain = ApproverChain([
        _slot("oncall", _never, timeout_s=1.0),    # times out
        _slot("manager", _approve),
    ], audit_log=log)
    assert await chain("wire", {}) is True
    records = log.all()
    assert [r.approver_id for r in records] == ["oncall", "manager"]
    assert records[0].decision is None and "timeout" in records[0].reason
    assert records[1].decision is True


@pytest.mark.asyncio
async def test_chain_deny_is_final():
    chain = ApproverChain([
        _slot("oncall", _deny),
        _slot("manager", _approve),      # never reached
    ], audit_log=ApprovalAuditLog())
    assert await chain("wire", {}) is False


@pytest.mark.asyncio
async def test_chain_exhaustion_returns_none():
    chain = ApproverChain([
        _slot("oncall", _abstain),
        _slot("manager", _never, timeout_s=1.0),
    ], audit_log=ApprovalAuditLog())
    assert await chain("wire", {}) is None


def test_chain_requires_at_least_one_slot():
    with pytest.raises(ValueError):
        ApproverChain([])


# ───────────────────────────── QuorumApprover ─────────────────────────────

@pytest.mark.asyncio
async def test_quorum_two_of_three_approves():
    quorum = QuorumApprover(
        approvers=[("a", _approve), ("b", _approve), ("c", _never)],
        required=2, timeout_s=2.0, audit_log=ApprovalAuditLog(),
    )
    assert await quorum("wire", {}) is True


@pytest.mark.asyncio
async def test_quorum_denied_when_quorum_impossible():
    # 2-of-3 with two denials: quorum can never be reached -> DENIED
    quorum = QuorumApprover(
        approvers=[("a", _deny), ("b", _deny), ("c", _never)],
        required=2, timeout_s=2.0, audit_log=ApprovalAuditLog(),
    )
    assert await quorum("wire", {}) is False


@pytest.mark.asyncio
async def test_quorum_single_deny_blocks_when_all_required():
    quorum = QuorumApprover(
        approvers=[("a", _approve), ("b", _deny)],
        required=2, timeout_s=2.0, audit_log=ApprovalAuditLog(),
    )
    assert await quorum("wire", {}) is False


@pytest.mark.asyncio
async def test_quorum_timeout_without_quorum_returns_none():
    quorum = QuorumApprover(
        approvers=[("a", _approve), ("b", _never), ("c", _never)],
        required=2, timeout_s=1.0, audit_log=ApprovalAuditLog(),
    )
    assert await quorum("wire", {}) is None


def test_quorum_validates_required_bounds():
    with pytest.raises(ValueError):
        QuorumApprover(approvers=[("a", _approve)], required=2)
    with pytest.raises(ValueError):
        QuorumApprover(approvers=[("a", _approve)], required=0)


@pytest.mark.asyncio
async def test_quorum_records_every_decision_in_audit_log():
    log = ApprovalAuditLog()
    quorum = QuorumApprover(
        approvers=[("a", _approve), ("b", _approve)],
        required=2, timeout_s=2.0, audit_log=log,
    )
    await quorum("wire", {"k": "v"})
    assert {r.approver_id for r in log.all()} == {"a", "b"}
    assert all(r.decision is True for r in log.all())


# ──────────────────────────── HITLWorkflowLayer ───────────────────────────

@pytest.mark.asyncio
async def test_workflow_layer_auto_for_non_consequential():
    layer = HITLWorkflowLayer(require_approval_for=["wire"],
                              audit_log=ApprovalAuditLog())
    assert await layer.gate("chat", {}) == HITLStatus.AUTO


@pytest.mark.asyncio
async def test_workflow_layer_idles_without_approver_and_records_audit():
    log = ApprovalAuditLog()
    layer = HITLWorkflowLayer(require_approval_for=["wire"], audit_log=log)
    assert await layer.gate("wire", {}) == HITLStatus.IDLE
    assert log.all()[0].reason == "no approver configured"


@pytest.mark.asyncio
async def test_workflow_layer_with_chain_approver():
    log = ApprovalAuditLog()
    chain = ApproverChain([
        _slot("oncall", _never, timeout_s=1.0),
        _slot("manager", _approve),
    ], audit_log=log)
    layer = HITLWorkflowLayer(require_approval_for=["wire"],
                              approver=chain, timeout_s=10.0, audit_log=log)
    assert await layer.gate("wire", {}) == HITLStatus.APPROVED
    # chain slots + the workflow-level record
    assert [r.approver_id for r in log.all()] == ["oncall", "manager", "workflow"]


@pytest.mark.asyncio
async def test_workflow_layer_denied_and_pending_count_resets():
    layer = HITLWorkflowLayer(require_approval_for=["wire"],
                              approver=_deny, audit_log=ApprovalAuditLog())
    assert await layer.gate("wire", {}) == HITLStatus.DENIED
    assert layer.pending_count == 0


@pytest.mark.asyncio
async def test_workflow_layer_outer_timeout_idles():
    layer = HITLWorkflowLayer(require_approval_for=["wire"],
                              approver=_never, timeout_s=1.0,
                              audit_log=ApprovalAuditLog())
    assert await layer.gate("wire", {}) == HITLStatus.IDLE
    assert layer.pending_count == 0
