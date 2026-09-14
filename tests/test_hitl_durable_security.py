from __future__ import annotations

import json
import threading
import time

from pramagent.queue import QueuedRequest, RequestStatus, SQLiteHITLQueue


def test_approval_binding_covers_action_context_and_tenant():
    request = QueuedRequest.new(
        "deploy",
        {"environment": "staging", "version": "1.2.3"},
        tenant_id="acme",
    )

    assert request.binding_is_valid()
    request.context["environment"] = "production"
    assert not request.binding_is_valid()


def test_expired_request_cannot_be_approved(tmp_path):
    queue = SQLiteHITLQueue(str(tmp_path / "hitl.db"))
    request = QueuedRequest.new("deploy", {}, tenant_id="acme")
    request.expires_at = time.time() - 1
    queue.enqueue(request)

    assert queue.decide(
        request.request_id,
        approved=True,
        decided_by="alice",
        tenant_id="acme",
        expected_binding=request.binding_hash,
    ) is False
    assert queue.get(request.request_id).status == RequestStatus.EXPIRED.value


def test_decision_must_match_the_bound_request(tmp_path):
    queue = SQLiteHITLQueue(str(tmp_path / "hitl.db"))
    request = QueuedRequest.new("deploy", {"version": "1"}, tenant_id="acme")
    queue.enqueue(request)

    assert queue.decide(
        request.request_id,
        approved=True,
        decided_by="alice",
        tenant_id="acme",
        expected_binding="wrong-binding",
    ) is False
    assert queue.get(request.request_id).status == RequestStatus.PENDING.value
    assert queue.decide(
        request.request_id,
        approved=True,
        decided_by="alice",
        tenant_id="acme",
        expected_binding=request.binding_hash,
    ) is True


def test_tampered_request_payload_cannot_be_approved(tmp_path):
    queue = SQLiteHITLQueue(str(tmp_path / "hitl.db"))
    request = QueuedRequest.new(
        "deploy", {"environment": "staging"}, tenant_id="acme"
    )
    queue.enqueue(request)
    queue._conn.execute(
        "UPDATE hitl_queue SET context = ? WHERE request_id = ?",
        (json.dumps({"environment": "production"}), request.request_id),
    )

    assert queue.decide(
        request.request_id,
        approved=True,
        decided_by="alice",
        tenant_id="acme",
        expected_binding=request.binding_hash,
    ) is False
    assert queue.get(request.request_id).status == RequestStatus.PENDING.value


def test_duplicate_request_id_cannot_reset_a_decision(tmp_path):
    queue = SQLiteHITLQueue(str(tmp_path / "hitl.db"))
    request = QueuedRequest.new("deploy", {}, tenant_id="acme")
    queue.enqueue(request)
    assert queue.decide(
        request.request_id,
        approved=False,
        decided_by="alice",
        expected_binding=request.binding_hash,
    )

    try:
        queue.enqueue(request)
    except Exception:
        pass
    else:
        raise AssertionError("duplicate enqueue must not reset a decided request")
    assert queue.get(request.request_id).status == RequestStatus.DENIED.value


def test_approval_is_single_use_across_sqlite_connections(tmp_path):
    path = str(tmp_path / "hitl.db")
    queues = [SQLiteHITLQueue(path), SQLiteHITLQueue(path)]
    request = QueuedRequest.new("deploy", {}, tenant_id="acme")
    queues[0].enqueue(request)
    barrier = threading.Barrier(2)
    results: list[bool] = []
    result_lock = threading.Lock()

    def approve(queue):
        barrier.wait()
        result = queue.decide(
            request.request_id,
            approved=True,
            decided_by="alice",
            tenant_id="acme",
            expected_binding=request.binding_hash,
        )
        with result_lock:
            results.append(result)

    threads = [threading.Thread(target=approve, args=(queue,)) for queue in queues]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads)
    assert sorted(results) == [False, True]
    assert queues[0].get(request.request_id).status == RequestStatus.APPROVED.value
    for queue in queues:
        queue.close()
