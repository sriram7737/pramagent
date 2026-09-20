"""Task-scoped authorization and mediated execution.

The model-facing side of this module can propose an :class:`ActionRequest`.
Only trusted application code can create task grants, register executors,
approve actions, or reconcile an unknown outcome.  Approvals are bound to the
canonical action digest, tenant, task, and policy version.

This module is an application control boundary, not an operating-system
sandbox.  Keep executor credentials outside agent processes and expose the
controller through a separately permissioned service in consequential
deployments.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from .types import Verdict


_MAX_JSON_BYTES = 256_000
_MAX_JSON_DEPTH = 32


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON property: {key}")
        result[key] = value
    return result


def _plain_json(value: Any, *, depth: int = 0) -> Any:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError("JSON value is too deeply nested")
    if value is None or type(value) in (str, int, bool):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("non-finite numbers are not permitted")
        return value
    if type(value) in (list, tuple):
        return [_plain_json(item, depth=depth + 1) for item in value]
    if type(value) is dict:
        result: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("JSON object keys must be strings")
            result[key] = _plain_json(item, depth=depth + 1)
        return result
    raise ValueError(f"unsupported argument type: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """Return the stable JSON representation used for action binding."""
    encoded = json.dumps(
        _plain_json(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(encoded.encode("utf-8")) > _MAX_JSON_BYTES:
        raise ValueError("JSON value exceeds the action snapshot limit")
    return encoded


def _parse_json_object(encoded: str) -> dict[str, Any]:
    value = json.loads(encoded, object_pairs_hook=_reject_duplicate_keys)
    if type(value) is not dict:
        raise ValueError("action arguments must be a JSON object")
    return value


def _identifier(name: str, value: str) -> str:
    if type(value) is not str or not value or len(value) > 256:
        raise ValueError(f"{name} must be a non-empty string of at most 256 characters")
    return value


def _string_tuple(name: str, values: tuple[str, ...]) -> tuple[str, ...]:
    if type(values) is not tuple:
        raise ValueError(f"{name} must be a tuple")
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        _identifier(name, value)
        if value in seen:
            raise ValueError(f"{name} contains a duplicate value")
        seen.add(value)
        normalized.append(value)
    return tuple(normalized)


def _nonnegative_int(name: str, value: int) -> int:
    if type(value) is not int or value < 0 or value > 2**63 - 1:
        raise ValueError(f"{name} must be a non-negative 64-bit integer")
    return value


class ActionEffect(str, Enum):
    READ = "read"
    WRITE = "write"
    PAYMENT = "payment"
    EXECUTE = "execute"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class ExecutionState(str, Enum):
    PROPOSED = "proposed"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    OUTCOME_UNKNOWN = "outcome_unknown"
    DENIED = "denied"
    CANCELLED = "cancelled"


class DecisionCode(str, Enum):
    AUTHORIZED = "AUTHORIZED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    COMPLETED = "COMPLETED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    INVALID_REQUEST = "INVALID_REQUEST"
    UNKNOWN_TASK = "UNKNOWN_TASK"
    TASK_DISABLED = "TASK_DISABLED"
    TASK_EXPIRED = "TASK_EXPIRED"
    POLICY_VERSION_MISMATCH = "POLICY_VERSION_MISMATCH"
    OPERATION_NOT_ALLOWED = "OPERATION_NOT_ALLOWED"
    TOOL_NOT_ALLOWED = "TOOL_NOT_ALLOWED"
    RESOURCE_NOT_ALLOWED = "RESOURCE_NOT_ALLOWED"
    DESTINATION_NOT_ALLOWED = "DESTINATION_NOT_ALLOWED"
    SPEND_LIMIT_EXCEEDED = "SPEND_LIMIT_EXCEEDED"
    ACTION_LIMIT_EXCEEDED = "ACTION_LIMIT_EXCEEDED"
    RECORD_LIMIT_EXCEEDED = "RECORD_LIMIT_EXCEEDED"
    SEQUENCE_NOT_ALLOWED = "SEQUENCE_NOT_ALLOWED"
    TOOL_GUARD_BLOCKED = "TOOL_GUARD_BLOCKED"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    APPROVAL_MISMATCH = "APPROVAL_MISMATCH"
    NO_PENDING_APPROVAL = "NO_PENDING_APPROVAL"
    CANCELLED = "CANCELLED"
    CONTROLLER_UNAVAILABLE = "CONTROLLER_UNAVAILABLE"
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"


@dataclass(frozen=True)
class ActionRequest:
    """An immutable snapshot of the exact operation proposed for execution."""

    execution_id: str
    task_id: str
    tenant_id: str
    policy_version: int
    tool_name: str
    operation: str
    arguments_json: str
    resources: tuple[str, ...] = ()
    destinations: tuple[str, ...] = ()
    spend_minor_units: int = 0
    affected_records: int = 0
    effect: ActionEffect = ActionEffect.UNKNOWN
    created_at_us: int = field(default_factory=lambda: time.time_ns() // 1_000)
    expires_at_us: int = 0

    def __post_init__(self) -> None:
        for name in ("execution_id", "task_id", "tenant_id", "tool_name", "operation"):
            _identifier(name, getattr(self, name))
        _nonnegative_int("policy_version", self.policy_version)
        _nonnegative_int("spend_minor_units", self.spend_minor_units)
        _nonnegative_int("affected_records", self.affected_records)
        _nonnegative_int("created_at_us", self.created_at_us)
        _nonnegative_int("expires_at_us", self.expires_at_us)
        _string_tuple("resources", self.resources)
        _string_tuple("destinations", self.destinations)
        if not isinstance(self.effect, ActionEffect):
            object.__setattr__(self, "effect", ActionEffect(self.effect))
        normalized = canonical_json(_parse_json_object(self.arguments_json))
        object.__setattr__(self, "arguments_json", normalized)

    @classmethod
    def create(
        cls,
        *,
        execution_id: str,
        task_id: str,
        tenant_id: str,
        policy_version: int,
        tool_name: str,
        operation: str,
        arguments: Mapping[str, Any],
        resources: tuple[str, ...] = (),
        destinations: tuple[str, ...] = (),
        spend_minor_units: int = 0,
        affected_records: int = 0,
        effect: ActionEffect = ActionEffect.UNKNOWN,
        created_at_us: Optional[int] = None,
        expires_at_us: int = 0,
    ) -> "ActionRequest":
        return cls(
            execution_id=execution_id,
            task_id=task_id,
            tenant_id=tenant_id,
            policy_version=policy_version,
            tool_name=tool_name,
            operation=operation,
            arguments_json=canonical_json(dict(arguments)),
            resources=resources,
            destinations=destinations,
            spend_minor_units=spend_minor_units,
            affected_records=affected_records,
            effect=effect,
            created_at_us=(time.time_ns() // 1_000 if created_at_us is None else created_at_us),
            expires_at_us=expires_at_us,
        )

    @property
    def arguments(self) -> dict[str, Any]:
        """Return a detached copy; callers cannot mutate the signed snapshot."""
        return _parse_json_object(self.arguments_json)

    def material(self) -> dict[str, Any]:
        return {
            "record_type": "pramagent.action_request",
            "record_version": 1,
            "execution_id": self.execution_id,
            "task_id": self.task_id,
            "tenant_id": self.tenant_id,
            "policy_version": self.policy_version,
            "tool_name": self.tool_name,
            "operation": self.operation,
            "arguments": self.arguments,
            "resources": list(self.resources),
            "destinations": list(self.destinations),
            "spend_minor_units": self.spend_minor_units,
            "affected_records": self.affected_records,
            "effect": self.effect.value,
            "created_at_us": self.created_at_us,
            "expires_at_us": self.expires_at_us,
        }

    @property
    def digest(self) -> str:
        payload = b"pramagent.action-request.v1\x00" + canonical_json(self.material()).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class TaskPermission:
    """Trusted, versioned authority for one task. Empty allow-lists deny all."""

    task_id: str
    tenant_id: str
    policy_version: int
    expires_at_us: int
    allowed_operations: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    allowed_resources: tuple[str, ...] = ()
    allowed_destinations: tuple[str, ...] = ()
    approval_required_operations: tuple[str, ...] = ()
    denied_operations: tuple[str, ...] = ()
    max_spend_minor_units: int = 0
    max_actions: int = 0
    max_affected_records: int = 0
    required_predecessors: tuple[tuple[str, str], ...] = ()
    active: bool = True

    def __post_init__(self) -> None:
        _identifier("task_id", self.task_id)
        _identifier("tenant_id", self.tenant_id)
        _nonnegative_int("policy_version", self.policy_version)
        _nonnegative_int("expires_at_us", self.expires_at_us)
        for name in (
            "allowed_operations", "allowed_tools", "allowed_resources",
            "allowed_destinations", "approval_required_operations", "denied_operations",
        ):
            _string_tuple(name, getattr(self, name))
        _nonnegative_int("max_spend_minor_units", self.max_spend_minor_units)
        _nonnegative_int("max_actions", self.max_actions)
        _nonnegative_int("max_affected_records", self.max_affected_records)
        if type(self.active) is not bool:
            raise ValueError("active must be a boolean")
        if type(self.required_predecessors) is not tuple:
            raise ValueError("required_predecessors must be a tuple")
        for pair in self.required_predecessors:
            if type(pair) is not tuple or len(pair) != 2:
                raise ValueError("each predecessor rule must be an (operation, predecessor) tuple")
            _identifier("operation", pair[0])
            _identifier("predecessor", pair[1])
        if set(self.approval_required_operations) - set(self.allowed_operations):
            raise ValueError("approval-required operations must also be allowed")
        if set(self.allowed_operations) & set(self.denied_operations):
            raise ValueError("an operation cannot be both allowed and denied")

    def material(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "tenant_id": self.tenant_id,
            "policy_version": self.policy_version,
            "expires_at_us": self.expires_at_us,
            "allowed_operations": list(self.allowed_operations),
            "allowed_tools": list(self.allowed_tools),
            "allowed_resources": list(self.allowed_resources),
            "allowed_destinations": list(self.allowed_destinations),
            "approval_required_operations": list(self.approval_required_operations),
            "denied_operations": list(self.denied_operations),
            "max_spend_minor_units": self.max_spend_minor_units,
            "max_actions": self.max_actions,
            "max_affected_records": self.max_affected_records,
            "required_predecessors": [list(pair) for pair in self.required_predecessors],
            "active": self.active,
        }

    @classmethod
    def from_material(cls, value: Mapping[str, Any]) -> "TaskPermission":
        data = dict(value)
        for name in (
            "allowed_operations", "allowed_tools", "allowed_resources",
            "allowed_destinations", "approval_required_operations", "denied_operations",
        ):
            data[name] = tuple(data.get(name, ()))
        data["required_predecessors"] = tuple(tuple(pair) for pair in data.get("required_predecessors", ()))
        return cls(**data)


@dataclass(frozen=True)
class ActionDecision:
    execution_id: str
    action_digest: str
    state: ExecutionState
    reason_code: DecisionCode
    explanation: str
    summary: str
    policy_version: int
    result: Any = None
    replayed: bool = False

    @property
    def allowed(self) -> bool:
        return self.state in (ExecutionState.APPROVED, ExecutionState.EXECUTING, ExecutionState.COMPLETED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "action_digest": self.action_digest,
            "state": self.state.value,
            "reason_code": self.reason_code.value,
            "explanation": self.explanation,
            "summary": self.summary,
            "policy_version": self.policy_version,
            "result": self.result,
            "replayed": self.replayed,
        }


def summarize_action(action: ActionRequest) -> str:
    """Render approval-critical facts without a model or network call."""
    resources = ", ".join(action.resources) if action.resources else "no declared resource"
    destinations = ", ".join(action.destinations) if action.destinations else "no external destination"
    if action.effect == ActionEffect.READ:
        return f"Read {resources} using {action.operation}. No changes are requested."
    if action.effect == ActionEffect.PAYMENT:
        return (
            f"Execute {action.operation} on {resources} to {destinations} for "
            f"{action.spend_minor_units} minor units. This moves value."
        )
    if action.effect == ActionEffect.WRITE:
        return f"Modify {resources} using {action.operation}. Recovery has not been verified."
    if action.effect == ActionEffect.EXTERNAL:
        return f"Send data or an action from {resources} to {destinations} using {action.operation}."
    if action.effect == ActionEffect.EXECUTE:
        return f"Execute {action.operation} with the worker's permissions. Full effects may be unknown."
    return f"Run {action.operation} through {action.tool_name}. Its full effects are unknown."


Executor = Callable[[dict[str, Any], ActionRequest], Any]


class _AuditUnavailable(RuntimeError):
    pass


class SQLiteActionController:
    """Durable task authority and exact-action execution mediator.

    The SQLite backend serializes reservations with ``BEGIN IMMEDIATE``.  It is
    suitable for one host.  Use a separately permissioned service and a shared
    database before running multiple hosts.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        operator_token: str,
        tool_guard: Any = None,
        audit: Any = None,
        clock_us: Callable[[], int] = lambda: time.time_ns() // 1_000,
    ) -> None:
        if type(operator_token) is not str or len(operator_token) < 16:
            raise ValueError("operator_token must contain at least 16 characters")
        self.path = str(path)
        self._operator_digest = hashlib.sha256(operator_token.encode("utf-8")).digest()
        self.tool_guard = tool_guard
        self.audit = audit
        self.clock_us = clock_us
        self.available = True
        self._lock = threading.RLock()
        self._executors: dict[str, Executor] = {}
        self._db = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS task_permissions (
                task_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                policy_version INTEGER NOT NULL,
                material TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS task_usage (
                task_id TEXT PRIMARY KEY,
                actions INTEGER NOT NULL DEFAULT 0,
                spend_minor_units INTEGER NOT NULL DEFAULT 0,
                affected_records INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(task_id) REFERENCES task_permissions(task_id)
            );
            CREATE TABLE IF NOT EXISTS action_executions (
                execution_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                policy_version INTEGER NOT NULL,
                action_digest TEXT NOT NULL,
                action_json TEXT NOT NULL,
                summary TEXT NOT NULL,
                state TEXT NOT NULL,
                reason_code TEXT NOT NULL,
                explanation TEXT NOT NULL,
                result_json TEXT,
                reviewer TEXT,
                created_at_us INTEGER NOT NULL,
                updated_at_us INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS action_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                execution_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                created_at_us INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_action_task_state
                ON action_executions(task_id, state);
            """
        )
        # A crash after dispatch cannot be interpreted as a failed action.
        self._db.execute(
            "UPDATE action_executions SET state=?, reason_code=?, explanation=?, updated_at_us=? "
            "WHERE state=?",
            (
                ExecutionState.OUTCOME_UNKNOWN.value,
                DecisionCode.RECONCILIATION_REQUIRED.value,
                "The controller restarted while this action was executing; reconcile before retrying.",
                self.clock_us(),
                ExecutionState.EXECUTING.value,
            ),
        )
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    def _operator(self, token: str) -> None:
        if type(token) is not str:
            raise PermissionError("operator authentication required")
        supplied = hashlib.sha256(token.encode("utf-8")).digest()
        if not hmac.compare_digest(supplied, self._operator_digest):
            raise PermissionError("operator authentication required")

    def register_executor(self, tool_name: str, executor: Executor, *, token: str) -> None:
        self._operator(token)
        _identifier("tool_name", tool_name)
        if not callable(executor):
            raise TypeError("executor must be callable")
        self._executors[tool_name] = executor

    def put_permission(self, permission: TaskPermission, *, token: str) -> None:
        self._operator(token)
        material = canonical_json(permission.material())
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT tenant_id, policy_version FROM task_permissions WHERE task_id=?",
                    (permission.task_id,),
                ).fetchone()
                if row is not None:
                    if row["tenant_id"] != permission.tenant_id:
                        raise ValueError("a task cannot be moved between tenants")
                    if permission.policy_version <= row["policy_version"]:
                        raise ValueError("policy_version must increase")
                self._db.execute(
                    "INSERT INTO task_permissions(task_id, tenant_id, policy_version, material) "
                    "VALUES(?,?,?,?) ON CONFLICT(task_id) DO UPDATE SET "
                    "tenant_id=excluded.tenant_id, policy_version=excluded.policy_version, material=excluded.material",
                    (permission.task_id, permission.tenant_id, permission.policy_version, material),
                )
                self._db.execute(
                    "INSERT OR IGNORE INTO task_usage(task_id, actions, spend_minor_units, affected_records) "
                    "VALUES(?,0,0,0)",
                    (permission.task_id,),
                )
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise

    def revoke_task(self, task_id: str, *, token: str) -> None:
        self._operator(token)
        permission = self.get_permission(task_id)
        if permission is None:
            raise KeyError(task_id)
        self.put_permission(
            TaskPermission.from_material({
                **permission.material(),
                "policy_version": permission.policy_version + 1,
                "active": False,
            }),
            token=token,
        )

    def get_permission(self, task_id: str) -> Optional[TaskPermission]:
        row = self._db.execute(
            "SELECT material FROM task_permissions WHERE task_id=?", (task_id,)
        ).fetchone()
        return None if row is None else TaskPermission.from_material(json.loads(row["material"]))

    def usage(self, task_id: str) -> dict[str, int]:
        row = self._db.execute(
            "SELECT actions, spend_minor_units, affected_records FROM task_usage WHERE task_id=?",
            (task_id,),
        ).fetchone()
        if row is None:
            return {"actions": 0, "spend_minor_units": 0, "affected_records": 0}
        return dict(row)

    def _record_event(self, action: ActionRequest, event_type: str, detail: Mapping[str, Any]) -> None:
        event = {
            "event_type": event_type,
            "execution_id": action.execution_id,
            "action_digest": action.digest,
            "task_id": action.task_id,
            "tenant_id": action.tenant_id,
            "policy_version": action.policy_version,
            **dict(detail),
        }
        self._db.execute(
            "INSERT INTO action_events(execution_id,event_type,detail_json,created_at_us) VALUES(?,?,?,?)",
            (action.execution_id, event_type, canonical_json(event), self.clock_us()),
        )
        if self.audit is not None:
            try:
                self.audit.append(event)
            except Exception as exc:
                raise _AuditUnavailable("action audit append failed") from exc

    def _decision_from_row(self, row: sqlite3.Row, *, replayed: bool = False) -> ActionDecision:
        return ActionDecision(
            execution_id=row["execution_id"],
            action_digest=row["action_digest"],
            state=ExecutionState(row["state"]),
            reason_code=DecisionCode(row["reason_code"]),
            explanation=row["explanation"],
            summary=row["summary"],
            policy_version=row["policy_version"],
            result=None if row["result_json"] is None else json.loads(row["result_json"]),
            replayed=replayed,
        )

    def get_decision(self, execution_id: str) -> Optional[ActionDecision]:
        row = self._db.execute(
            "SELECT * FROM action_executions WHERE execution_id=?", (execution_id,)
        ).fetchone()
        return None if row is None else self._decision_from_row(row)

    def _release_reservation(self, action: ActionRequest) -> None:
        self._db.execute(
            "UPDATE task_usage SET actions=MAX(0,actions-1), "
            "spend_minor_units=MAX(0,spend_minor_units-?), "
            "affected_records=MAX(0,affected_records-?) WHERE task_id=?",
            (action.spend_minor_units, action.affected_records, action.task_id),
        )

    @staticmethod
    def _deny_reason(permission: TaskPermission, action: ActionRequest, now_us: int) -> Optional[tuple[DecisionCode, str]]:
        if not permission.active:
            return DecisionCode.TASK_DISABLED, "The task permission has been revoked or disabled."
        if now_us >= permission.expires_at_us:
            return DecisionCode.TASK_EXPIRED, "The task permission has expired."
        if action.expires_at_us and now_us >= action.expires_at_us:
            return DecisionCode.TASK_EXPIRED, "The proposed action has expired."
        if permission.tenant_id != action.tenant_id:
            return DecisionCode.RESOURCE_NOT_ALLOWED, "The action tenant does not match the task tenant."
        if permission.policy_version != action.policy_version:
            return DecisionCode.POLICY_VERSION_MISMATCH, "The action was proposed under a different policy version."
        if action.operation in permission.denied_operations or action.operation not in permission.allowed_operations:
            return DecisionCode.OPERATION_NOT_ALLOWED, "The operation is outside the authorized task scope."
        if action.tool_name not in permission.allowed_tools:
            return DecisionCode.TOOL_NOT_ALLOWED, "The tool is outside the authorized task scope."
        if not set(action.resources).issubset(permission.allowed_resources):
            return DecisionCode.RESOURCE_NOT_ALLOWED, "One or more resources are outside the authorized task scope."
        if not set(action.destinations).issubset(permission.allowed_destinations):
            return DecisionCode.DESTINATION_NOT_ALLOWED, "One or more destinations are outside the authorized task scope."
        return None

    def _deny(self, action: ActionRequest, code: DecisionCode, explanation: str) -> ActionDecision:
        summary = summarize_action(action)
        now = self.clock_us()
        self._db.execute(
            "INSERT INTO action_executions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                action.execution_id, action.task_id, action.tenant_id, action.policy_version,
                action.digest, canonical_json(action.material()), summary,
                ExecutionState.DENIED.value, code.value, explanation, None, None,
                action.created_at_us, now,
            ),
        )
        self._record_event(action, "action_denied", {"reason_code": code.value, "summary": summary})
        return ActionDecision(
            action.execution_id, action.digest, ExecutionState.DENIED, code,
            explanation, summary, action.policy_version,
        )

    def submit(self, action: ActionRequest) -> ActionDecision:
        """Authorize an exact action and execute it or hold it for approval."""
        if not isinstance(action, ActionRequest):
            raise TypeError("action must be an ActionRequest")
        with self._lock:
            if not self.available:
                return ActionDecision(
                    action.execution_id, action.digest, ExecutionState.DENIED,
                    DecisionCode.CONTROLLER_UNAVAILABLE,
                    "The authorization controller is unavailable; execution is paused.",
                    summarize_action(action), action.policy_version,
                )
            self._db.execute("BEGIN IMMEDIATE")
            try:
                existing = self._db.execute(
                    "SELECT * FROM action_executions WHERE execution_id=?", (action.execution_id,)
                ).fetchone()
                if existing is not None:
                    if existing["action_digest"] != action.digest:
                        self._db.rollback()
                        return ActionDecision(
                            action.execution_id, action.digest, ExecutionState.DENIED,
                            DecisionCode.IDEMPOTENCY_CONFLICT,
                            "This execution ID is already bound to different arguments.",
                            summarize_action(action), action.policy_version,
                        )
                    self._db.rollback()
                    if existing["state"] == ExecutionState.APPROVED.value:
                        return self._execute(action.execution_id)
                    return self._decision_from_row(existing, replayed=True)

                permission = self.get_permission(action.task_id)
                if permission is None:
                    decision = self._deny(action, DecisionCode.UNKNOWN_TASK, "No trusted permission exists for this task.")
                    self._db.commit()
                    return decision
                denied = self._deny_reason(permission, action, self.clock_us())
                if denied is not None:
                    decision = self._deny(action, *denied)
                    self._db.commit()
                    return decision

                if self.tool_guard is not None:
                    tool_decision = self.tool_guard.evaluate(
                        action.tool_name,
                        action.arguments,
                        tenant_id=action.tenant_id,
                        session_id=action.task_id,
                        action_label=action.operation,
                    )
                    if tool_decision.verdict == Verdict.BLOCK:
                        decision = self._deny(
                            action, DecisionCode.TOOL_GUARD_BLOCKED,
                            f"Tool policy blocked the action: {tool_decision.reason}",
                        )
                        self._db.commit()
                        return decision
                    guard_requires_approval = tool_decision.verdict == Verdict.ESCALATE
                else:
                    guard_requires_approval = False

                predecessor_map = dict(permission.required_predecessors)
                predecessor = predecessor_map.get(action.operation)
                if predecessor:
                    row = self._db.execute(
                        "SELECT 1 FROM action_executions WHERE task_id=? AND state=? "
                        "AND json_extract(action_json, '$.operation')=? LIMIT 1",
                        (action.task_id, ExecutionState.COMPLETED.value, predecessor),
                    ).fetchone()
                    if row is None:
                        decision = self._deny(
                            action, DecisionCode.SEQUENCE_NOT_ALLOWED,
                            f"Operation {action.operation} requires completed predecessor {predecessor}.",
                        )
                        self._db.commit()
                        return decision

                usage = self._db.execute(
                    "SELECT actions, spend_minor_units, affected_records FROM task_usage WHERE task_id=?",
                    (action.task_id,),
                ).fetchone()
                if usage["actions"] + 1 > permission.max_actions:
                    decision = self._deny(action, DecisionCode.ACTION_LIMIT_EXCEEDED, "The task action limit would be exceeded.")
                    self._db.commit()
                    return decision
                if usage["spend_minor_units"] + action.spend_minor_units > permission.max_spend_minor_units:
                    decision = self._deny(action, DecisionCode.SPEND_LIMIT_EXCEEDED, "The task spending limit would be exceeded.")
                    self._db.commit()
                    return decision
                if usage["affected_records"] + action.affected_records > permission.max_affected_records:
                    decision = self._deny(action, DecisionCode.RECORD_LIMIT_EXCEEDED, "The task affected-record limit would be exceeded.")
                    self._db.commit()
                    return decision

                requires_approval = guard_requires_approval or action.operation in permission.approval_required_operations
                state = ExecutionState.AWAITING_APPROVAL if requires_approval else ExecutionState.APPROVED
                code = DecisionCode.APPROVAL_REQUIRED if requires_approval else DecisionCode.AUTHORIZED
                explanation = (
                    "A trusted reviewer must approve this exact action."
                    if requires_approval else "The exact action is within the active task permission."
                )
                summary = summarize_action(action)
                now = self.clock_us()
                self._db.execute(
                    "INSERT INTO action_executions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        action.execution_id, action.task_id, action.tenant_id, action.policy_version,
                        action.digest, canonical_json(action.material()), summary, state.value,
                        code.value, explanation, None, None, action.created_at_us, now,
                    ),
                )
                # Reserve cumulative authority before approval/execution so
                # concurrent pending requests cannot overbook the task.
                self._db.execute(
                    "UPDATE task_usage SET actions=actions+1, spend_minor_units=spend_minor_units+?, "
                    "affected_records=affected_records+? WHERE task_id=?",
                    (action.spend_minor_units, action.affected_records, action.task_id),
                )
                self._record_event(action, "action_authorized", {
                    "state": state.value,
                    "reason_code": code.value,
                    "summary": summary,
                })
                self._db.commit()
            except _AuditUnavailable:
                self._db.rollback()
                return ActionDecision(
                    action.execution_id, action.digest, ExecutionState.DENIED,
                    DecisionCode.AUDIT_UNAVAILABLE,
                    "The action audit sink is unavailable; execution is paused.",
                    summarize_action(action), action.policy_version,
                )
            except Exception:
                self._db.rollback()
                raise

        if requires_approval:
            return self.get_decision(action.execution_id)  # type: ignore[return-value]
        return self._execute(action.execution_id)

    def approve(
        self,
        execution_id: str,
        action_digest: str,
        *,
        reviewer: str,
        token: str,
    ) -> ActionDecision:
        self._operator(token)
        _identifier("reviewer", reviewer)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT * FROM action_executions WHERE execution_id=?", (execution_id,)
                ).fetchone()
                if row is None or row["state"] != ExecutionState.AWAITING_APPROVAL.value:
                    self._db.rollback()
                    return ActionDecision(
                        execution_id, action_digest, ExecutionState.DENIED,
                        DecisionCode.NO_PENDING_APPROVAL,
                        "No matching action is awaiting approval.", "", 0,
                    )
                if not hmac.compare_digest(row["action_digest"], action_digest):
                    self._db.rollback()
                    return ActionDecision(
                        execution_id, action_digest, ExecutionState.DENIED,
                        DecisionCode.APPROVAL_MISMATCH,
                        "Approval does not match the exact proposed action.",
                        row["summary"], row["policy_version"],
                    )
                action = self._action_from_row(row)
                permission = self.get_permission(row["task_id"])
                now = self.clock_us()
                invalid_code: Optional[DecisionCode] = None
                invalid_explanation = ""
                if permission is None:
                    invalid_code = DecisionCode.UNKNOWN_TASK
                    invalid_explanation = "The task permission no longer exists."
                elif not permission.active:
                    invalid_code = DecisionCode.TASK_DISABLED
                    invalid_explanation = "The task permission was disabled before approval."
                elif permission.policy_version != row["policy_version"]:
                    invalid_code = DecisionCode.POLICY_VERSION_MISMATCH
                    invalid_explanation = "The task policy changed before approval."
                elif now >= permission.expires_at_us or (
                    action.expires_at_us and now >= action.expires_at_us
                ):
                    invalid_code = DecisionCode.TASK_EXPIRED
                    invalid_explanation = "The task or action expired before approval."
                if invalid_code is not None:
                    self._release_reservation(action)
                    self._db.execute(
                        "UPDATE action_executions SET state=?,reason_code=?,explanation=?,updated_at_us=? WHERE execution_id=?",
                        (
                            ExecutionState.DENIED.value,
                            invalid_code.value,
                            invalid_explanation,
                            self.clock_us(), execution_id,
                        ),
                    )
                    self._record_event(action, "action_denied", {
                        "reason_code": invalid_code.value,
                        "detail": invalid_explanation,
                    })
                    self._db.commit()
                    return self.get_decision(execution_id)  # type: ignore[return-value]
                self._db.execute(
                    "UPDATE action_executions SET state=?,reason_code=?,explanation=?,reviewer=?,updated_at_us=? "
                    "WHERE execution_id=?",
                    (
                        ExecutionState.APPROVED.value, DecisionCode.AUTHORIZED.value,
                        "A trusted reviewer approved the exact action.", reviewer,
                        self.clock_us(), execution_id,
                    ),
                )
                self._record_event(action, "action_approved", {"reviewer": reviewer})
                self._db.commit()
            except _AuditUnavailable:
                self._db.rollback()
                return ActionDecision(
                    action.execution_id, action.digest, ExecutionState.DENIED,
                    DecisionCode.AUDIT_UNAVAILABLE,
                    "The action audit sink is unavailable; dispatch did not start.",
                    summarize_action(action), action.policy_version,
                )
            except Exception:
                self._db.rollback()
                raise
        return self._execute(execution_id)

    def cancel(self, execution_id: str, *, reviewer: str, token: str) -> ActionDecision:
        """Cancel a pending action and release its unused reservation."""
        self._operator(token)
        _identifier("reviewer", reviewer)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT * FROM action_executions WHERE execution_id=?", (execution_id,)
                ).fetchone()
                if row is None or row["state"] != ExecutionState.AWAITING_APPROVAL.value:
                    self._db.rollback()
                    raise ValueError("only an awaiting-approval action may be cancelled")
                action = self._action_from_row(row)
                self._release_reservation(action)
                self._db.execute(
                    "UPDATE action_executions SET state=?,reason_code=?,explanation=?,reviewer=?,updated_at_us=? "
                    "WHERE execution_id=?",
                    (
                        ExecutionState.CANCELLED.value, DecisionCode.CANCELLED.value,
                        "A trusted reviewer cancelled the action before execution.",
                        reviewer, self.clock_us(), execution_id,
                    ),
                )
                self._record_event(action, "action_cancelled", {"reviewer": reviewer})
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        return self.get_decision(execution_id)  # type: ignore[return-value]

    def _action_from_row(self, row: sqlite3.Row) -> ActionRequest:
        value = json.loads(row["action_json"])
        return ActionRequest.create(
            execution_id=value["execution_id"], task_id=value["task_id"],
            tenant_id=value["tenant_id"], policy_version=value["policy_version"],
            tool_name=value["tool_name"], operation=value["operation"],
            arguments=value["arguments"], resources=tuple(value["resources"]),
            destinations=tuple(value["destinations"]),
            spend_minor_units=value["spend_minor_units"],
            affected_records=value["affected_records"], effect=ActionEffect(value["effect"]),
            created_at_us=value["created_at_us"], expires_at_us=value["expires_at_us"],
        )

    def _execute(self, execution_id: str) -> ActionDecision:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT * FROM action_executions WHERE execution_id=?", (execution_id,)
                ).fetchone()
                if row is None:
                    raise KeyError(execution_id)
                if row["state"] != ExecutionState.APPROVED.value:
                    self._db.rollback()
                    return self._decision_from_row(row, replayed=True)
                action = self._action_from_row(row)
                permission = self.get_permission(action.task_id)
                denied = (
                    (DecisionCode.UNKNOWN_TASK, "The task permission no longer exists.")
                    if permission is None
                    else self._deny_reason(permission, action, self.clock_us())
                )
                if denied is not None:
                    self._release_reservation(action)
                    self._db.execute(
                        "UPDATE action_executions SET state=?,reason_code=?,explanation=?,updated_at_us=? "
                        "WHERE execution_id=?",
                        (
                            ExecutionState.DENIED.value, denied[0].value, denied[1],
                            self.clock_us(), execution_id,
                        ),
                    )
                    self._record_event(action, "action_denied_before_dispatch", {
                        "reason_code": denied[0].value,
                    })
                    self._db.commit()
                    return self.get_decision(execution_id)  # type: ignore[return-value]
                executor = self._executors.get(action.tool_name)
                if executor is None:
                    self._db.execute(
                        "UPDATE action_executions SET state=?,reason_code=?,explanation=?,updated_at_us=? WHERE execution_id=?",
                        (
                            ExecutionState.FAILED.value, DecisionCode.EXECUTION_FAILED.value,
                            "No trusted executor is registered for this tool.", self.clock_us(), execution_id,
                        ),
                    )
                    self._record_event(action, "action_failed", {"reason_code": DecisionCode.EXECUTION_FAILED.value})
                    self._db.commit()
                    return self.get_decision(execution_id)  # type: ignore[return-value]
                self._db.execute(
                    "UPDATE action_executions SET state=?,updated_at_us=? WHERE execution_id=?",
                    (ExecutionState.EXECUTING.value, self.clock_us(), execution_id),
                )
                self._record_event(action, "action_dispatching", {"tool_name": action.tool_name})
                self._db.commit()
            except _AuditUnavailable:
                self._db.rollback()
                return ActionDecision(
                    action.execution_id, action.digest, ExecutionState.DENIED,
                    DecisionCode.AUDIT_UNAVAILABLE,
                    "The action audit sink is unavailable; dispatch did not start.",
                    summarize_action(action), action.policy_version,
                )
            except Exception:
                self._db.rollback()
                raise

        try:
            result = _plain_json(executor(action.arguments, action))
            result_json = canonical_json(result)
        except Exception as exc:
            # Once dispatch starts, an exception cannot prove that the target
            # performed no side effect.  Reconciliation is mandatory.
            try:
                with self._lock, self._db:
                    self._db.execute(
                        "UPDATE action_executions SET state=?,reason_code=?,explanation=?,updated_at_us=? WHERE execution_id=?",
                        (
                            ExecutionState.OUTCOME_UNKNOWN.value,
                            DecisionCode.RECONCILIATION_REQUIRED.value,
                            f"Executor outcome is unknown ({type(exc).__name__}); reconcile before retrying.",
                            self.clock_us(), execution_id,
                        ),
                    )
                    self._record_event(action, "action_outcome_unknown", {
                        "reason_code": DecisionCode.RECONCILIATION_REQUIRED.value,
                        "error_type": type(exc).__name__,
                    })
            except _AuditUnavailable:
                self._mark_unknown_without_audit(
                    execution_id,
                    f"Executor outcome is unknown ({type(exc).__name__}) and the audit sink is unavailable.",
                )
            return self.get_decision(execution_id)  # type: ignore[return-value]

        try:
            with self._lock, self._db:
                self._db.execute(
                    "UPDATE action_executions SET state=?,reason_code=?,explanation=?,result_json=?,updated_at_us=? "
                    "WHERE execution_id=?",
                    (
                        ExecutionState.COMPLETED.value, DecisionCode.COMPLETED.value,
                        "The trusted executor completed the exact authorized action.",
                        result_json, self.clock_us(), execution_id,
                    ),
                )
                self._record_event(action, "action_completed", {"reason_code": DecisionCode.COMPLETED.value})
        except _AuditUnavailable:
            self._mark_unknown_without_audit(
                execution_id,
                "The executor returned, but completion evidence could not be persisted.",
            )
        return self.get_decision(execution_id)  # type: ignore[return-value]

    def _mark_unknown_without_audit(self, execution_id: str, explanation: str) -> None:
        """Persist the conservative state when the audit sink itself is down."""
        with self._lock, self._db:
            self._db.execute(
                "UPDATE action_executions SET state=?,reason_code=?,explanation=?,result_json=NULL,updated_at_us=? "
                "WHERE execution_id=?",
                (
                    ExecutionState.OUTCOME_UNKNOWN.value,
                    DecisionCode.RECONCILIATION_REQUIRED.value,
                    explanation, self.clock_us(), execution_id,
                ),
            )

    def reconcile(
        self,
        execution_id: str,
        *,
        completed: bool,
        result: Any,
        reviewer: str,
        token: str,
    ) -> ActionDecision:
        self._operator(token)
        _identifier("reviewer", reviewer)
        result_json = canonical_json(result)
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT * FROM action_executions WHERE execution_id=?", (execution_id,)
            ).fetchone()
            if row is None or row["state"] != ExecutionState.OUTCOME_UNKNOWN.value:
                raise ValueError("only an outcome-unknown action may be reconciled")
            action = self._action_from_row(row)
            state = ExecutionState.COMPLETED if completed else ExecutionState.FAILED
            code = DecisionCode.COMPLETED if completed else DecisionCode.EXECUTION_FAILED
            self._db.execute(
                "UPDATE action_executions SET state=?,reason_code=?,explanation=?,result_json=?,reviewer=?,updated_at_us=? "
                "WHERE execution_id=?",
                (
                    state.value, code.value, "A trusted reviewer reconciled the external outcome.",
                    result_json, reviewer, self.clock_us(), execution_id,
                ),
            )
            self._record_event(action, "action_reconciled", {
                "state": state.value, "reviewer": reviewer,
            })
        return self.get_decision(execution_id)  # type: ignore[return-value]
