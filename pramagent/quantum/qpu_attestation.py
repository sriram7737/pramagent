"""Convenience API for a guarded IBM hardware attestation."""
from __future__ import annotations

from typing import Any

from ..core import Pramagent
from .ibm_runtime import (
    DEFAULT_MAX_SHOTS_PER_CALL,
    DEFAULT_MAX_SHOTS_PER_SESSION,
    IBM_HARDWARE_TOOL_NAME,
    IBMQuantumRuntime,
    make_ibm_hardware_policy,
)


def run_hardware_attestation(
    *,
    shots: int = 128,
    backend_name: str = "",
    confirm_hardware: bool = False,
    allow_unpriced_hardware: bool = False,
    minimum_correlation: float = 0.60,
    optimization_level: int = 3,
    initial_layout: tuple[int, int] | list[int] | None = None,
    max_layout_error_proxy: float | None = 0.05,
    calibration_valid_for_seconds: float = 900.0,
    max_shots_per_call: int = DEFAULT_MAX_SHOTS_PER_CALL,
    max_shots_per_session: int = DEFAULT_MAX_SHOTS_PER_SESSION,
    tenant_id: str = "local-operator",
    session_id: str = "ibm-attestation",
    armor: Pramagent | None = None,
    **runner_kwargs: Any,
) -> dict[str, Any]:
    """Run the packaged Bell-pair attestation and return a JSON-safe record.

    Direct application integrations should pass their configured ``Pramagent``
    instance so the evidence is written to the deployment's durable audit
    backend. When ``armor`` is omitted, this helper uses an in-memory chain.
    """
    runtime_armor = armor or Pramagent()
    if IBM_HARDWARE_TOOL_NAME not in runtime_armor.tool_guard.policies:
        runtime_armor.tool_guard.register(
            make_ibm_hardware_policy(max_shots_per_call=max_shots_per_call)
        )
    runner = IBMQuantumRuntime(
        runtime_armor,
        tenant_id=tenant_id,
        session_id=session_id,
        max_shots_per_call=max_shots_per_call,
        max_shots_per_session=max_shots_per_session,
        **runner_kwargs,
    )
    return runner.run_hardware_attestation(
        shots=shots,
        backend_name=backend_name,
        confirm_hardware=confirm_hardware,
        allow_unpriced_hardware=allow_unpriced_hardware,
        minimum_correlation=minimum_correlation,
        optimization_level=optimization_level,
        initial_layout=initial_layout,
        max_layout_error_proxy=max_layout_error_proxy,
        calibration_valid_for_seconds=calibration_valid_for_seconds,
    ).to_dict()
