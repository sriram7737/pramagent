from __future__ import annotations

import json
from pathlib import Path

import pytest

from pramagent.quantum import QuantumEvidenceError, QuantumExecutionEvidence


def _evidence(**changes):
    values = {
        "provider": "provider-a",
        "backend": "qpu-1",
        "execution_id": "job-123",
        "workload": "caption_projection",
        "device_kind": "hardware",
        "circuit_hash": "a" * 64,
        "shots_requested": 100,
        "shots_observed": 100,
        "counts": {"00": 52, "11": 48},
    }
    values.update(changes)
    return QuantumExecutionEvidence(**values)


def test_provider_neutral_evidence_roundtrips_and_verifies():
    sealed = _evidence().seal()

    restored = QuantumExecutionEvidence.from_dict(sealed.to_dict())

    assert restored.provider == "provider-a"
    assert restored.execution_id == "job-123"
    assert restored.evidence_hash == sealed.computed_hash()


def test_evidence_hash_detects_field_tampering():
    payload = _evidence().seal().to_dict()
    payload["shots_observed"] = 99

    with pytest.raises(QuantumEvidenceError):
        QuantumExecutionEvidence.from_dict(payload)


def test_measurement_counts_must_match_observed_shots():
    with pytest.raises(QuantumEvidenceError, match="do not match"):
        _evidence(shots_observed=99).seal()


def test_unknown_cost_is_distinct_from_zero_cost():
    evidence = _evidence(
        pricing_model="ibm_qpu_time_unpriced",
        estimated_cost_usd=None,
        actual_cost_usd=None,
    ).seal()

    assert evidence.estimated_cost_usd is None
    assert evidence.actual_cost_usd is None


@pytest.mark.parametrize(
    ("filename", "execution_id"),
    [
        (
            "ibm_fez_daj5doomhr3c73e8i5a0.json",
            "daj5doomhr3c73e8i5a0",
        ),
        (
            "ibm_fez_dajg0i1hvn6c73cuckbg.json",
            "dajg0i1hvn6c73cuckbg",
        ),
        (
            "ibm_fez_dajg4l1hvn6c73cucon0.json",
            "dajg4l1hvn6c73cucon0",
        ),
    ],
)
def test_published_ibm_hardware_result_is_sealed_and_consistent(
    filename, execution_id
):
    result_path = (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "quantum-results"
        / filename
    )
    record = json.loads(result_path.read_text(encoding="utf-8"))

    evidence = QuantumExecutionEvidence.from_dict(record["evidence"])

    assert evidence.backend == "ibm_fez"
    assert evidence.execution_id == execution_id
    assert sum(evidence.counts.values()) == evidence.shots_observed == 128
    assert record["derived"]["same_bit_correlation"] == pytest.approx(
        (evidence.counts["00"] + evidence.counts["11"]) / evidence.shots_observed
    )


def test_transpiler_depth_attribution_covers_the_full_grid():
    result_path = (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "quantum-results"
        / "transpiler_depth_attribution.json"
    )
    record = json.loads(result_path.read_text(encoding="utf-8"))
    rows = record["results"]

    assert len(rows) == 6
    assert {
        (row["optimization_level"], row["requested_layout"])
        for row in rows
    } == {
        (level, layout)
        for level in (1, 3)
        for layout in ("[0,1]", "[146,147]", "auto")
    }
    for row in rows:
        expected_depth, expected_size = (
            (8, 12) if row["optimization_level"] == 1 else (7, 11)
        )
        assert row["seeds"] == 10
        assert row["depth_min"] == row["depth_median"] == row["depth_max"]
        assert row["depth_min"] == expected_depth
        assert row["size_min"] == row["size_max"] == expected_size
