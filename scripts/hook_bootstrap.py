#!/usr/bin/env python3
"""Run a hook child process and convert startup failures into a denial."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import subprocess
import sys
from pathlib import Path


MAX_EVENT_BYTES = 4 * 1024 * 1024


def _deny(host: str, reason: str) -> dict:
    if host == "gemini":
        return {"decision": "deny", "reason": reason}
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
        "additionalContext": reason,
    }


def _emit(payload: dict) -> int:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")))
    sys.stdout.write("\n")
    return 0


def _verify_child(script: Path) -> None:
    """Refuse to launch a child that differs from the reviewed manifest."""
    repo_root = Path(__file__).resolve().parents[1]
    manifest_path = repo_root / "pramagent" / "hook_integrity.json"
    relative = script.relative_to(repo_root).as_posix()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = (manifest.get("files") or {}).get(relative, "")
    if not expected:
        raise RuntimeError("hook child is not listed in the integrity manifest")
    # Windows and Unix use different harmless line endings in source checkouts.
    # Hash a canonical text representation so the approved manifest is portable.
    actual = hashlib.sha256(script.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    if not hmac.compare_digest(expected, actual):
        raise RuntimeError("hook child hash does not match the integrity manifest")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", choices=("pretool", "gemini"), required=True)
    parser.add_argument("--script", required=True)
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    raw = sys.stdin.buffer.read(MAX_EVENT_BYTES + 1)
    if len(raw) > MAX_EVENT_BYTES:
        return _emit(_deny(args.host, "Pramagent hook rejected an oversized event."))

    script = Path(args.script).expanduser().resolve()
    try:
        _verify_child(script)
        completed = subprocess.run(
            [sys.executable, str(script)],
            input=raw,
            capture_output=True,
            timeout=args.timeout,
            check=False,
        )
        output = json.loads(completed.stdout.decode("utf-8"))
        if completed.returncode != 0 or not isinstance(output, dict):
            raise RuntimeError(f"hook exited with status {completed.returncode}")
    except Exception as exc:
        reason = f"Pramagent hook failed closed before evaluation: {type(exc).__name__}."
        return _emit(_deny(args.host, reason))
    return _emit(output)


if __name__ == "__main__":
    raise SystemExit(main())
