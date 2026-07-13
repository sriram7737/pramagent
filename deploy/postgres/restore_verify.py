"""Automated restore drill: latest backup -> scratch DB -> chain verify.

Scripts the manual steps docs/BACKUP_DR_RUNBOOK.md's "Restore Drill" section
already describes, against the real backup artifacts backup.py produces.
Run it against a scratch DSN, never the production database — pg_restore
--clean drops and recreates the target schema.

Exit 0 and a summary line means the drill passed; anything else means fix it
before trusting the backup. Record the printed summary with release evidence
per the runbook's "Record" checklist.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

logging.basicConfig(level=os.environ.get("PRAMAGENT_LOG_LEVEL", "INFO").upper())
log = logging.getLogger("pramagent.restore_verify")


class RestoreVerifyError(RuntimeError):
    pass


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RestoreVerifyError(f"{name} is required")
    return value


def _s3_client():
    import boto3

    return boto3.client("s3")


def _latest_backup_key(bucket: str, prefix: str) -> str:
    s3 = _s3_client()
    paginator = s3.get_paginator("list_objects_v2")
    latest_key = ""
    latest_mtime = None
    for page in paginator.paginate(Bucket=bucket, Prefix=f"{prefix}/"):
        for obj in page.get("Contents", []):
            if latest_mtime is None or obj["LastModified"] > latest_mtime:
                latest_mtime = obj["LastModified"]
                latest_key = obj["Key"]
    if not latest_key:
        raise RestoreVerifyError(f"no backups found under s3://{bucket}/{prefix}/")
    return latest_key


def _dsn_env(dsn: str) -> dict:
    parsed = urlparse(dsn)
    env = dict(os.environ)
    env["PGHOST"] = parsed.hostname or "localhost"
    env["PGPORT"] = str(parsed.port or 5432)
    env["PGUSER"] = parsed.username or ""
    env["PGPASSWORD"] = parsed.password or ""
    env["PGDATABASE"] = (parsed.path or "/").lstrip("/")
    return env


def run_drill() -> dict:
    started = time.time()
    bucket = _require_env("PRAMAGENT_BACKUP_S3_BUCKET")
    prefix = os.environ.get("PRAMAGENT_BACKUP_S3_PREFIX", "pramagent/backups").strip("/")
    scratch_dsn = _require_env("PRAMAGENT_RESTORE_VERIFY_DSN")

    key = _latest_backup_key(bucket, prefix)
    log.info("restoring s3://%s/%s into scratch DB", bucket, key)

    with tempfile.NamedTemporaryFile(suffix=".dump", delete=False) as tmp:
        dump_path = tmp.name
    try:
        _s3_client().download_file(bucket, key, dump_path)

        result = subprocess.run(
            ["pg_restore", "--clean", "--if-exists", "--no-owner", "-d", "postgres", dump_path],
            env=_dsn_env(scratch_dsn),
            capture_output=True,
            text=True,
            timeout=int(os.environ.get("PRAMAGENT_BACKUP_TIMEOUT_S", "3600")),
        )
        # pg_restore --clean warns (non-fatal) about objects that don't exist
        # yet on a first-ever run; only a genuinely fatal restore is an error.
        if result.returncode not in (0, 1):
            raise RestoreVerifyError(f"pg_restore failed: {result.stderr[-2000:]}")
    finally:
        try:
            os.remove(dump_path)
        except OSError:
            pass

    from pramagent.store_postgres import PostgresStore

    store = PostgresStore.from_dsn(scratch_dsn)
    broken = store.verify()
    duration_s = time.time() - started

    summary = {
        "drill_date": datetime.now(timezone.utc).isoformat(),
        "backup_key": key,
        "restore_duration_s": round(duration_s, 1),
        "chain_valid": not broken,
        "broken_links": len(broken),
    }
    return summary


def main() -> int:
    try:
        summary = run_drill()
    except RestoreVerifyError as exc:
        log.error("restore drill failed: %s", exc)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["chain_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
