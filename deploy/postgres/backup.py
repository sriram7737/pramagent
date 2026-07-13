"""Scheduled Postgres backup: pg_dump -> gzip -> object storage.

Closes the "backup automation" gap the BACKUP_DR_RUNBOOK.md targets (RPO 15
minutes / RTO 4 hours) with a real, working mechanism instead of only the
documented obligation to "enable managed Postgres backups before production
traffic." Runs once per invocation; the backup service's entrypoint loops it
on PRAMAGENT_BACKUP_INTERVAL_S.

Uses pg_dump's custom format (-Fc): compressed, and restorable with parallel
pg_restore, which the restore drill (restore_verify.py) relies on.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

logging.basicConfig(level=os.environ.get("PRAMAGENT_LOG_LEVEL", "INFO").upper())
log = logging.getLogger("pramagent.backup")


class BackupError(RuntimeError):
    pass


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise BackupError(f"{name} is required")
    return value


def _s3_client():
    try:
        import boto3
    except ImportError as exc:
        raise BackupError(
            "boto3 is not installed; the backup image must include the "
            "'s3' extra"
        ) from exc
    return boto3.client("s3")


def _dsn_env(dsn: str) -> dict:
    """pg_dump reads connection info from libpq env vars, not argv, so the
    password never appears in a process listing."""
    parsed = urlparse(dsn)
    env = dict(os.environ)
    env["PGHOST"] = parsed.hostname or "localhost"
    env["PGPORT"] = str(parsed.port or 5432)
    env["PGUSER"] = parsed.username or ""
    env["PGPASSWORD"] = parsed.password or ""
    env["PGDATABASE"] = (parsed.path or "/").lstrip("/")
    return env


def run_backup() -> str:
    """Dump, upload, prune. Returns the uploaded object key."""
    dsn = _require_env("PRAMAGENT_POSTGRES_DSN")
    bucket = _require_env("PRAMAGENT_BACKUP_S3_BUCKET")
    prefix = os.environ.get("PRAMAGENT_BACKUP_S3_PREFIX", "pramagent/backups").strip("/")
    retention_days = int(os.environ.get("PRAMAGENT_BACKUP_RETENTION_DAYS", "30"))

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    key = f"{prefix}/pramagent-{stamp}.dump"

    with tempfile.NamedTemporaryFile(suffix=".dump", delete=False) as tmp:
        dump_path = tmp.name
    try:
        log.info("running pg_dump -> %s", dump_path)
        result = subprocess.run(
            ["pg_dump", "-Fc", "-f", dump_path],
            env=_dsn_env(dsn),
            capture_output=True,
            text=True,
            timeout=int(os.environ.get("PRAMAGENT_BACKUP_TIMEOUT_S", "3600")),
        )
        if result.returncode != 0:
            raise BackupError(f"pg_dump failed: {result.stderr[-2000:]}")

        size_bytes = os.path.getsize(dump_path)
        if size_bytes == 0:
            raise BackupError("pg_dump produced an empty file")

        s3 = _s3_client()
        extra_args = {"ServerSideEncryption": "AES256"}
        kms_key_id = os.environ.get("PRAMAGENT_BACKUP_KMS_KEY_ID", "").strip()
        if kms_key_id:
            extra_args = {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": kms_key_id}

        log.info("uploading %d bytes to s3://%s/%s", size_bytes, bucket, key)
        s3.upload_file(dump_path, bucket, key, ExtraArgs=extra_args)
    finally:
        try:
            os.remove(dump_path)
        except OSError:
            pass

    _prune_old_backups(bucket, prefix, retention_days)
    log.info("backup complete: s3://%s/%s", bucket, key)
    return key


def _prune_old_backups(bucket: str, prefix: str, retention_days: int) -> None:
    if retention_days <= 0:
        return
    s3 = _s3_client()
    cutoff = time.time() - retention_days * 86400
    paginator = s3.get_paginator("list_objects_v2")
    deleted = 0
    for page in paginator.paginate(Bucket=bucket, Prefix=f"{prefix}/"):
        for obj in page.get("Contents", []):
            if obj["LastModified"].timestamp() < cutoff:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
                deleted += 1
    if deleted:
        log.info("pruned %d backup(s) older than %d day(s)", deleted, retention_days)


def main() -> int:
    try:
        run_backup()
        return 0
    except BackupError as exc:
        log.error("backup failed: %s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
