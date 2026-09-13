"""
pramagent.store_s3
==================
S3 cold-archive wrapper for trace stores.

This module is intentionally a wrapper, not a replacement for Postgres/SQLite.
Hot reads and writes stay in the primary TraceStore; retention or erasure flows
archive selected traces to S3 as gzip-compressed encrypted JSON before removing
them from the primary store.
"""
from __future__ import annotations

import gzip
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .store import TraceStore
from .types import TraceEvent


class S3ArchiveError(RuntimeError):
    """Raised when S3 archive configuration or IO fails."""


@dataclass(frozen=True)
class ArchiveRecord:
    call_id: str
    tenant_id: str
    session_id: str
    created_at: float
    this_hash: str
    prev_hash: str
    archived_at: float
    bucket: str
    key: str
    encrypted: bool = True

    @property
    def uri(self) -> str:
        return f"s3://{self.bucket}/{self.key}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "call_id": self.call_id,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "created_at": self.created_at,
            "this_hash": self.this_hash,
            "prev_hash": self.prev_hash,
            "archived_at": self.archived_at,
            "bucket": self.bucket,
            "key": self.key,
            "uri": self.uri,
            "encrypted": self.encrypted,
        }


class S3ColdArchiveStore:
    """TraceStore-compatible cold archive wrapper.

    The wrapper preserves the TraceStore interface and adds ``archive_metadata``
    for compliance reports. ``metadata_sink`` can persist each ArchiveRecord to
    Postgres or another metadata table owned by the caller.
    """

    def __init__(
        self,
        primary: TraceStore,
        *,
        bucket: str,
        prefix: str = "pramagent/traces",
        s3_client: Optional[Any] = None,
        encryption_key: bytes | str | None = None,
        metadata_sink: Optional[Callable[[ArchiveRecord], None]] = None,
    ) -> None:
        if not bucket:
            raise ValueError("bucket is required")
        self.primary = primary
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.s3 = s3_client or self._load_s3_client()
        self._fernet = self._load_fernet(encryption_key)
        self._metadata_sink = metadata_sink
        self._metadata: dict[str, ArchiveRecord] = {}

    @staticmethod
    def _load_s3_client() -> Any:
        try:
            import boto3  # type: ignore
        except ImportError as exc:
            raise S3ArchiveError(
                "boto3 is not installed; install with: pip install 'pramagent[s3]'"
            ) from exc
        return boto3.client("s3")

    @staticmethod
    def _load_fernet(encryption_key: bytes | str | None) -> Any:
        key = encryption_key or os.environ.get("PRAMAGENT_ARCHIVE_KEY")
        if not key:
            raise ValueError(
                "S3 archive encryption key required: pass encryption_key= "
                "or set PRAMAGENT_ARCHIVE_KEY"
            )
        try:
            from cryptography.fernet import Fernet
        except ImportError as exc:
            raise S3ArchiveError(
                "cryptography is required for encrypted S3 archives; "
                "install with: pip install 'pramagent[s3]'"
            ) from exc
        return Fernet(key if isinstance(key, bytes) else key.encode())

    def save(self, trace: TraceEvent) -> None:
        self.primary.save(trace)

    def get(self, call_id: str, tenant_id: str | None = None) -> TraceEvent:
        try:
            return self.primary.get(call_id, tenant_id=tenant_id)
        except KeyError:
            record = self._metadata.get(call_id)
            if record is None:
                raise
            if tenant_id is not None and record.tenant_id != tenant_id:
                raise PermissionError(
                    f"archived trace {call_id} does not belong to tenant {tenant_id}"
                )
            return self._load_archived(record)

    def list_all(self, limit: int | None = None) -> list[TraceEvent]:
        items = list(self.primary.list_all(limit=limit))
        if limit is None:
            for record in self._metadata.values():
                items.append(self._load_archived(record))
        return items

    def prune_older_than(self, cutoff_ts: float, tenant_id: str | None = None) -> int:
        candidates = [
            trace for trace in self.primary.list_all()
            if trace.created_at < cutoff_ts
            and (tenant_id is None or trace.tenant_id == tenant_id)
        ]
        for trace in candidates:
            self._archive_trace(trace)
        return self.primary.prune_older_than(cutoff_ts, tenant_id=tenant_id)

    def delete_for_tenant(self, tenant_id: str) -> int:
        """GDPR erasure: destroy, never archive.

        Archive-then-delete is correct for prune_older_than (retention) but
        is the opposite of erasure — it would preserve the personal data in
        cold storage indefinitely. Erasure bypasses archival entirely and
        also deletes every object this bucket already holds under the
        tenant's prefix (covering archives written by other processes)."""
        self._validate_tenant_id(tenant_id)
        self._delete_archived_for_tenant(tenant_id)
        return self.primary.delete_for_tenant(tenant_id)

    def _delete_archived_for_tenant(self, tenant_id: str) -> int:
        """Remove all archived S3 objects under tenant={id}/ and drop their
        in-memory metadata. Returns the number of objects deleted."""
        prefix = f"{self.prefix}/tenant={tenant_id}/"
        deleted = 0
        token: Optional[str] = None
        while True:
            kwargs: dict[str, Any] = {"Bucket": self.bucket, "Prefix": prefix}
            if token:
                kwargs["ContinuationToken"] = token
            page = self.s3.list_objects_v2(**kwargs)
            keys = [{"Key": item["Key"]} for item in page.get("Contents", [])]
            if keys:
                self.s3.delete_objects(
                    Bucket=self.bucket, Delete={"Objects": keys, "Quiet": True})
                deleted += len(keys)
            if not page.get("IsTruncated"):
                break
            token = page.get("NextContinuationToken")
        for call_id, record in list(self._metadata.items()):
            if record.tenant_id == tenant_id:
                self._metadata.pop(call_id, None)
        return deleted

    def archive_metadata(self) -> list[dict[str, Any]]:
        return [record.to_dict() for record in self._metadata.values()]

    def _archive_trace(self, trace: TraceEvent) -> ArchiveRecord:
        record = self._record_for(trace)
        body = self._encode(trace)
        self.s3.put_object(
            Bucket=self.bucket,
            Key=record.key,
            Body=body,
            ContentType="application/json",
            ContentEncoding="gzip",
            Metadata={
                "call_id": trace.call_id,
                "tenant_id": trace.tenant_id,
                "session_id": trace.session_id,
                "this_hash": trace.this_hash,
                "prev_hash": trace.prev_hash,
                "encrypted": "true",
            },
        )
        self._metadata[trace.call_id] = record
        if self._metadata_sink is not None:
            self._metadata_sink(record)
        return record

    def _load_archived(self, record: ArchiveRecord) -> TraceEvent:
        obj = self.s3.get_object(Bucket=record.bucket, Key=record.key)
        body = obj["Body"].read()
        return TraceEvent.from_dict(json.loads(self._decode(body)))

    def _record_for(self, trace: TraceEvent) -> ArchiveRecord:
        self._validate_tenant_id(trace.tenant_id)
        day = time.strftime("%Y/%m/%d", time.gmtime(trace.created_at))
        key = (
            f"{self.prefix}/tenant={trace.tenant_id}/{day}/"
            f"{trace.call_id}.json.gz.fernet"
        )
        return ArchiveRecord(
            call_id=trace.call_id,
            tenant_id=trace.tenant_id,
            session_id=trace.session_id,
            created_at=trace.created_at,
            this_hash=trace.this_hash,
            prev_hash=trace.prev_hash,
            archived_at=time.time(),
            bucket=self.bucket,
            key=key,
        )

    @staticmethod
    def _validate_tenant_id(tenant_id: str) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", tenant_id or ""):
            raise ValueError(
                "tenant_id must be 1-128 ASCII letters, digits, dots, underscores, or hyphens"
            )

    def _encode(self, trace: TraceEvent) -> bytes:
        raw = json.dumps(trace.to_dict(), sort_keys=True).encode("utf-8")
        compressed = gzip.compress(raw)
        return self._fernet.encrypt(compressed)

    def _decode(self, body: bytes) -> str:
        compressed = self._fernet.decrypt(body)
        return gzip.decompress(compressed).decode("utf-8")
