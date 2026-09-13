import time

import pytest
from cryptography.fernet import Fernet

from pramagent.store import MemoryStore
from pramagent.store_s3 import S3ColdArchiveStore
from pramagent.types import TraceEvent


class _Body:
    def __init__(self, data):
        self._data = data

    def read(self):
        return self._data


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.puts = []
        self.deletes = []

    def put_object(self, **kwargs):
        key = (kwargs["Bucket"], kwargs["Key"])
        self.objects[key] = kwargs
        self.puts.append(kwargs)

    def get_object(self, Bucket, Key):
        return {"Body": _Body(self.objects[(Bucket, Key)]["Body"])}

    def list_objects_v2(self, Bucket, Prefix, **kwargs):
        contents = [{"Key": key} for (bucket, key) in self.objects
                    if bucket == Bucket and key.startswith(Prefix)]
        return {"Contents": contents, "IsTruncated": False}

    def delete_objects(self, Bucket, Delete):
        for item in Delete["Objects"]:
            self.objects.pop((Bucket, item["Key"]), None)
            self.deletes.append(item["Key"])
        return {}


def _trace(call_id, tenant, created_at):
    return TraceEvent(
        call_id=call_id,
        tenant_id=tenant,
        session_id="s1",
        created_at=created_at,
        input_text="hello",
        output_text="world",
        prev_hash="0" * 64,
        this_hash=f"{call_id:0<64}"[:64],
    )


def test_s3_archive_prune_encrypts_and_deletes_hot_trace():
    hot = MemoryStore()
    old = _trace("old", "tenant_a", time.time() - 1000)
    fresh = _trace("fresh", "tenant_a", time.time())
    hot.save(old)
    hot.save(fresh)
    s3 = FakeS3()
    archived = []
    store = S3ColdArchiveStore(
        hot,
        bucket="audit-bucket",
        s3_client=s3,
        encryption_key=Fernet.generate_key(),
        metadata_sink=archived.append,
    )

    deleted = store.prune_older_than(time.time() - 100)

    assert deleted == 1
    assert hot.get("fresh").call_id == "fresh"
    with pytest.raises(KeyError):
        hot.get("old")
    restored = store.get("old", tenant_id="tenant_a")
    assert restored.call_id == "old"
    assert restored.tenant_id == "tenant_a"
    assert archived[0].uri.startswith("s3://audit-bucket/pramagent/traces/")
    assert s3.puts[0]["Metadata"]["encrypted"] == "true"


def test_s3_erasure_destroys_and_never_archives():
    """GDPR erasure must NOT copy the data to cold storage first — archive-
    then-delete preserves the personal data indefinitely, the opposite of
    Art. 17 . prune_older_than keeps archiving (retention)."""
    hot = MemoryStore()
    hot.save(_trace("a1", "tenant_a", time.time()))
    hot.save(_trace("b1", "tenant_b", time.time()))
    s3 = FakeS3()
    store = S3ColdArchiveStore(
        hot,
        bucket="audit-bucket",
        s3_client=s3,
        encryption_key=Fernet.generate_key(),
    )

    deleted = store.delete_for_tenant("tenant_a")

    assert deleted == 1
    assert s3.puts == []                      # nothing was archived
    with pytest.raises(KeyError):
        store.get("a1", tenant_id="tenant_a")  # the data is GONE
    assert hot.get("b1").tenant_id == "tenant_b"
    assert store.archive_metadata() == []


def test_s3_erasure_deletes_previously_archived_objects():
    """Objects archived earlier (e.g. by retention) for the erased tenant are
    deleted from the bucket too — erasure reaches cold storage."""
    hot = MemoryStore()
    old_a = _trace("old-a", "tenant_a", time.time() - 1000)
    old_b = _trace("old-b", "tenant_b", time.time() - 1000)
    hot.save(old_a)
    hot.save(old_b)
    s3 = FakeS3()
    store = S3ColdArchiveStore(
        hot,
        bucket="audit-bucket",
        s3_client=s3,
        encryption_key=Fernet.generate_key(),
    )
    store.prune_older_than(time.time() - 100)          # archives both tenants
    assert len(s3.objects) == 2

    store.delete_for_tenant("tenant_a")

    remaining = [key for (_, key) in s3.objects]
    assert all("tenant=tenant_a/" not in key for key in remaining)
    assert any("tenant=tenant_b/" in key for key in remaining)
    with pytest.raises(KeyError):
        store.get("old-a", tenant_id="tenant_a")       # archive copy gone too
    assert store.get("old-b", tenant_id="tenant_b").call_id == "old-b"


def test_s3_archive_requires_encryption_key():
    with pytest.raises(ValueError):
        S3ColdArchiveStore(MemoryStore(), bucket="audit-bucket", s3_client=FakeS3())


@pytest.mark.parametrize("tenant_id", ["../victim", "victim/child", "", "tenant space"])
def test_s3_archive_rejects_unsafe_tenant_id(tenant_id):
    hot = MemoryStore()
    hot.save(_trace("unsafe", tenant_id, time.time() - 1000))
    store = S3ColdArchiveStore(
        hot,
        bucket="audit-bucket",
        s3_client=FakeS3(),
        encryption_key=Fernet.generate_key(),
    )

    with pytest.raises(ValueError, match="tenant_id"):
        store.prune_older_than(time.time())
