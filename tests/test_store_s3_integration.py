"""Integration test: S3ColdArchiveStore against a REAL S3 API.

Unlike test_store_s3.py (in-memory FakeS3), this exercises the real boto3
request/response path — the part a hand-rolled fake cannot cover. It is opt-in:
set PRAMAGENT_S3_ENDPOINT to an S3-compatible endpoint and it runs; otherwise it
skips, so normal CI is unaffected.

Run against Floci (local AWS emulator):

    docker run -d --name floci -p 4566:4566 floci/floci:latest
    PRAMAGENT_S3_ENDPOINT=http://localhost:4566 python -m pytest tests/test_store_s3_integration.py -q

Or against real AWS by setting PRAMAGENT_S3_ENDPOINT to "" is NOT enough — point
it at a reachable endpoint (LocalStack/Floci/S3) and provide credentials via the
usual AWS env vars; the dummy test credentials below suit local emulators.
"""
import os
import time

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.config import Config  # noqa: E402
from cryptography.fernet import Fernet  # noqa: E402

from pramagent.store import MemoryStore  # noqa: E402
from pramagent.store_s3 import S3ColdArchiveStore  # noqa: E402
from pramagent.types import TraceEvent  # noqa: E402

_ENDPOINT = os.environ.get("PRAMAGENT_S3_ENDPOINT")

pytestmark = pytest.mark.skipif(
    not _ENDPOINT,
    reason="set PRAMAGENT_S3_ENDPOINT (e.g. http://localhost:4566 for Floci) to run",
)


@pytest.fixture
def s3_client():
    return boto3.client(
        "s3", endpoint_url=_ENDPOINT, region_name="us-east-1",
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
        config=Config(retries={"max_attempts": 2}, connect_timeout=5, read_timeout=15),
    )


@pytest.fixture
def bucket(s3_client):
    name = f"pramagent-it-{int(time.time() * 1000)}"
    s3_client.create_bucket(Bucket=name)
    yield name
    try:  # best-effort teardown
        objs = s3_client.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            s3_client.delete_objects(
                Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3_client.delete_bucket(Bucket=name)
    except Exception:
        pass


def _trace(call_id, tenant, created_at):
    return TraceEvent(
        call_id=call_id, tenant_id=tenant, session_id="s1", created_at=created_at,
        input_text="hello-" + call_id, output_text="world",
        prev_hash="0" * 64, this_hash=f"{call_id:0<64}"[:64],
    )


def _store(s3_client, bucket):
    return S3ColdArchiveStore(
        MemoryStore(), bucket=bucket, s3_client=s3_client,
        encryption_key=Fernet.generate_key(),
    )


def test_prune_archives_encrypted_and_roundtrips(s3_client, bucket):
    store = _store(s3_client, bucket)
    now = time.time()
    store.save(_trace("it_old", "tenant_a", now - 10_000))
    store.save(_trace("it_new", "tenant_a", now))

    archived = store.prune_older_than(now - 5_000)               # put_object
    assert archived >= 1

    keys = [o["Key"] for o in s3_client.list_objects_v2(
        Bucket=bucket, Prefix="pramagent/traces/").get("Contents", [])]
    assert len(keys) == 1

    raw = s3_client.get_object(Bucket=bucket, Key=keys[0])["Body"].read()
    assert b"hello-it_old" not in raw and b"world" not in raw    # encrypted at rest

    got = store.get("it_old", tenant_id="tenant_a")              # S3 read + decrypt
    assert got.call_id == "it_old"
    assert got.input_text == "hello-it_old"


def test_cross_tenant_archived_read_is_blocked(s3_client, bucket):
    store = _store(s3_client, bucket)
    now = time.time()
    store.save(_trace("it_x", "tenant_a", now - 10_000))
    store.prune_older_than(now - 5_000)

    with pytest.raises(PermissionError):
        store.get("it_x", tenant_id="tenant_b")


def test_gdpr_erasure_deletes_archived_objects(s3_client, bucket):
    store = _store(s3_client, bucket)
    now = time.time()
    store.save(_trace("it_e", "tenant_a", now - 10_000))
    store.prune_older_than(now - 5_000)

    store.delete_for_tenant("tenant_a")                          # list + delete_objects

    remaining = s3_client.list_objects_v2(
        Bucket=bucket, Prefix="pramagent/traces/").get("Contents", [])
    assert len(remaining) == 0
