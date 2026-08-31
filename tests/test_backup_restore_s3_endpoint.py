import importlib
import sys
import types


def _fake_boto3(monkeypatch):
    calls = []

    def client(service, **kwargs):
        calls.append({"service": service, **kwargs})
        return object()

    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=client))
    return calls


def test_backup_s3_client_uses_aws_endpoint_url(monkeypatch):
    calls = _fake_boto3(monkeypatch)
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://localhost:4566")
    backup = importlib.import_module("deploy.postgres.backup")

    backup._s3_client()

    assert calls == [{"service": "s3", "endpoint_url": "http://localhost:4566"}]


def test_backup_s3_client_keeps_default_endpoint_when_unset(monkeypatch):
    calls = _fake_boto3(monkeypatch)
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    backup = importlib.import_module("deploy.postgres.backup")

    backup._s3_client()

    assert calls == [{"service": "s3", "endpoint_url": None}]


def test_restore_s3_client_uses_aws_endpoint_url(monkeypatch):
    calls = _fake_boto3(monkeypatch)
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://localhost:4566")
    restore_verify = importlib.import_module("deploy.postgres.restore_verify")

    restore_verify._s3_client()

    assert calls == [{"service": "s3", "endpoint_url": "http://localhost:4566"}]


def test_restore_uses_database_from_scratch_dsn():
    restore_verify = importlib.import_module("deploy.postgres.restore_verify")

    assert (
        restore_verify._dsn_database(
            "postgresql://restore:pass@postgres:5432/pramagent_restore"
        )
        == "pramagent_restore"
    )


def test_backup_prefers_backup_postgres_dsn(monkeypatch, tmp_path):
    seen = {}
    dump_path = tmp_path / "backup.dump"

    class FakeResult:
        returncode = 0
        stderr = ""

    class FakeS3:
        def upload_file(self, path, bucket, key, ExtraArgs=None):
            seen["upload"] = (path, bucket, key, ExtraArgs)

        def get_paginator(self, _name):
            class Paginator:
                def paginate(self, **_kwargs):
                    return []

            return Paginator()

    def fake_run(_cmd, *, env, **_kwargs):
        seen["pguser"] = env["PGUSER"]
        seen["pgdatabase"] = env["PGDATABASE"]
        dump_path.write_bytes(b"dump")
        return FakeResult()

    class FakeTemp:
        name = str(dump_path)

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    backup = importlib.import_module("deploy.postgres.backup")
    monkeypatch.setenv(
        "PRAMAGENT_POSTGRES_DSN",
        "postgresql://app:app-pass@postgres:5432/pramagent",
    )
    monkeypatch.setenv(
        "PRAMAGENT_BACKUP_POSTGRES_DSN",
        "postgresql://backup:backup-pass@postgres:5432/pramagent",
    )
    monkeypatch.setenv("PRAMAGENT_BACKUP_S3_BUCKET", "bucket")
    monkeypatch.setenv("PRAMAGENT_BACKUP_RETENTION_DAYS", "0")
    monkeypatch.setattr(backup.subprocess, "run", fake_run)
    monkeypatch.setattr(backup.tempfile, "NamedTemporaryFile", lambda **_kwargs: FakeTemp())
    monkeypatch.setattr(backup, "_s3_client", lambda: FakeS3())

    key = backup.run_backup()

    assert seen["pguser"] == "backup"
    assert seen["pgdatabase"] == "pramagent"
    assert seen["upload"][1] == "bucket"
    assert key.startswith("pramagent/backups/pramagent-")
