# Backup And Disaster Recovery Runbook

This runbook defines the minimum production backup posture for Pramagent
deployments that store tenant traces, audit chains, HITL queues, or API keys.

## Targets

| System | RPO | RTO | Notes |
| --- | ---: | ---: | --- |
| Postgres trace/audit store | 15 minutes | 4 hours | Managed PITR or WAL archiving required |
| SQLite demo/local store | 24 hours | 8 hours | Only acceptable for non-PHI, non-enterprise demos |
| S3 cold archive | 24 hours | 8 hours | Bucket versioning and server-side encryption required |
| API key registry | 15 minutes | 4 hours | Same Postgres backup plan as trace store |

## Required Controls

1. Enable managed Postgres backups/PITR before production traffic, **or**
   enable the self-hosted backup automation below if you're running the
   docker-compose Postgres service rather than a managed one.
2. Store backups encrypted with cloud KMS or equivalent.
3. Restrict restore permissions to a migration/operator role, not the runtime
   app role.
4. Keep backup configuration and last restore-drill evidence with release
   evidence.
5. Never use volatile `MemoryStore` for production or PHI mode.

## Self-Hosted Backup Automation (docker-compose Postgres)

If you're using the docker-compose `postgres` service (self-hosted, not a
managed cloud database), there is no backup mechanism unless you enable it —
`docker compose up` alone does not back anything up. A scheduled `pg_dump` ->
object-storage job ships as an opt-in profile:

```bash
# .env: set PRAMAGENT_BACKUP_S3_BUCKET, AWS credentials, and (optionally)
# PRAMAGENT_BACKUP_S3_PREFIX / PRAMAGENT_BACKUP_RETENTION_DAYS / PRAMAGENT_BACKUP_INTERVAL_S
docker compose --profile backup up -d backup
```

This runs `deploy/postgres/backup.py` on a loop (`PRAMAGENT_BACKUP_INTERVAL_S`,
default hourly): `pg_dump -Fc` the database, upload it SSE-encrypted to
`s3://$PRAMAGENT_BACKUP_S3_BUCKET/$PRAMAGENT_BACKUP_S3_PREFIX/`, then prune
objects older than `PRAMAGENT_BACKUP_RETENTION_DAYS`. It connects as the same
`pramagent_app` role the API uses (see `deploy/postgres/init.sh`), not the
Postgres superuser.

If you're on a managed Postgres (RDS, Cloud SQL, etc.) instead, use its native
backup/PITR feature — `backup.py` is only for the self-hosted compose path.

## Restore Drill

Run at least quarterly and before enterprise security review. Point
`PRAMAGENT_RESTORE_VERIFY_DSN` at a scratch database, never production —
`pg_restore --clean` drops the target schema first.

```bash
export PRAMAGENT_BACKUP_S3_BUCKET="..."
export PRAMAGENT_RESTORE_VERIFY_DSN="postgresql://.../pramagent_restore_scratch"
python deploy/postgres/restore_verify.py
```

This downloads the newest backup, restores it into the scratch database, runs
the same chain-verification `PostgresStore.verify()` uses, and prints a JSON
summary (`drill_date`, `backup_key`, `restore_duration_s`, `chain_valid`,
`broken_links`) — exits non-zero if the chain is broken. Record that summary
with release evidence.

Manual equivalent, if you're restoring from a managed-Postgres snapshot
instead of an S3 backup produced by `backup.py`:

```bash
# 1. Restore latest backup into an isolated database.
export PRAMAGENT_POSTGRES_DSN="postgresql://..."

# 2. Verify DB connectivity and schema.
pramagent validate

# 3. Verify audit-chain integrity after restore.
python - <<'PY'
from pramagent.store_postgres import PostgresStore
import os

store = PostgresStore.from_dsn(os.environ["PRAMAGENT_POSTGRES_DSN"])
broken = store.verify()
raise SystemExit(1 if broken else 0)
PY
```

Record:

- Drill date
- Backup timestamp restored
- Restore duration
- Audit-chain verification result
- Data owner approval
- Follow-up fixes

## Tenant Erasure And Backups

Tenant erasure deletes hot trace rows and tombstones audit-chain payload fields.
Backups may still contain pre-erasure content until backup retention expires.
For GDPR/HIPAA-sensitive tenants, document the backup-retention window in the
customer data processing terms and avoid restoring erased tenant data into
production without legal/privacy approval.

## Failure Procedure

If the primary DB is unavailable:

1. Mark the API degraded by failing readiness checks.
2. Stop writes or route to a hot standby if available.
3. Restore to a new primary from the newest verified backup/PITR point.
4. Run audit-chain verification.
5. Rotate credentials exposed during failover.
6. Publish an incident timeline if RTO/RPO is missed.
