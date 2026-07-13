-- Pramagent optional additional hardening migration.
--
-- Row-level tenant isolation on pramagent_traces (ENABLE + FORCE ROW LEVEL
-- SECURITY, and the pramagent_trace_tenant_isolation policy) is no longer
-- opt-in — PostgresStore's own DDL (_DDL_TRACES in store_postgres.py)
-- applies it on every startup, against whatever role the app's DSN
-- connects as. deploy/postgres/init.sh creates that role (pramagent_app) as
-- a plain, non-superuser LOGIN role so the policy actually has teeth:
-- Postgres superusers and BYPASSRLS roles bypass row security
-- unconditionally, FORCE included, so a superuser DSN would make the policy
-- a silent no-op no matter what this file does.
--
-- pramagent_chain's append-only guarantee (no DELETE, ever; UPDATE only via
-- the GDPR redaction path) is likewise no longer opt-in — it's a BEFORE
-- UPDATE/DELETE trigger in the default DDL (pramagent_chain_append_only_guard),
-- not a GRANT omission. GRANT/REVOKE alone was the pre-existing (and
-- insufficient) mechanism: REVOKE does work against a table's own owner in
-- Postgres, but relying only on "never GRANT DELETE" is one careless
-- `GRANT ALL` away from silently regressing. The trigger fires regardless of
-- ownership or grants, so it holds even if this file is never run.
--
-- What remains here is strictly additional lockdown for deployments that
-- want a stricter migration-time-vs-runtime split: run this once, after
-- init.sh and the app's first successful DDL run, to drop pramagent_app's
-- CREATE privilege on the schema (it only needs it once, to create the
-- tables it now owns) and pin its table grants down to exactly what the
-- running app issues.

BEGIN;

-- The runtime role should read/write existing objects, not create arbitrary
-- objects in public once the app's own DDL has run at least once.
REVOKE CREATE ON SCHEMA public FROM pramagent_app;

GRANT USAGE ON SCHEMA public TO pramagent_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON pramagent_traces TO pramagent_app;
GRANT SELECT, INSERT, UPDATE ON pramagent_chain TO pramagent_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO pramagent_app;

COMMIT;
