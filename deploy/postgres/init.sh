#!/bin/sh
# Pramagent bootstrap: creates a dedicated, non-superuser application role.
#
# Tables are created by PostgresStore on first connection (auto-DDL), which
# also enables + FORCES row-level tenant isolation on pramagent_traces. That
# policy is a no-op for a superuser or BYPASSRLS role — Postgres exempts them
# from row security unconditionally, FORCE included. POSTGRES_USER (the
# bootstrap user docker-compose creates from the postgres image's own
# entrypoint) is a superuser, so the app must connect as this separate role
# instead for the isolation policy to actually take effect.
#
# A .sh script (not .sql) so docker-entrypoint-initdb.d gives it the
# container's real environment — .sql files run through psql with no
# variable substitution.
set -e

: "${PRAMAGENT_APP_DB_PASSWORD:?PRAMAGENT_APP_DB_PASSWORD is required for the init script}"

psql \
  -v ON_ERROR_STOP=1 \
  --set=app_password="$PRAMAGENT_APP_DB_PASSWORD" \
  --set=db_name="$POSTGRES_DB" \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" <<-'EOSQL'
SELECT 'CREATE ROLE pramagent_app LOGIN'
WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'pramagent_app')
\gexec

ALTER ROLE pramagent_app WITH LOGIN PASSWORD :'app_password';

-- Least privilege: connect + create-in-schema only. PostgresStore's own DDL
-- (CREATE TABLE IF NOT EXISTS ...) makes pramagent_app the table owner, so
-- its later ALTER TABLE ... ROW LEVEL SECURITY / CREATE POLICY statements
-- succeed without any extra grant here.
GRANT CONNECT ON DATABASE :"db_name" TO pramagent_app;
GRANT USAGE, CREATE ON SCHEMA public TO pramagent_app;
EOSQL
