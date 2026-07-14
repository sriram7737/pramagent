# Incident Response Runbook

This is an operator runbook for Pramagent security incidents. It is not a legal
notice template and does not by itself satisfy SOC 2 or HIPAA obligations, but
it gives the on-call team a concrete response path.

## Severity

| Severity | Trigger | Target response |
| --- | --- | --- |
| SEV-1 | Confirmed cross-tenant exposure, PHI/secret leak, compromised signing key, or audit-chain tamper evidence | Page immediately; contain within 1 hour |
| SEV-2 | Suspected auth bypass, dependency exploit exposure, failed external anchoring, or repeated policy-bypass attempts | Triage within 4 hours |
| SEV-3 | Scanner finding, failed backup drill, non-sensitive telemetry issue | Triage next business day |

## Detection

Audit-chain tamper detection is automated, not just a human-triggered check:

- `pramagent audit-verify-watch` runs `store.verify()` and alerts to
  `PRAMAGENT_AUDIT_ALERT_WEBHOOK_URL` on any broken link. Run it from an
  external scheduler (cron, k8s CronJob) or as the opt-in docker-compose
  `audit-watch` profile (`docker compose --profile audit-watch up -d`),
  which checks on a loop (`PRAMAGENT_AUDIT_WATCH_INTERVAL_S`, default 15
  minutes).
- A tamper alert fires this runbook at SEV-1 — treat it as evidence a
  privileged Postgres credential was used to rewrite chain history (see
  `pramagent_chain_append_only_guard_trigger` in `store_postgres.py`), not
  just a false positive to dismiss.
- Manual check for any specific tenant/incident: `GET /v1/audit/verify`
  (accepts a `read` or `audit`-scoped key — issue an `audit`-only key to
  monitoring integrations instead of a full read-scoped key).
- Everything else (auth-failure spikes, unusual traffic patterns) is still
  manual/log-review based — there is no SIEM integration.

**Detection limit — know what tamper-alert silence does and does not mean.**
`verify_chain()` recomputes the hash chain from the payloads stored in the
same database it protects. If `PRAMAGENT_SIGNING_KEY` is NOT configured, an
attacker with raw database write access can edit a record and recompute
every hash after it forward — `verify_chain()` will report `True` and no
alert will ever fire, because the hash function and its inputs are both
public. If a signing key IS configured, that specific forgery requires the
key too — but an attacker who also has the application's runtime secrets
(and therefore the key) can still do it. Either way, a clean `verify_chain()`
result is not proof against a privileged-database-access incident by
itself. Corroborate with the database provider's own connection and
activity history and with infrastructure-level access logs, not the chain
alone. External anchoring (`EthereumBackend` / `HyperledgerBackend`) closes
this gap by publishing the chain head somewhere outside the database's own
trust boundary. Treat a missing external anchor as a standing gap in
tamper-detection coverage for this deployment, not a reason to trust
chain-only evidence more than it can support.

## On-Call Roster And Escalation

**Interim roster:** Sriram Rampelli is the creator and current accountable
incident owner. Contact is email-only until a production paging/phone path is
created. Before citing production incident-response readiness, replace this
interim roster with a real primary/secondary rotation and paging channel.

| Role | Name | Contact | Escalates to (if unreachable in 15 min) |
| --- | --- | --- | --- |
| Incident commander (primary) | Sriram Rampelli, creator | Email only: sriramrampelli@gmail.com | No secondary yet; email Sriram Rampelli |
| Incident commander (secondary) | Sriram Rampelli, creator | Email only: sriramrampelli@gmail.com | No secondary yet; email Sriram Rampelli |
| Scribe | Sriram Rampelli, creator | Email only: sriramrampelli@gmail.com | No secondary yet; email Sriram Rampelli |
| Data/privacy owner (PHI/GDPR calls) | Sriram Rampelli, creator | Email only: sriramrampelli@gmail.com | No secondary yet; email Sriram Rampelli |
| Infra/on-call (Postgres, Redis, deploy) | Sriram Rampelli, creator | Email only: sriramrampelli@gmail.com | No secondary yet; email Sriram Rampelli |

Paging channel: email-only for now, sriramrampelli@gmail.com. No phone or
PagerDuty/Opsgenie rotation is configured yet.

Automated signals with nowhere to page yet: `pramagent audit-verify-watch`
posts to `PRAMAGENT_AUDIT_ALERT_WEBHOOK_URL` on tamper detection. Point that
at a real paging integration's webhook once paging exists.

## First 30 Minutes

1. Assign an incident commander and scribe (see roster above).
2. Freeze risky deploys unless the deploy is needed for containment.
3. Preserve evidence: request IDs, trace IDs, audit-chain head, deployment SHA,
   environment variables inventory, and relevant application logs.
4. If auth/secrets are implicated, rotate `PRAMAGENT_JWT_SECRETS`,
   `PRAMAGENT_API_KEYS`/registry keys, provider API keys, and database
   credentials.
5. If tenant isolation is implicated, disable public write routes at the edge
   or set maintenance mode at the proxy until scoped reads are verified.

## Containment Checklist

- Verify `/v1/audit/verify` for affected tenants.
- Export affected tenant evidence with the store export tooling before erasure:

```bash
pramagent audit-export --tenant-id <tenant_id> --out incident-evidence.jsonl
```

  Requires a Postgres-backed store (`PRAMAGENT_POSTGRES_DSN`) — SQLite and
  encrypted-SQLite stores don't implement bulk export yet.

  **Correlating an exported trace to who approved it or which key called
  it is a three-way join, not a single-table lookup:** `TraceEvent` (what
  the export contains) has no `actor`/`approver` field of its own. To
  answer "who approved this" join the exported `call_id` against the HITL
  approval queue's `decided_by` field; to answer "which key made this
  call" join the tenant/timestamp against `pramagent_api_key_audit`
  (issuance/revocation events, not per-call attribution — API keys map to
  a tenant, not to an individual call). Do this join manually during an
  incident until this gap is closed with a dedicated field.
- Revoke compromised API keys with:

```bash
pramagent auth-revoke <api_key> --actor incident-commander
```

  This command has two working backends and one hard failure mode,
  depending on how this deployment issues keys:
  - `PRAMAGENT_API_KEY_DSN` set (Postgres-backed registry): revokes
    immediately and durably in the database.
  - `PRAMAGENT_API_KEY_DSN` unset but `PRAMAGENT_API_KEY_REVOCATION_FILE`
    set (the simpler `PRAMAGENT_API_KEYS=tenant:key,...` env-var mode):
    appends the key's hash to that file. A running API process picks this
    up on its next auth check (no restart needed) because the registry
    reloads the file on mtime change.
  - Neither set: the command fails with an actionable error. The only
    real fallback in that configuration is to remove the compromised key
    from `PRAMAGENT_API_KEYS` and redeploy/restart every API process —
    do this immediately rather than treating the CLI failure as "done."

- Rotate JWT signing keys by adding a new `kid:secret` to
  `PRAMAGENT_JWT_SECRETS`, setting `PRAMAGENT_JWT_ACTIVE_KID`, deploying, then
  retiring the old `kid` after active tokens expire.
- If PHI may be involved, treat the event as potential ePHI exposure until the
  privacy/security owner documents otherwise.

## Eradication And Recovery

1. Patch or disable the vulnerable route/configuration.
2. Redeploy from a known-good commit.
3. Run targeted tests for the failed control area.
4. Re-run dependency audit and security-header scan where relevant.
5. Restore data only from backups that predate compromise and pass integrity
   verification.

## Customer And Regulatory Review

The incident commander owns factual timeline collection. Legal/privacy owners
decide external notices, including HIPAA breach notification analysis when PHI
or ePHI may have been stored, processed, or transmitted.

Record:

- Incident ID
- Affected tenant IDs
- Data classes involved
- Exposure window
- Containment time
- Customer/regulatory notification decision
- Follow-up owner and due date

## Post-Incident

Within five business days, publish an internal postmortem with root cause,
blast radius, missed detections, permanent fixes, and evidence that fixes were
tested.
