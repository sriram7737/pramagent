# Pramagent - Control Mapping (SOC 2 / HIPAA / EU AI Act)

This maps Pramagent's implemented controls to common framework expectations.
It is an engineering self-assessment to accelerate an auditor's review - **not**
a certification. Independent audit is required for any compliance claim.

## EU AI Act (high-risk systems)
| Article | Expectation | Pramagent control |
|---|---|---|
| Art. 12 | Automatic record-keeping / logging | Hash-chained immutable trace per call; 180-day retention floor enforced |
| Art. 13 | Transparency | Full trace + RCA replay/incident report per decision |
| Art. 14 | Human oversight | HITLLayer: propose-and-wait, idle-on-silence, escalation, quorum |
| Art. 15 | Accuracy/robustness/security | ToolGuard schema validation, injection defense, circuit breakers |

## HIPAA Security Rule
| Safeguard | Citation | Pramagent control |
|---|---|---|
| Access control | 164.312(a)(1) | API-key + JWT auth, per-tenant isolation, cross-tenant trace guard |
| Audit controls | 164.312(b) | Tamper-evident hash chain + approval audit log |
| Integrity | 164.312(c)(1) | SHA-256 chain verification detects any retroactive edit |
| Transmission security | 164.312(e)(1) | TLS/HSTS headers; encrypted-at-rest SQLite option |
| Minimum necessary | 164.502(b) | PII scrubbing before model exposure |

## SOC 2 (Trust Services Criteria)
| TSC | Pramagent control |
|---|---|
| CC6 (Logical access) | Auth, tenant isolation, rate limiting |
| CC7 (System operations) | OTel tracing, structured logs, health/readiness probes, circuit breakers |
| CC8 (Change management) | Schema migration runner with recorded versions |
| A1 (Availability) | Graceful degradation (Redis/Postgres fail-open to local), retries |
| C1 (Confidentiality) | PII scrubbing, output exfiltration scanning, encrypted store |
| P-series (Privacy) | Consent registry, purpose limitation, retention policy, GDPR erasure endpoint |

## NIST AI RMF 1.0 self-assessment

This is a self-assessment against the NIST AI Risk Management Framework
functions. It is not a certification, and it does not replace external
red-team or penetration-test evidence.

| Function | Intent | Pramagent control | Evidence / gap |
|---|---|---|---|
| GOVERN | Establish AI risk policies, accountability, and oversight | Alpha status, hardening guide, implementation-status matrix, explicit "not production certified" language, approval roles for HITL/dashboard | Evidence exists in docs; enterprise SSO/RBAC and external policy review remain gaps |
| MAP | Identify context, stakeholders, data flows, and risk surfaces | Tenant IDs, session IDs, ToolGuard side-effect taxonomy, provider adapters, trace/RCA data model | Data-flow diagrams and live workflow docs exist; customer-specific risk assessments still required |
| MEASURE | Analyze, test, and monitor AI risks | Red-team benchmark, dynamic prompt tests, load tests, ZAP/Bandit/Semgrep scans, OTel metrics, audit verification | Security scans now run locally and are wired in CI; third-party red-team and pen-test still required |
| MANAGE | Prioritize, respond to, and monitor mitigations | Deterministic ToolGuard policy, isolation layer, HITL escalation, rate limits, quotas, circuit breakers, retention/erasure endpoints | Controls are implemented for developer beta; enterprise runbooks, SSO, persistent billing ledger, and formal incident process remain roadmap |

## Agent-security conformance

`docs/CONFORMANCE.md` maps the same implementation to Google DeepMind
individual-agent control vocabulary and the AWS Agentic AI Security Scoping
Matrix. New traces include `aws_scope`, `detection_tier`, `response_tier`,
`attack_techniques`, and `conformance_metrics`. Runtime traces report coverage
and time-to-response; seeded red-team runs report recall.

## Auditor-facing artifacts
- `ComplianceReporter.generate()` - point-in-time JSON/text/PDF-style evidence
  package across SOC2, HIPAA, GDPR, NIST AI RMF, EU AI Act, and PCI DSS
- `GET /v1/audit/verify` - live hash-chain validity
- `POST /v1/rca/{id}/incident` - per-decision incident report
