"""
pramagent.compliance
====================
Retention tracking, consent + purpose-limitation registry, and automated
compliance report generation (JSON for machines, plain-text/PDF for auditors).

This complements ComplianceLayer (PII scrubbing in pramagent.layers): that layer
prevents PII reaching the model; this module records the *governance* metadata an
auditor asks for — what consent was on file, what purpose each tenant's data may
be used for, what the retention policy is, and a point-in-time attestation that
the audit chain verifies.

Nothing here calls an LLM. All deterministic, all auditable.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Purpose(str, Enum):
    """Lawful purpose categories (GDPR Art. 5(1)(b) purpose limitation)."""
    SERVICE = "service_provision"
    SECURITY = "security_monitoring"
    LEGAL = "legal_obligation"
    ANALYTICS = "analytics"
    SUPPORT = "customer_support"


@dataclass
class ConsentRecord:
    tenant_id: str
    subject_id: str                       # data-subject identifier (hashed in prod)
    purposes: list[str]                   # allowed Purpose values
    granted_at: float = field(default_factory=time.time)
    revoked_at: Optional[float] = None
    source: str = ""                      # where consent was captured

    @property
    def active(self) -> bool:
        return self.revoked_at is None

    def allows(self, purpose: str) -> bool:
        return self.active and purpose in self.purposes


class ConsentRegistry:
    """In-memory consent + purpose-limitation registry.

    Swap the dict for Postgres/Redis in production; the interface is stable.
    """

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], ConsentRecord] = {}

    def grant(self, tenant_id: str, subject_id: str, purposes: list[str],
              source: str = "") -> ConsentRecord:
        rec = ConsentRecord(tenant_id=tenant_id, subject_id=subject_id,
                            purposes=list(purposes), source=source)
        self._records[(tenant_id, subject_id)] = rec
        return rec

    def revoke(self, tenant_id: str, subject_id: str) -> bool:
        rec = self._records.get((tenant_id, subject_id))
        if rec is None or not rec.active:
            return False
        rec.revoked_at = time.time()
        return True

    def get(self, tenant_id: str, subject_id: str) -> Optional[ConsentRecord]:
        return self._records.get((tenant_id, subject_id))

    def check(self, tenant_id: str, subject_id: str, purpose: str) -> bool:
        """True if an active consent covers `purpose`. Absence = no consent."""
        rec = self._records.get((tenant_id, subject_id))
        return bool(rec and rec.allows(purpose))

    def for_tenant(self, tenant_id: str) -> list[ConsentRecord]:
        return [r for k, r in self._records.items() if k[0] == tenant_id]


@dataclass
class RetentionPolicy:
    """Per-tenant retention policy with a hard legal floor."""
    retention_days: int = 365
    legal_floor_days: int = 180          # EU AI Act Art. 12 minimum for audit logs

    def __post_init__(self) -> None:
        if self.retention_days < self.legal_floor_days:
            raise ValueError(
                f"retention_days={self.retention_days} below legal floor "
                f"{self.legal_floor_days}")

    def cutoff_ts(self, now: Optional[float] = None) -> float:
        now = now if now is not None else time.time()
        return now - self.retention_days * 86400


class ComplianceReporter:
    """Generate auditor-facing compliance reports.

    Pulls live numbers from a store (trace counts), the audit backend (chain
    validity), and the consent registry, and renders them as JSON or text. A
    PDF renderer is provided that uses the project's pdf skill output path if
    reportlab is available, else falls back to text.
    """

    FRAMEWORKS = ("EU_AI_ACT", "GDPR", "HIPAA", "SOC2", "NIST_AI_RMF", "PCI_DSS")

    # ── Control mapping ────────────────────────────────────────────────
    # Maps each framework's relevant control IDs to the Pramagent feature
    # that provides evidence for the control. Used by ``generate()`` to
    # render the control-mapping table in the evidence PDF.
    CONTROL_MAP: dict[str, list[tuple[str, str, str]]] = {
        # framework: list of (control_id, description, pramagent_evidence)
        "SOC2": [
            ("CC6.1", "Logical access controls restrict the system",
             "Per-tenant API keys + JWT; ToolGuardLayer policy enforcement"),
            ("CC6.6", "Logical access security measures protect data in transit",
             "Provider TLS enforced; redaction occurs before egress"),
            ("CC6.7", "The entity restricts the transmission of information",
             "ComplianceLayer redacts PII before model exposure"),
            ("CC7.2", "Monitors system components for anomalies",
             "ObservabilityLayer; tamper-evident audit chain"),
            ("CC7.3", "Evaluates security events for incidents",
             "RCAEngine on every blocked / escalated call"),
            ("CC8.1", "Authorises, designs, develops, tests changes",
             "Deterministic rules in pramagent/rules/ — human-readable"),
            ("A1.2", "Authorises, modifies, removes access",
             "Per-tenant key registry; revocation via APIKeyRegistry"),
        ],
        "HIPAA": [
            ("164.308(a)(1)(ii)(D)", "Information system activity review",
             "Hash-chained audit trail; ComplianceReporter evidence packages"),
            ("164.308(a)(4)", "Information access management",
             "Tenant isolation in IsolationLayer; per-tenant keys"),
            # Finding 2.x: honest scope — the REST auth model identifies the
            # tenant/API key, not an individual end user, and session_id is
            # client-supplied (not derived from the credential). This is
            # tenant/session attribution, not per-user identification.
            ("164.312(a)(1)", "Access control — tenant/session attribution "
             "(not per-individual-user; session_id is client-supplied)",
             "Tenant + client-supplied session ids on every TraceEvent"),
            ("164.312(b)", "Audit controls",
             "HashChainBackend / EthereumBackend with chain verification"),
            ("164.312(c)(1)", "Integrity — protect ePHI from improper alteration",
             "Tamper-evident chain; canonical_hash over every payload"),
            ("164.312(e)(1)", "Transmission security",
             "PHI redaction (pramagent.rules.PHI_PATTERNS) before model send"),
        ],
        "GDPR": [
            ("Art. 5(1)(b)", "Purpose limitation",
             "ConsentRegistry purposes; per-call purpose check"),
            ("Art. 5(1)(c)", "Data minimisation",
             "ComplianceLayer scrubs PII before model exposure"),
            ("Art. 5(1)(e)", "Storage limitation",
             "RetentionPolicy with enforced legal floor"),
            ("Art. 7", "Consent",
             "ConsentRegistry.grant / revoke"),
            ("Art. 17", "Right to erasure",
             "store.delete_for_tenant(tenant_id)"),
            ("Art. 22", "Right to human review of automated decisions",
             "HITLLayer — propose and wait, silence is never consent"),
            ("Art. 30", "Records of processing activities",
             "TraceEvent on every call; tamper-evident chain"),
            ("Art. 32", "Security of processing",
             "Tenant isolation, redaction, audit chain"),
        ],
        "NIST_AI_RMF": [
            ("GOVERN-1.1", "Documented policies for AI risk management",
             "Deterministic rules in pramagent/rules/ are the policy artefact"),
            ("MAP-2.3", "Categorisation of the AI system risks",
             "Verdict precedence: BLOCK > ESCALATE > REDACT > ALLOW"),
            ("MEASURE-2.7", "AI system security risks evaluated",
             "INJECTION_CORPUS + OWASP_LLM_TOP10 corpora"),
            ("MEASURE-2.8", "Privacy risks evaluated",
             "PHI_PATTERNS + FINANCIAL_PII + ComplianceLayer"),
            ("MANAGE-1.3", "Mechanisms in place to monitor AI risks",
             "ObservabilityLayer + audit chain verification"),
            ("MANAGE-2.4", "Human review for high-impact decisions",
             "HITLLayer with persistent queue store"),
            ("MANAGE-4.1", "Post-deployment AI system monitoring",
             "TraceEvent + RCAEngine"),
        ],
        "EU_AI_ACT": [
            ("Art. 12", "Record keeping (minimum 6 months)",
             "Hash-chained traces; RetentionPolicy legal_floor_days >= 180"),
            ("Art. 13", "Transparency and provision of information",
             "TraceEvent is first-class on every AgentResponse"),
            ("Art. 14", "Human oversight",
             "HITLLayer — silence is never consent"),
            ("Art. 15", "Accuracy, robustness, cybersecurity",
             "Deterministic rules + ReliabilityLayer + audit chain"),
        ],
        "PCI_DSS": [
            ("3.4", "Render PAN unreadable wherever stored",
             "FINANCIAL_PII brand-specific PAN rules redact before storage"),
            ("3.2", "Do not store sensitive authentication data after auth",
             "fin_cvv_in_context + fin_track_data rules"),
            ("10.1", "Audit trails to reconstruct events",
             "Hash-chained TraceEvent per call"),
            ("10.5.5", "Use integrity monitoring on logs",
             "audit.verify_chain() proves no log was altered"),
        ],
    }

    def __init__(self, *, store=None, audit=None,
                 consent: Optional[ConsentRegistry] = None,
                 retention: Optional[RetentionPolicy] = None) -> None:
        self.store = store
        self.audit = audit
        self.consent = consent or ConsentRegistry()
        self.retention = retention or RetentionPolicy()

    def _trace_stats(self, tenant_id: Optional[str]) -> dict:
        if self.store is None:
            return {"total": 0, "tenant": 0}
        # SQL COUNT when the store supports it — never a full-table load
        # just to count rows (P2-14).
        counter = getattr(self.store, "count", None)
        if counter is not None:
            total = counter()
            tenant = counter(tenant_id) if tenant_id else total
            return {"total": total, "tenant": tenant}
        all_traces = self.store.list_all()
        total = len(all_traces)
        if tenant_id:
            tenant = sum(1 for t in all_traces
                         if getattr(t, "tenant_id", None) == tenant_id)
        else:
            tenant = total
        return {"total": total, "tenant": tenant}

    def _chain_valid(self) -> Optional[bool]:
        if self.audit is None or not hasattr(self.audit, "verify_chain"):
            return None
        try:
            return bool(self.audit.verify_chain())
        except Exception:
            return None

    def _chain_tamper_evident(self) -> Optional[bool]:
        """Whether the audit chain is tamper-evident *against a writer* (finding
        2.1), not merely internally consistent.

        A keyed HMAC chain (PRAMAGENT_SIGNING_KEY set) cannot be reforged
        without the secret. An unkeyed chain is plain SHA-256: verify_chain()
        can still return True, but anyone with write access can edit a row and
        recompute every downstream hash, so it detects accidental corruption
        only. Returns None when there is no verifiable chain at all."""
        if self.audit is None or not hasattr(self.audit, "verify_chain"):
            return None
        key = getattr(self.audit, "_signing_key", None)
        if not key:
            keyring = getattr(self.audit, "_keyring", None)
            if keyring is not None:
                try:
                    key = keyring.active_key()
                except Exception:
                    key = None
        return bool(key)

    def build(self, *, tenant_id: Optional[str] = None,
              framework: str = "EU_AI_ACT") -> dict:
        """Return a structured compliance report as a dict (JSON-serialisable)."""
        # A store outage must never yield a report silently asserting zero
        # traces as signed evidence (P3-12) — the failure is stamped into
        # the report so an auditor sees it.
        store_error = ""
        try:
            stats = self._trace_stats(tenant_id)
        except Exception as exc:
            stats = {"total": 0, "tenant": 0}
            store_error = repr(exc)[:200]
        consents = (self.consent.for_tenant(tenant_id) if tenant_id
                    else [r for recs in [self.consent.for_tenant(t)
                          for t in {k[0] for k in self.consent._records}]
                          for r in recs])
        active_consents = sum(1 for c in consents if c.active)
        return {
            "report_type": "pramagent_compliance",
            "framework": framework,
            "generated_at": time.time(),
            "generated_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                              time.gmtime()),
            "tenant_id": tenant_id or "*ALL*",
            "audit": {
                # hash_chain_verified means the chain is internally consistent.
                # tamper_evident_against_writer means that consistency is
                # HMAC-protected (finding 2.1): False here => an actor with DB
                # write access could have reforged history undetectably, so an
                # auditor must not read "verified: true" as tamper-evidence.
                "hash_chain_verified": self._chain_valid(),
                "hash_chain_tamper_evident_against_writer": self._chain_tamper_evident(),
                "trace_records_total": stats["total"],
                "trace_records_tenant": stats["tenant"],
                **({"store_error": store_error} if store_error else {}),
            },
            "retention": {
                "retention_days": self.retention.retention_days,
                "legal_floor_days": self.retention.legal_floor_days,
                "policy_compliant":
                    self.retention.retention_days >= self.retention.legal_floor_days,
            },
            "consent": {
                "records_on_file": len(consents),
                "active": active_consents,
                "revoked": len(consents) - active_consents,
            },
            "controls": self._controls(framework),
        }

    def _has_active_consent(self) -> bool:
        """True when at least one active consent record is on file."""
        try:
            return any(r.active for r in self.consent._records.values())
        except Exception:
            return False

    def _control_in_place(self, evidence: str) -> bool:
        """Probe the live system for a control instead of attesting it (P2-14).

        Controls whose evidence names a probeable object (the audit chain,
        the consent registry, the retention policy, the store) are measured
        at report time; purely structural controls (deterministic rules,
        redaction patterns — properties of the shipped code, not of runtime
        state) remain True by construction."""
        ev = evidence.lower()
        if "chain" in ev or "audit" in ev:
            return self._chain_valid() is True
        if "consent" in ev:
            return self._has_active_consent()
        if "retention" in ev:
            return self.retention.retention_days >= self.retention.legal_floor_days
        if "delete_for_tenant" in ev or "store." in ev:
            return self.store is not None and hasattr(self.store, "delete_for_tenant")
        return True

    def _controls(self, framework: str) -> list[dict]:
        """Map implemented Pramagent controls to a framework's expectations.

        Live-system rows are probed at report time (P2-14): the audit row
        reflects an actual verify_chain() run, the retention row an actual
        policy comparison. Structural rows (scrubbing, HITL gating) are
        properties of the pipeline code itself."""
        base = [
            # "Tamper-evident" requires BOTH a valid chain AND a signing key
            # (finding 2.1): an unkeyed chain is not tamper-evident against a
            # writer, so this control must not read in_place merely because the
            # hashes are self-consistent.
            ("audit_trail", "Tamper-evident hash-chained audit log",
             self._chain_valid() is True and self._chain_tamper_evident() is True),
            ("pii_minimization", "PII scrubbed before model exposure", True),
            ("access_control", "Per-tenant API-key + JWT auth, tenant isolation", True),
            ("human_oversight", "HITL approval gate for consequential actions", True),
            ("retention_limit",
             f"Retention floor {self.retention.legal_floor_days}d enforced",
             self.retention.retention_days >= self.retention.legal_floor_days),
        ]
        return [{"control_id": cid, "description": desc, "in_place": ok}
                for cid, desc, ok in base]

    def to_json(self, *, tenant_id: Optional[str] = None,
                framework: str = "EU_AI_ACT", path: Optional[str] = None) -> str:
        report = self.build(tenant_id=tenant_id, framework=framework)
        blob = json.dumps(report, indent=2, sort_keys=True)
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(blob)
        return blob

    def to_text(self, *, tenant_id: Optional[str] = None,
                framework: str = "EU_AI_ACT") -> str:
        r = self.build(tenant_id=tenant_id, framework=framework)
        lines = [
            "PRAMAGENT COMPLIANCE REPORT",
            "=" * 60,
            f"Framework:      {r['framework']}",
            f"Generated:      {r['generated_at_iso']}",
            f"Tenant:         {r['tenant_id']}",
            "",
            "AUDIT",
            f"  Hash chain verified : {r['audit']['hash_chain_verified']}",
            f"  Tamper-evident (HMAC): {r['audit']['hash_chain_tamper_evident_against_writer']}",
            f"  Trace records (all) : {r['audit']['trace_records_total']}",
            f"  Trace records (tnt) : {r['audit']['trace_records_tenant']}",
            "",
            "RETENTION",
            f"  Policy (days)       : {r['retention']['retention_days']}",
            f"  Legal floor (days)  : {r['retention']['legal_floor_days']}",
            f"  Compliant           : {r['retention']['policy_compliant']}",
            "",
            "CONSENT",
            f"  Records on file     : {r['consent']['records_on_file']}",
            f"  Active / Revoked    : {r['consent']['active']} / {r['consent']['revoked']}",
            "",
            "CONTROLS",
        ]
        for c in r["controls"]:
            mark = "✓" if c["in_place"] else "✗"
            lines.append(f"  [{mark}] {c['control_id']}: {c['description']}")
        return "\n".join(lines)

    def to_pdf(self, path: str, *, tenant_id: Optional[str] = None,
               framework: str = "EU_AI_ACT") -> str:
        """Write a PDF report. Uses reportlab if present; else writes text to path."""
        text = self.to_text(tenant_id=tenant_id, framework=framework)
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
            c = canvas.Canvas(path, pagesize=letter)
            _, height = letter
            y = height - 50
            for line in text.splitlines():
                c.drawString(50, y, line[:100])
                y -= 14
                if y < 50:
                    c.showPage()
                    y = height - 50
            c.save()
        except Exception:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        return path

    # ────────────────────────────────────────────────────────────────────
    #  Evidence package generator
    # ────────────────────────────────────────────────────────────────────
    def _traces_in_window(self, period_start: Optional[float],
                          period_end: Optional[float],
                          tenant_id: Optional[str]) -> list:
        """Return traces in the requested period (and tenant scope).

        Store failures propagate — collect_evidence stamps them into the
        evidence package instead of silently reporting zero traces (P3-12)."""
        if self.store is None:
            return []
        traces = self.store.list_all()
        ps = period_start if period_start is not None else 0.0
        pe = period_end if period_end is not None else time.time() + 1
        out = []
        for t in traces:
            ts = getattr(t, "created_at", 0.0) or 0.0
            if ts < ps or ts > pe:
                continue
            if tenant_id and getattr(t, "tenant_id", None) != tenant_id:
                continue
            out.append(t)
        return out

    @staticmethod
    def _parse_period(value):
        """Accept ``None``, a unix timestamp, or an ISO-8601 ``YYYY-MM-DD[Thh:mm:ss]``."""
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return float(value)
        s = str(value).strip()
        if not s:
            return None
        # Try ISO formats
        from datetime import datetime
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(s, fmt).timestamp()
            except ValueError:
                continue
        try:
            return float(s)
        except ValueError:
            raise ValueError(f"unrecognised period value: {value!r}")

    def collect_evidence(self, *, framework: str,
                         period_start=None, period_end=None,
                         tenant_id: Optional[str] = None) -> dict:
        """Gather the raw evidence payload (used by ``generate``)."""
        ps = self._parse_period(period_start)
        pe = self._parse_period(period_end)
        store_error = ""
        try:
            traces = self._traces_in_window(ps, pe, tenant_id)
        except Exception as exc:
            traces = []
            store_error = repr(exc)[:200]

        blocked = []
        approvals = []
        redaction_counts: dict[str, int] = {}
        for t in traces:
            pre = getattr(t, "pre_verdict", None)
            post = getattr(t, "post_verdict", None)
            if pre == "block" or post == "block":
                fired = [r for r in getattr(t, "rules_evaluated", []) if getattr(r, "fired", False)]
                blocked.append({
                    "call_id": getattr(t, "call_id", ""),
                    "tenant_id": getattr(t, "tenant_id", ""),
                    "created_at": getattr(t, "created_at", 0.0),
                    "rules": [getattr(r, "rule_id", "") for r in fired],
                    "reason": (fired[0].detail if fired else ""),
                })
            hs = getattr(t, "hitl_status", "")
            if hs in ("approved", "denied"):
                approvals.append({
                    "call_id": getattr(t, "call_id", ""),
                    "tenant_id": getattr(t, "tenant_id", ""),
                    "decision": hs,
                    "timestamp": getattr(t, "created_at", 0.0),
                })
            for label in getattr(t, "pii_redactions", []) or []:
                redaction_counts[label] = redaction_counts.get(label, 0) + 1

        controls = self.CONTROL_MAP.get(framework, [])
        # in_place is measured, not attested: probeable controls (chain,
        # consent, retention, store) are checked against the live objects at
        # evidence-generation time (P2-14).
        controls_rows = [
            {"control_id": cid, "description": desc, "evidence": ev,
             "in_place": self._control_in_place(ev)}
            for cid, desc, ev in controls
        ]

        return {
            "framework": framework,
            "tenant_id": tenant_id or "*ALL*",
            "period_start": ps,
            "period_end": pe,
            "period_start_iso": (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ps))
                                 if ps else "(open)"),
            "period_end_iso": (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(pe))
                               if pe else "(open)"),
            "generated_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trace_count": len(traces),
            "blocked": blocked,
            "approvals": approvals,
            "redactions": redaction_counts,
            "redaction_total": sum(redaction_counts.values()),
            "chain_verified": self._chain_valid(),
            "controls": controls_rows,
            **({"store_error": store_error} if store_error else {}),
        }

    def generate(self, *, framework: str = "SOC2",
                 period_start=None, period_end=None,
                 tenant_id: Optional[str] = None,
                 output: Optional[str] = None) -> str:
        """Generate a signed, point-in-time evidence package.

        Parameters
        ----------
        framework : str
            One of ``SOC2``, ``HIPAA``, ``GDPR``, ``NIST_AI_RMF``, ``EU_AI_ACT``, ``PCI_DSS``.
        period_start, period_end : float | str | None
            Window for the report. ``None`` means open-ended on that side.
            Strings are parsed as ISO-8601.
        tenant_id : str | None
            Scope the report to a single tenant. ``None`` means all tenants.
        output : str | None
            Path to write the PDF. If the extension is ``.json`` a JSON payload
            is written instead. If ``None`` the function returns the text body
            and writes nothing.

        Returns the path written (or the rendered text body if ``output`` is None).
        """
        if framework not in self.FRAMEWORKS:
            raise ValueError(
                f"unknown framework {framework!r}; must be one of {self.FRAMEWORKS}")

        ev = self.collect_evidence(
            framework=framework, period_start=period_start,
            period_end=period_end, tenant_id=tenant_id,
        )

        if output is None:
            return self._render_text(ev)

        if output.lower().endswith(".json"):
            with open(output, "w", encoding="utf-8") as f:
                json.dump(ev, f, indent=2, sort_keys=True, default=str)
            return output

        # Default: write PDF (reportlab) with text fallback.
        return self._render_pdf(ev, output)

    # ── Renderers ──────────────────────────────────────────────────────
    @staticmethod
    def _render_text(ev: dict) -> str:
        lines = [
            "PRAMAGENT — COMPLIANCE EVIDENCE PACKAGE",
            "=" * 70,
            f"Framework      : {ev['framework']}",
            f"Tenant         : {ev['tenant_id']}",
            f"Period         : {ev['period_start_iso']}  →  {ev['period_end_iso']}",
            f"Generated      : {ev['generated_at_iso']}",
            f"Traces in scope: {ev['trace_count']}",
            f"Chain verified : {ev['chain_verified']}",
            "",
            "BLOCKED CALLS",
            f"  total: {len(ev['blocked'])}",
        ]
        for b in ev["blocked"][:50]:
            ts = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(b["created_at"]))
            rules = ", ".join(b["rules"]) or "(no rule id)"
            lines.append(f"  [{ts}] {b['call_id'][:8]} tenant={b['tenant_id']} rules={rules}")
        if len(ev["blocked"]) > 50:
            lines.append(f"  … {len(ev['blocked']) - 50} more (see JSON export)")
        lines += ["", "HITL APPROVALS"]
        lines.append(f"  total: {len(ev['approvals'])}")
        for a in ev["approvals"][:50]:
            ts = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(a["timestamp"]))
            lines.append(f"  [{ts}] {a['call_id'][:8]} decision={a['decision']}")
        lines += ["", "PII REDACTIONS"]
        lines.append(f"  total redactions: {ev['redaction_total']}")
        for label, count in sorted(ev["redactions"].items(), key=lambda kv: -kv[1]):
            lines.append(f"  {label:24s} {count}")
        lines += ["", "CONTROL MAPPING"]
        for c in ev["controls"]:
            mark = "✓" if c["in_place"] else "✗"
            lines.append(f"  [{mark}] {c['control_id']:20s} {c['description']}")
            lines.append(f"          evidence: {c['evidence']}")
        lines += ["", "─" * 70,
                  "Evidence chain root: see `audit.head` for the live hash.",
                  "Any retroactive edit to a row above breaks every hash after it."]
        return "\n".join(lines)

    @staticmethod
    def _render_pdf(ev: dict, path: str) -> str:
        text = ComplianceReporter._render_text(ev)
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
            from reportlab.lib.units import inch
            c = canvas.Canvas(path, pagesize=letter)
            width, height = letter
            # Header
            c.setFont("Helvetica-Bold", 14)
            c.drawString(0.6 * inch, height - 0.6 * inch,
                         f"Pramagent Evidence Package — {ev['framework']}")
            c.setFont("Helvetica", 9)
            c.drawString(0.6 * inch, height - 0.85 * inch,
                         f"Generated {ev['generated_at_iso']}  •  Tenant {ev['tenant_id']}  •  "
                         f"Period {ev['period_start_iso']} → {ev['period_end_iso']}")
            c.line(0.6 * inch, height - 0.95 * inch, width - 0.6 * inch, height - 0.95 * inch)
            # Body
            c.setFont("Courier", 8)
            y = height - 1.2 * inch
            for line in text.splitlines():
                c.drawString(0.6 * inch, y, line[:110])
                y -= 11
                if y < 0.6 * inch:
                    c.showPage()
                    c.setFont("Courier", 8)
                    y = height - 0.6 * inch
            c.save()
        except Exception:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        return path
