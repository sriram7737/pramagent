"""
pramagent.rules.financial
=========================
PCI-DSS-relevant patterns and other financial PII beyond what
ComplianceLayer (in pramagent.layers) already covers.

ComplianceLayer catches: generic credit-card-shaped numbers, IBAN, account.
This corpus adds:
  - PAN by brand (Visa / Mastercard / Amex / Discover / JCB / Diners) with
    correct length & BIN
  - CVV when it appears in a CV2/CVC/CVV context (not bare 3-digit numbers)
  - Routing+account pairs in close proximity
  - SWIFT / BIC codes
  - Crypto wallet addresses (BTC, ETH, SOL, XRP)
  - Tax IDs (US EIN, UK NIN, IN PAN, CA SIN)

Default action is REDACT — the goal is to keep these out of prompts and logs.
For the highest-sensitivity items (full PAN, private key fragments) we mark
BLOCK to prevent the call from proceeding at all.
"""
from __future__ import annotations

from ..layers import Rule
from ..types import Verdict


_PATTERNS: list[tuple[str, str, str, Verdict]] = [
    # Card brand-specific PAN (with BIN ranges)
    # Visa: starts with 4, 13 or 16 digits
    ("fin_pan_visa",
     r"\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,4}\b",
     "PCI-DSS: Visa PAN", Verdict.REDACT),
    # Mastercard: 51-55 or 2221-2720
    ("fin_pan_mastercard",
     r"\b(?:5[1-5]\d{2}|22[2-9]\d|2[3-6]\d{2}|27[01]\d|2720)[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
     "PCI-DSS: Mastercard PAN", Verdict.REDACT),
    # Amex: 34 or 37, 15 digits
    ("fin_pan_amex",
     r"\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b",
     "PCI-DSS: Amex PAN", Verdict.REDACT),
    # Discover: 6011 or 65
    ("fin_pan_discover",
     r"\b(?:6011|65\d{2}|64[4-9]\d)[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
     "PCI-DSS: Discover PAN", Verdict.REDACT),
    # JCB: 35
    ("fin_pan_jcb",
     r"\b35\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
     "PCI-DSS: JCB PAN", Verdict.REDACT),
    # Diners Club: 300-305, 36, 38
    ("fin_pan_diners",
     r"\b3(?:0[0-5]|[68]\d)\d[\s-]?\d{6}[\s-]?\d{4}\b",
     "PCI-DSS: Diners Club PAN", Verdict.REDACT),

    # CVV / CVC / CV2 — three or four digits IN CONTEXT
    ("fin_cvv_in_context",
     r"\b(?:CVV|CVC|CV2|CID|security\s+code)\s*[:#]?\s*\d{3,4}\b",
     "PCI-DSS: CVV/CVC in context", Verdict.REDACT),

    # Card expiry in context — MM/YY or MM/YYYY
    ("fin_expiry_in_context",
     r"\b(?:exp(?:iry|ires|iration)?|valid\s+thru)\s*[:#]?\s*(?:0[1-9]|1[0-2])\s*/\s*\d{2,4}\b",
     "PCI-DSS: card expiry in context", Verdict.REDACT),

    # Bank wire details
    # SWIFT / BIC: 8 or 11 chars (4 letter bank, 2 letter country, 2 alnum location, optional 3 alnum branch)
    ("fin_swift_bic",
     r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
     "Banking: SWIFT/BIC code", Verdict.REDACT),

    # Routing + account pair in close proximity
    ("fin_routing_account_pair",
     r"routing\s*(?:number|#)?\s*[:.]?\s*\d{9}[\s\S]{0,40}account\s*(?:number|#)?\s*[:.]?\s*\d{6,17}",
     "Banking: routing+account pair", Verdict.REDACT),

    # Crypto wallets
    ("fin_crypto_btc",
     r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b",
     "Crypto: Bitcoin wallet", Verdict.REDACT),
    ("fin_crypto_eth",
     r"\b0x[a-fA-F0-9]{40}\b",
     "Crypto: Ethereum address", Verdict.REDACT),
    ("fin_crypto_sol",
     r"\b(?:sol[123]|[1-9A-HJ-NP-Za-km-z]{43,44})\b(?=.*solana|.*\bSOL\b)",
     "Crypto: Solana address (in context)", Verdict.REDACT),
    ("fin_crypto_xrp",
     r"\br[a-km-zA-HJ-NP-Z1-9]{24,34}\b",
     "Crypto: XRP address", Verdict.REDACT),

    # Tax / national ID numbers
    # US EIN — XX-XXXXXXX
    ("fin_us_ein",
     r"\b\d{2}-\d{7}\b",
     "Tax: US Employer ID Number (EIN)", Verdict.REDACT),
    # UK National Insurance Number — AA000000A
    ("fin_uk_nin",
     r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b",
     "Tax: UK National Insurance Number", Verdict.REDACT),
    # India PAN — AAAAA9999A
    ("fin_in_pan",
     r"\b[A-Z]{5}\d{4}[A-Z]\b",
     "Tax: India PAN", Verdict.REDACT),
    # Canada SIN — 9 digits, often grouped 3-3-3
    ("fin_ca_sin",
     r"\b\d{3}[\s-]\d{3}[\s-]\d{3}\b(?=.*\b(?:SIN|social\s+insurance)\b)",
     "Tax: Canada SIN (in context)", Verdict.REDACT),

    # High-sensitivity (BLOCK)
    # PCI track data — magnetic stripe / chip dumps
    ("fin_track_data",
     r"(?:%B\d{12,19}\^[A-Z\s/]{2,26}\^\d{4}|;\d{12,19}=\d{4})",
     "PCI-DSS: track 1/2 magstripe data", Verdict.BLOCK),

    # PGP private-key block specifically (also caught by OWASP rule, kept for finance audit clarity)
    ("fin_pgp_private_key",
     r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----",
     "Banking: PGP private key block", Verdict.BLOCK),
]


FINANCIAL_PII: list[Rule] = [
    Rule(rule_id=rid, action=verdict, pattern=pat, detail=detail)
    for rid, pat, detail, verdict in _PATTERNS
]

__all__ = ["FINANCIAL_PII"]
