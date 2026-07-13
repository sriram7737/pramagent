"""
pramagent.secrets
==================
Secret resolution with optional AWS Secrets Manager / HashiCorp Vault
backing, instead of every secret being a plain environment variable —
closing the "env-var only, no secret-manager integration" gap.

Resolution order for resolve_secret("PRAMAGENT_JWT_SECRET"):
  1. PRAMAGENT_JWT_SECRET itself, if set directly — unchanged default path,
     so existing plain-env-var deployments see no behavior change.
  2. PRAMAGENT_JWT_SECRET_AWS_SECRET_ID -> AWS Secrets Manager GetSecretValue.
  3. PRAMAGENT_JWT_SECRET_VAULT_PATH -> HashiCorp Vault KV v2 read.
  4. The caller's default (usually "").

A fetched value is cached in-process — these underlie hot-path auth checks,
not something to re-fetch over the network on every request. Restart the
process (or call clear_secret_cache()) to pick up a rotated value.
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)

_cache: dict[str, str] = {}


def clear_secret_cache() -> None:
    """Drop cached secret-manager values, forcing the next resolve_secret()
    call to re-fetch. Useful after a known rotation without a full restart."""
    _cache.clear()


def resolve_secret(name: str, default: str = "") -> str:
    """Resolve a secret by its usual env-var name.

    name is the plain env var (e.g. "PRAMAGENT_JWT_SECRET"); the
    secret-manager indirection variables are derived from it
    (f"{name}_AWS_SECRET_ID", f"{name}_VAULT_PATH") rather than requiring a
    separate naming scheme per secret.
    """
    direct = os.environ.get(name, "")
    if direct:
        return direct

    if name in _cache:
        return _cache[name]

    aws_secret_id = os.environ.get(f"{name}_AWS_SECRET_ID", "").strip()
    if aws_secret_id:
        value = _fetch_aws_secret(aws_secret_id)
        if value:
            _cache[name] = value
            return value

    vault_path = os.environ.get(f"{name}_VAULT_PATH", "").strip()
    if vault_path:
        value = _fetch_vault_secret(vault_path)
        if value:
            _cache[name] = value
            return value

    return default


def _fetch_aws_secret(secret_id: str) -> str:
    try:
        import boto3
    except ImportError:
        log.error(
            "%s references an AWS secret id but boto3 is not installed; "
            "install with: pip install 'pramagent[s3]' (or boto3 directly)",
            secret_id,
        )
        return ""
    try:
        client = boto3.client(
            "secretsmanager",
            region_name=os.environ.get("AWS_DEFAULT_REGION") or None,
        )
        response = client.get_secret_value(SecretId=secret_id)
        return response.get("SecretString", "") or ""
    except Exception as exc:
        log.error("failed to fetch AWS secret %s: %s", secret_id, exc)
        return ""


def _fetch_vault_secret(path: str) -> str:
    """Read a HashiCorp Vault KV v2 secret.

    VAULT_ADDR and VAULT_TOKEN (the standard Vault client env vars) must be
    set. Expects the secret's `value` key to hold the actual string, e.g.:
        vault kv put secret/pramagent/jwt value=<the-real-secret>
    """
    vault_addr = os.environ.get("VAULT_ADDR", "").strip()
    vault_token = os.environ.get("VAULT_TOKEN", "").strip()
    if not vault_addr or not vault_token:
        log.error(
            "%s references a Vault path but VAULT_ADDR/VAULT_TOKEN are not "
            "set; cannot reach Vault", path,
        )
        return ""

    try:
        from .security import UnsafeURLError, validate_http_url
        url = validate_http_url(
            f"{vault_addr.rstrip('/')}/v1/{path.lstrip('/')}",
            allow_http_localhost=True,
            allow_private=True,  # Vault is commonly reached over a private network
            context="Vault address",
        )
    except UnsafeURLError as exc:
        log.error("refusing unsafe Vault address: %s", exc)
        return ""

    try:
        import json
        import urllib.error
        import urllib.request

        req = urllib.request.Request(url, headers={"X-Vault-Token": vault_token})
        # Vault address is validated above; token comes from the trusted
        # environment, never from user input.
        with urllib.request.urlopen(req, timeout=5.0) as resp:  # nosec B310
            body = json.loads(resp.read().decode("utf-8"))
        return str(body.get("data", {}).get("data", {}).get("value", "") or "")
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        log.error("failed to fetch Vault secret %s: %s", path, exc)
        return ""
