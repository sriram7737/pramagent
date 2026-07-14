"""
pramagent._pg
=============
Postgres driver shim. The packaged extra is ``psycopg[binary]`` (psycopg 3 —
the maintained driver; psycopg2-binary is explicitly not recommended for
production by its maintainers), but existing deployments that already have
psycopg2 installed keep working: ``connect()`` prefers psycopg 3 and falls
back to psycopg2.

Both drivers expose the same surface used in this codebase: ``connect(dsn)``,
``%s`` placeholders, cursor context managers, ``commit``/``rollback``/
``close``, and the connection context manager (transaction scope).
"""
from __future__ import annotations

import os


def _targets_loopback(dsn: str) -> bool:
    """True when the DSN points at localhost — the dev case where enforcing
    TLS would just break local containers with no security benefit."""
    d = dsn.lower()
    return ("localhost" in d or "127.0.0.1" in d
            or "[::1]" in d or "host=::1" in d)


def _desired_sslmode(dsn: str) -> "str | None":
    """C4: the sslmode to inject, or None to leave the DSN untouched.

    Postgres carries the trace store and audit chain, so connections should
    encrypt in transit by default. If the DSN already sets sslmode we respect
    it; PRAMAGENT_POSTGRES_SSLMODE overrides the default (e.g. 'verify-full'
    to also check the server cert, or 'disable' to opt out); otherwise remote
    connections default to 'require' and loopback dev connections are left
    alone."""
    if "sslmode=" in dsn.lower():
        return None
    override = os.environ.get("PRAMAGENT_POSTGRES_SSLMODE", "").strip()
    if override:
        return override
    if _targets_loopback(dsn):
        return None
    return "require"


def _apply_sslmode(dsn: str) -> str:
    mode = _desired_sslmode(dsn)
    if not mode:
        return dsn
    if dsn.startswith(("postgres://", "postgresql://")):
        sep = "&" if "?" in dsn else "?"
        return f"{dsn}{sep}sslmode={mode}"
    return f"{dsn} sslmode={mode}".strip()


def driver():
    """Return (name, module) for the available driver, or (None, None)."""
    try:
        import psycopg  # psycopg 3
        return "psycopg3", psycopg
    except ImportError:
        pass
    try:
        import psycopg2
        return "psycopg2", psycopg2
    except ImportError:
        return None, None


def connect(dsn: str):
    """Open a connection with whichever driver is installed.

    Raises RuntimeError with an install hint when neither is available.
    """
    name, mod = driver()
    if mod is None:
        raise RuntimeError(
            "no Postgres driver installed; install pramagent[postgres] "
            "(psycopg[binary]>=3.1)"
        )
    return mod.connect(_apply_sslmode(dsn))


def transient_exceptions() -> tuple[type, ...]:
    """Exception classes worth retrying (connection blips, timeouts)."""
    name, mod = driver()
    if mod is None:
        return ()
    return (mod.OperationalError, mod.InterfaceError)
