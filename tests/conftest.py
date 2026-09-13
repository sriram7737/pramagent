"""Shared test configuration.

The API factory refuses to boot without a persistent store . Tests run
against in-memory stores deliberately, so the suite opts in explicitly —
exactly the switch a dev deployment would flip.
"""
import os

os.environ.setdefault("PRAMAGENT_ALLOW_MEMORY_STORE", "1")
# build_default_armor() now refuses a persistent store without a signing key
# : an unkeyed audit chain is not tamper-evident. The suite runs
# with a fixed non-secret key by default — the switch a real deployment flips —
# and individual tests delenv it to exercise the refusal path.
os.environ.setdefault("PRAMAGENT_SIGNING_KEY", "test-signing-key-not-a-real-secret")
# The API now fails closed in the request path when no API-key registry is
# configured . Most tests run against an empty registry on purpose
# (dev/demo mode), so the suite opts into unauthenticated access by default —
# the same explicit switch a dev deployment flips — and auth tests delenv it to
# exercise the fail-closed path.
os.environ.setdefault("PRAMAGENT_ALLOW_UNAUTHENTICATED_API", "1")
# Most API tests deliberately select logical tenants without provisioning
# credentials. Production/default no-auth mode is strict single-tenant.
os.environ.setdefault("PRAMAGENT_STRICT_SINGLE_TENANT", "false")
