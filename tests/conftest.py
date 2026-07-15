"""Shared test configuration.

The API factory refuses to boot without a persistent store (P0-1). Tests run
against in-memory stores deliberately, so the suite opts in explicitly —
exactly the switch a dev deployment would flip.
"""
import os

os.environ.setdefault("PRAMAGENT_ALLOW_MEMORY_STORE", "1")
# build_default_armor() now refuses a persistent store without a signing key
# (finding 2.1): an unkeyed audit chain is not tamper-evident. The suite runs
# with a fixed non-secret key by default — the switch a real deployment flips —
# and individual tests delenv it to exercise the refusal path.
os.environ.setdefault("PRAMAGENT_SIGNING_KEY", "test-signing-key-not-a-real-secret")
