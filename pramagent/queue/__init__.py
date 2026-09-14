"""
pramagent.queue
===============
Persistent approval queues for HITL — survive process restarts, support
arbitrarily long waits, and back the HITLLayer when ``store=`` is set.

    HITLQueueStore           — Protocol any backend implements
    InMemoryHITLQueue        — default, lost on restart (parity with no-store mode)
    SQLiteHITLQueue          — file-backed, single-process, zero dependencies
    PostgresHITLQueue        — multi-worker production backend; uses ``psycopg``
                               if installed, else raises with a clear message

All three speak the same protocol, so swapping is one line. The HITLLayer
treats the store as authoritative: once a row is in the queue the request can
be approved by any process (a Slack webhook handler, an admin CLI, a separate
worker) and Pramagent will pick up the decision via polling.
"""
from __future__ import annotations

from .base import (HITLQueueStore, InMemoryHITLQueue, QueuedRequest,
                   RequestStatus, approval_binding)
from .sqlite import SQLiteHITLQueue
from .postgres import PostgresHITLQueue

__all__ = [
    "HITLQueueStore",
    "InMemoryHITLQueue",
    "QueuedRequest",
    "RequestStatus",
    "approval_binding",
    "SQLiteHITLQueue",
    "PostgresHITLQueue",
]
