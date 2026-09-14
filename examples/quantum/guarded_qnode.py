"""Compatibility import for the packaged PennyLane QNode guard.

Applications should import these APIs from ``pramagent.quantum`` or
``pramagent.quantum.guarded_qnode``. This module keeps the original example
path working for existing demos.
"""

from pramagent.quantum.guarded_qnode import *  # noqa: F403
