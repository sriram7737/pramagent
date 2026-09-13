"""HTTP sidecar for Pramagent. Import the app factory or the ready-made app.

    from pramagent.api.app import create_app          # factory (preferred)
    from pramagent.api.app import app                 # eager module-level app

The module-level ``app`` exists only when PRAMAGENT_EAGER_APP != "0" ;
the factory is always available.
"""
from .app import create_app

try:
    from .app import app
    __all__ = ["app", "create_app"]
except ImportError:  # PRAMAGENT_EAGER_APP=0 — factory-only mode
    __all__ = ["create_app"]
