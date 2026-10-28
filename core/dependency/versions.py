"""Versions of the dependency engine (Doc 07 §29; C-132).

``GRAPH_ALGORITHM_VERSION`` is recorded in every graph and in the hash. Any change to the edge
rules (C-133, C-134, C-136), the node attributes or the vocabularies bumps it.

- ``dail-graph-1``: P3c.
- ``dail-graph-2``: the RDS subnet placement slot and the literals explained by a reference
  (C-136).
"""

from __future__ import annotations

from typing import Final

GRAPH_ALGORITHM_VERSION: Final = "dail-graph-2"
