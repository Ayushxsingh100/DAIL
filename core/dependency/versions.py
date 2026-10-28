"""Versions of the dependency engine (Doc 07 §29; C-132).

``GRAPH_ALGORITHM_VERSION`` is recorded in every graph and in the hash. Any change to the edge
rules (C-133, C-134), the node attributes or the vocabularies bumps it.
"""

from __future__ import annotations

from typing import Final

GRAPH_ALGORITHM_VERSION: Final = "dail-graph-1"
