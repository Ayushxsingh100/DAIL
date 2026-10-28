"""A read-only index over the resources of one state (C-133).

``StateIndex`` answers the two questions the edge rules ask: which resource has this address, and
which instances does this resource block have in the state. Unique addresses are checked by
``build_graph``; the index itself refuses a duplicate too.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from core.dependency.addresses import split_key
from core.dependency.errors import DependencyInputError
from core.domain.resource import Resource


@dataclass(frozen=True)
class StateIndex:
    by_address: Mapping[str, Resource]
    instances: Mapping[str, tuple[str, ...]]

    @classmethod
    def of(cls, resources: Iterable[Resource]) -> StateIndex:
        by_address: dict[str, Resource] = {}
        blocks: dict[str, list[str]] = {}
        for resource in resources:
            if not isinstance(resource, Resource):
                raise DependencyInputError("the state must hold Resource objects")
            if resource.address in by_address:
                raise DependencyInputError(f"duplicate resource address {resource.address!r}")
            by_address[resource.address] = resource
            block, key = split_key(resource.address)
            if key is not None:
                blocks.setdefault(block, []).append(resource.address)
        return cls(
            by_address=MappingProxyType(dict(sorted(by_address.items()))),
            instances=MappingProxyType({b: tuple(sorted(a)) for b, a in sorted(blocks.items())}),
        )

    def sorted_resources(self) -> tuple[Resource, ...]:
        return tuple(self.by_address.values())

    def instances_of(self, address: str) -> tuple[str, ...]:
        """The instance addresses of a block that is itself no resource of the state, else ``()``.

        This is the question behind a block-level reference: the address names a block, nothing
        in the state has exactly that address, and the block has instances (C-133 item 3).
        """
        if address in self.by_address:
            return ()
        return self.instances.get(address, ())
