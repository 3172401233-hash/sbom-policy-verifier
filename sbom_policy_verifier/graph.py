"""Dependency graph construction, cycle detection and reachability paths."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .errors import StructuralError
from .identities import Component, normalize_component


@dataclass
class DependencyGraph:
    """Normalized components plus the ``dependsOn`` edge set."""

    components: dict[str, Component] = field(default_factory=dict)
    edges: dict[str, list[str]] = field(default_factory=dict)
    roots: list[str] = field(default_factory=list)
    metadata_ref: str | None = None
    errors: list[StructuralError] = field(default_factory=list)

    def has_ref(self, ref: str) -> bool:
        return ref in self.components or ref == self.metadata_ref

    def component_pairs(self) -> list[tuple[str, Component]]:
        return sorted(self.components.items(), key=lambda item: item[0])

    def find_cycles(self) -> list[list[str]]:
        """Return simple cycles as ref lists (last ref equals the first)."""
        color: dict[str, int] = {}  # 0 = white, 1 = gray, 2 = black
        stack: list[str] = []
        cycles: list[list[str]] = []
        seen_signatures: set[tuple[str, ...]] = set()

        def visit(node: str) -> None:
            color[node] = 1
            stack.append(node)
            for neighbor in self.edges.get(node, ()):  # edges target only known refs
                state = color.get(neighbor, 0)
                if state == 1:
                    start = stack.index(neighbor)
                    cycle = stack[start:] + [neighbor]
                    signature = _canonical_cycle(cycle)
                    if signature not in seen_signatures:
                        seen_signatures.add(signature)
                        cycles.append(cycle)
                elif state == 0:
                    visit(neighbor)
            stack.pop()
            color[node] = 2

        for node in sorted(self.edges):
            if color.get(node, 0) == 0:
                visit(node)
        return cycles

    def shortest_path(self, target: str) -> list[str]:
        """BFS from a root component to ``target``; [] when unreachable."""
        if target not in self.components:
            return []
        queue: deque[str] = deque(self.roots)
        parents: dict[str, str | None] = {root: None for root in self.roots}
        while queue:
            node = queue.popleft()
            if node == target:
                path: list[str] = []
                current: str | None = node
                while current is not None:
                    path.append(current)
                    current = parents[current]
                path.reverse()
                return path
            for neighbor in self.edges.get(node, ()):
                if neighbor not in parents and neighbor in self.components:
                    parents[neighbor] = node
                    queue.append(neighbor)
        return []


def _canonical_cycle(cycle: list[str]) -> tuple[str, ...]:
    nodes = cycle[:-1]
    if not nodes:
        return tuple()
    pivot = min(range(len(nodes)), key=lambda idx: nodes[idx])
    rotated = nodes[pivot:] + nodes[:pivot]
    return tuple(rotated)


def build_graph(document: dict) -> DependencyGraph:
    """Normalize a CycloneDX JSON document into a :class:`DependencyGraph`."""

    graph = DependencyGraph()
    errors = graph.errors

    metadata = document.get("metadata") or {}
    metadata_component = metadata.get("component")
    if isinstance(metadata_component, dict):
        meta_ref = metadata_component.get("bom-ref") or metadata_component.get("ref")
        if meta_ref is not None:
            graph.metadata_ref = str(meta_ref)
            graph.edges.setdefault(graph.metadata_ref, [])

    raw_components = document.get("components") or []
    if not isinstance(raw_components, list):
        raw_components = []

    for index, raw in enumerate(raw_components):
        if not isinstance(raw, dict):
            errors.append(
                StructuralError("invalid_component", f"component #{index} is not an object")
            )
            continue
        fallback = f"__anon__{index}"
        component = normalize_component(raw, fallback)
        ref = component.bom_ref
        if ref in graph.components or ref == graph.metadata_ref:
            errors.append(
                StructuralError(
                    "duplicate_bom_ref",
                    f"duplicate bom-ref {ref!r}; later occurrence ignored",
                    bom_ref=ref,
                )
            )
            continue
        graph.components[ref] = component
        graph.edges.setdefault(ref, [])
        if component.purl_error:
            errors.append(
                StructuralError(
                    "invalid_purl",
                    f"component {ref!r} has unparseable purl: {component.purl_error}",
                    bom_ref=ref,
                )
            )
        if not component.has_identity:
            errors.append(
                StructuralError(
                    "unknown_identity",
                    f"component {ref!r} has neither purl nor name",
                    bom_ref=ref,
                )
            )

    known_refs = set(graph.components)
    if graph.metadata_ref is not None:
        known_refs.add(graph.metadata_ref)

    dependencies = document.get("dependencies") or []
    if not isinstance(dependencies, list):
        dependencies = []

    referenced: set[str] = set()
    for entry in dependencies:
        if not isinstance(entry, dict):
            errors.append(StructuralError("invalid_dependency", "dependency entry is not an object"))
            continue
        source = entry.get("ref")
        if source is None:
            errors.append(
                StructuralError("invalid_dependency", "dependency entry is missing 'ref'")
            )
            continue
        source = str(source)
        if source not in known_refs:
            errors.append(
                StructuralError(
                    "dangling_reference",
                    f"dependency source ref {source!r} does not match any component",
                    bom_ref=source,
                )
            )
            continue
        targets = entry.get("dependsOn") or []
        if not isinstance(targets, list):
            targets = []
        outgoing = graph.edges.setdefault(source, [])
        for raw_target in targets:
            target = str(raw_target)
            if target not in known_refs:
                errors.append(
                    StructuralError(
                        "dangling_reference",
                        f"ref {target!r} depended on by {source!r} does not exist",
                        bom_ref=target,
                    )
                )
                continue
            referenced.add(target)
            if target not in outgoing:
                outgoing.append(target)

    for ref in graph.components:
        graph.edges.setdefault(ref, [])
        if ref not in referenced:
            graph.roots.append(ref)
    graph.roots.sort()

    for cycle in graph.find_cycles():
        errors.append(
            StructuralError(
                "dependency_cycle",
                "dependency cycle detected: " + " -> ".join(cycle),
                bom_ref=cycle[0],
            )
        )

    return graph
