"""Offline CycloneDX JSON loading entry points."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import StructuralError
from .graph import DependencyGraph, build_graph

SUPPORTED_FORMAT = "CycloneDX"


def load_sbom(source: str | Path | dict[str, Any]) -> DependencyGraph:
    """Load an SBOM from a path, a JSON string or an already parsed dict."""

    if isinstance(source, dict):
        document = source
    elif isinstance(source, (str, Path)):
        path = Path(source)
        if path.exists() and path.is_file():
            document = json.loads(path.read_text(encoding="utf-8"))
        else:
            document = json.loads(str(source))
    else:
        raise TypeError(f"unsupported SBOM source: {type(source).__name__}")

    if not isinstance(document, dict):
        raise ValueError("SBOM document must be a JSON object")

    graph = build_graph(document)
    if document.get("bomFormat") != SUPPORTED_FORMAT:
        graph.errors.insert(
            0,
            StructuralError(
                "unsupported_format",
                f"bomFormat must be {SUPPORTED_FORMAT!r}, got "
                f"{document.get('bomFormat')!r}",
            ),
        )
    return graph
