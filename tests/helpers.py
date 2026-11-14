"""Helpers that generate CycloneDX JSON SBOM documents for tests."""

from __future__ import annotations

from typing import Any


def component(
    ref: str,
    name: str,
    version: str = "",
    purl: str | None = None,
    supplier: str | dict | None = None,
    licenses: list[Any] | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {"bom-ref": ref, "name": name}
    if version:
        data["version"] = version
    if purl:
        data["purl"] = purl
    if supplier is not None:
        data["supplier"] = supplier
    if licenses is not None:
        data["licenses"] = licenses
    return data


def license_id(spdx_id: str) -> dict[str, Any]:
    return {"license": {"id": spdx_id}}


def license_expression(expression: str) -> dict[str, Any]:
    return {"expression": expression}


def dependency(ref: str, depends_on: list[str]) -> dict[str, Any]:
    return {"ref": ref, "dependsOn": depends_on}


def make_sbom(
    components: list[dict[str, Any]],
    dependencies: list[dict[str, Any]] | None = None,
    *,
    metadata_component: dict[str, Any] | None = None,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        "version": 1,
        "components": components,
    }
    if dependencies is not None:
        document["dependencies"] = dependencies
    if metadata_component is not None:
        document["metadata"] = {"component": metadata_component}
    return document
