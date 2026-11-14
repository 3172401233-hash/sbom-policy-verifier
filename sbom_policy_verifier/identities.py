"""Component identity normalization: purl, name, version, supplier, licenses."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .purl import InvalidPurl, Purl, parse_purl

_LICENSE_SPLIT_RE = re.compile(
    r"\s+(?:AND|OR|WITH)\s+|[(,)]|^[(,)]", re.IGNORECASE
)


def normalize_name(value: str | None) -> str:
    """Lower-case and collapse whitespace; empty string means absent."""
    if not value:
        return ""
    return re.sub(r"\s+", " ", value.strip().lower())


def normalize_version(value: str | None) -> str:
    """Trim and collapse internal whitespace; case preserved for comparison."""
    if not value:
        return ""
    return re.sub(r"\s+", " ", value.strip())


def normalize_supplier(value: dict | str | None) -> str:
    """Extract a stable supplier identity from name or URL."""
    if not value:
        return ""
    if isinstance(value, str):
        text = value
    elif isinstance(value, dict):
        text = str(value.get("name") or value.get("url") or "")
    else:
        return ""
    text = re.sub(r"\s+", " ", text.strip())
    return text.lower()


def extract_license_tokens(license_entry: object) -> list[str]:
    """Pull SPDX license IDs / names out of a CycloneDX license object."""
    tokens: list[str] = []
    if isinstance(license_entry, dict):
        license_obj = license_entry.get("license")
        expression = license_entry.get("expression")
        if isinstance(license_obj, dict):
            token = license_obj.get("id") or license_obj.get("name")
            if token:
                tokens.extend(split_license_expression(str(token)))
        if expression:
            tokens.extend(split_license_expression(str(expression)))
    elif isinstance(license_entry, str):
        tokens.extend(split_license_expression(license_entry))
    return tokens


def split_license_expression(expression: str) -> list[str]:
    """Split an SPDX expression into its individual license identifiers."""
    tokens: list[str] = []
    for part in _LICENSE_SPLIT_RE.split(expression):
        part = part.strip().upper()
        if part and part not in {"AND", "OR", "WITH"}:
            tokens.append(part)
    if not tokens:
        stripped = expression.strip().upper()
        if stripped:
            tokens.append(stripped)
    return tokens


def normalize_licenses(licenses: object) -> tuple[str, ...]:
    if not isinstance(licenses, list):
        return ()
    result: list[str] = []
    seen: set[str] = set()
    for entry in licenses:
        for token in extract_license_tokens(entry):
            if token not in seen:
                seen.add(token)
                result.append(token)
    return tuple(result)


@dataclass
class Component:
    """A normalized CycloneDX component."""

    bom_ref: str
    name: str
    raw_name: str
    version: str
    supplier: str
    licenses: tuple[str, ...] = ()
    purl: Purl | None = None
    purl_canonical: str = ""
    purl_error: str = ""
    has_identity: bool = True
    raw: dict = field(default_factory=dict)

    def display(self) -> str:
        if self.purl_canonical:
            return self.purl_canonical
        label = self.raw_name or self.name
        if self.version:
            return f"{label}@{self.version}"
        return label


def normalize_component(data: dict, fallback_ref: str) -> Component:
    """Build a :class:`Component` from one raw CycloneDX component entry."""
    raw_ref = data.get("bom-ref") or data.get("ref")
    bom_ref = str(raw_ref) if raw_ref is not None else fallback_ref

    raw_name = str(data.get("name") or "").strip()
    name = normalize_name(raw_name)
    version = normalize_version(data.get("version"))
    supplier = normalize_supplier(data.get("supplier"))
    licenses = normalize_licenses(data.get("licenses"))

    purl_obj: Purl | None = None
    purl_canonical = ""
    purl_error = ""
    raw_purl = data.get("purl")
    if raw_purl:
        try:
            purl_obj = parse_purl(str(raw_purl))
            purl_canonical = purl_obj.canonical()
        except InvalidPurl as exc:
            purl_error = str(exc)

    has_identity = bool(purl_obj is not None or name)

    return Component(
        bom_ref=bom_ref,
        name=name,
        raw_name=raw_name,
        version=version,
        supplier=supplier,
        licenses=licenses,
        purl=purl_obj,
        purl_canonical=purl_canonical,
        purl_error=purl_error,
        has_identity=has_identity,
        raw=data,
    )
