"""Minimal offline Package URL (purl) parser and normalizer.

Implements the subset of the Package URL specification needed for stable
component identity comparison without any third-party dependency.
See https://github.com/package-url/purl-spec
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote, unquote


class InvalidPurl(ValueError):
    """Raised when a purl string cannot be parsed."""


def _decode(value: str) -> str:
    return unquote(value).strip()


def _quote(value: str) -> str:
    return quote(value, safe="")


def _split_path(value: str) -> tuple[str, ...]:
    parts: list[str] = []
    for segment in value.split("/"):
        segment = _decode(segment)
        if segment and segment not in (".", ".."):
            parts.append(segment)
    return tuple(parts)


def _parse_qualifiers(query: str) -> tuple[tuple[str, str], ...]:
    parsed: dict[str, str] = {}
    for pair in query.split("&"):
        if not pair:
            continue
        if "=" not in pair:
            raise InvalidPurl(f"invalid purl qualifier: {pair!r}")
        key, value = pair.split("=", 1)
        key = _decode(key).lower()
        if not key:
            raise InvalidPurl("purl qualifier key is empty")
        parsed[key] = _decode(value)
    return tuple(sorted(parsed.items()))


@dataclass(frozen=True)
class Purl:
    """Normalized Package URL coordinates."""

    type: str
    namespace: tuple[str, ...]
    name: str
    version: str | None
    qualifiers: tuple[tuple[str, str], ...]
    subpath: tuple[str, ...]
    raw: str

    @property
    def namespace_str(self) -> str | None:
        return "/".join(self.namespace) if self.namespace else None

    @property
    def subpath_str(self) -> str | None:
        return "/".join(self.subpath) if self.subpath else None

    def canonical(self, *, with_version: bool = True) -> str:
        text = f"pkg:{self.type}/"
        if self.namespace:
            text += "/".join(_quote(part) for part in self.namespace) + "/"
        text += _quote(self.name)
        if with_version and self.version is not None:
            text += "@" + _quote(self.version)
        if self.qualifiers:
            text += "?" + "&".join(f"{key}={_quote(val)}" for key, val in self.qualifiers)
        if self.subpath:
            text += "#" + "/".join(_quote(part) for part in self.subpath)
        return text

    def same_coordinates(self, other: "Purl", *, compare_version: bool = False) -> bool:
        """Compare type/namespace/name (and optionally version)."""
        if (self.type, self.namespace, self.name) != (
            other.type,
            other.namespace,
            other.name,
        ):
            return False
        if compare_version and self.version != other.version:
            return False
        return True


def parse_purl(text: str) -> Purl:
    """Parse and normalize a purl string.

    Raises :class:`InvalidPurl` for malformed input.
    """

    if not isinstance(text, str) or not text.strip():
        raise InvalidPurl("purl must be a non-empty string")
    raw = text.strip()
    if not raw.lower().startswith("pkg:"):
        raise InvalidPurl(f"purl must start with 'pkg:': {text!r}")

    rest = raw[4:]

    subpath: tuple[str, ...] = ()
    if "#" in rest:
        rest, fragment = rest.split("#", 1)
        subpath = _split_path(fragment)

    qualifiers: tuple[tuple[str, str], ...] = ()
    if "?" in rest:
        rest, query = rest.split("?", 1)
        qualifiers = _parse_qualifiers(query)

    version: str | None = None
    if "@" in rest:
        rest, raw_version = rest.rsplit("@", 1)
        version = _decode(raw_version)

    if "/" not in rest:
        raise InvalidPurl(f"purl is missing component name: {text!r}")
    raw_type, path = rest.split("/", 1)
    purl_type = _decode(raw_type).lower()
    if not purl_type:
        raise InvalidPurl(f"purl is missing package type: {text!r}")

    segments = [
        segment for segment in (_decode(part).lower() for part in path.split("/")) if segment
    ]
    if not segments:
        raise InvalidPurl(f"purl is missing component name: {text!r}")

    name = segments[-1]
    namespace = tuple(segments[:-1])
    return Purl(
        type=purl_type,
        namespace=namespace,
        name=name,
        version=version,
        qualifiers=qualifiers,
        subpath=subpath,
        raw=raw,
    )
