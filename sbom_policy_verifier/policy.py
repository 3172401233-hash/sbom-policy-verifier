"""Policy rule and exception model with offline matching logic."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import ExceptionInfo
from .graph import DependencyGraph
from .identities import Component, normalize_name
from .purl import InvalidPurl, parse_purl
from .versions import InvalidConstraint, version_in_range

RULE_TYPES = ("deny_component", "deny_version", "deny_license", "deny_missing_supplier")


class PolicyError(ValueError):
    """Raised when a policy document is malformed."""


@dataclass
class Rule:
    """A single deny rule. All set selectors must match (logical AND)."""

    id: str
    type: str
    purl: str | None = None
    name: str | None = None
    version_range: str | list[str] | None = None
    licenses: tuple[str, ...] = ()
    message: str = ""
    _parsed_purl: Any = None

    def describe(self) -> str:
        parts = [f"rule {self.id!r} ({self.type})"]
        if self.purl:
            parts.append(f"purl~{self.purl}")
        if self.name:
            parts.append(f"name~{self.name}")
        if self.version_range is not None:
            parts.append(f"version~{self.version_range}")
        if self.licenses:
            parts.append(f"license~{'/'.join(self.licenses)}")
        return ", ".join(parts)


@dataclass
class ExceptionEntry:
    """Time-bounded exception attached to a rule and component selectors."""

    id: str
    rule_id: str
    purl: str | None = None
    name: str | None = None
    reason: str = ""
    expires_at: datetime | None = None
    expires_raw: str | None = None
    _parsed_purl: Any = None

    def evaluate(self, now: datetime) -> ExceptionInfo:
        if self.expires_at is None:
            return ExceptionInfo(
                id=self.id,
                reason=self.reason,
                expires_at=self.expires_raw,
                active=False,
                status="missing_expiry",
            )
        active = now < self.expires_at
        return ExceptionInfo(
            id=self.id,
            reason=self.reason,
            expires_at=self.expires_raw,
            active=active,
            status="active" if active else "expired",
        )


@dataclass
class Policy:
    rules: list[Rule] = field(default_factory=list)
    exceptions: list[ExceptionEntry] = field(default_factory=list)

    def rule_map(self) -> dict[str, Rule]:
        return {rule.id: rule for rule in self.rules}

    def exceptions_for(self, rule_id: str) -> list[ExceptionEntry]:
        return [entry for entry in self.exceptions if entry.rule_id == rule_id]


def _parse_expiry(value: Any) -> tuple[datetime | None, str | None]:
    if value in (None, ""):
        return None, None
    text = str(value).strip()
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise PolicyError(f"invalid expires_at value {text!r}: {exc}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed, text


def _optional_purl(value: Any, context: str) -> Any:
    if not value:
        return None
    try:
        return parse_purl(str(value))
    except InvalidPurl as exc:
        raise PolicyError(f"{context} contains invalid purl {value!r}: {exc}") from exc


def load_policy(source: str | Path | dict[str, Any]) -> Policy:
    """Parse a policy JSON document (path, JSON string or dict)."""

    if isinstance(source, dict):
        data = source
    elif isinstance(source, (str, Path)):
        path = Path(source)
        if path.exists() and path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
        else:
            data = json.loads(str(source))
    else:
        raise TypeError(f"unsupported policy source: {type(source).__name__}")
    if not isinstance(data, dict):
        raise PolicyError("policy document must be a JSON object")

    rules: list[Rule] = []
    seen_rule_ids: set[str] = set()
    for index, raw in enumerate(data.get("rules") or []):
        if not isinstance(raw, dict):
            raise PolicyError(f"rules[{index}] must be an object")
        rule_id = str(raw.get("id") or f"rule-{index}")
        if rule_id in seen_rule_ids:
            raise PolicyError(f"duplicate rule id {rule_id!r}")
        seen_rule_ids.add(rule_id)
        rule_type = str(raw.get("type") or "")
        if rule_type not in RULE_TYPES:
            raise PolicyError(
                f"rule {rule_id!r} has unsupported type {rule_type!r}; "
                f"expected one of {sorted(RULE_TYPES)}"
            )
        range_spec = raw.get("version_range", raw.get("version"))
        if range_spec is not None:
            try:
                version_in_range("0.0.0", range_spec)
            except InvalidConstraint as exc:
                raise PolicyError(f"rule {rule_id!r}: {exc}") from exc
        licenses = tuple(
            str(item).strip().upper()
            for item in (raw.get("licenses") or [])
            if str(item).strip()
        )
        rules.append(
            Rule(
                id=rule_id,
                type=rule_type,
                purl=str(raw["purl"]) if raw.get("purl") else None,
                name=normalize_name(raw.get("name")) or None,
                version_range=range_spec,
                licenses=licenses,
                message=str(raw.get("message") or ""),
                _parsed_purl=_optional_purl(raw.get("purl"), f"rule {rule_id!r}"),
            )
        )

    exceptions: list[ExceptionEntry] = []
    seen_exception_ids: set[str] = set()
    for index, raw in enumerate(data.get("exceptions") or []):
        if not isinstance(raw, dict):
            raise PolicyError(f"exceptions[{index}] must be an object")
        exc_id = str(raw.get("id") or f"exception-{index}")
        if exc_id in seen_exception_ids:
            raise PolicyError(f"duplicate exception id {exc_id!r}")
        seen_exception_ids.add(exc_id)
        rule_id = str(raw.get("rule_id") or "")
        if rule_id not in seen_rule_ids:
            raise PolicyError(
                f"exception {exc_id!r} references unknown rule_id {rule_id!r}"
            )
        expires_at, expires_raw = _parse_expiry(raw.get("expires_at"))
        exceptions.append(
            ExceptionEntry(
                id=exc_id,
                rule_id=rule_id,
                purl=str(raw["purl"]) if raw.get("purl") else None,
                name=normalize_name(raw.get("name")) or None,
                reason=str(raw.get("reason") or ""),
                expires_at=expires_at,
                expires_raw=expires_raw,
                _parsed_purl=_optional_purl(raw.get("purl"), f"exception {exc_id!r}"),
            )
        )

    return Policy(rules=rules, exceptions=exceptions)


def _purl_matches(rule_purl: Any, component: Component) -> bool:
    if rule_purl is None:
        return True
    if component.purl is None:
        return False
    return component.purl.same_coordinates(rule_purl)


def _name_matches(rule_name: str | None, component: Component) -> bool:
    if not rule_name:
        return True
    return component.name == rule_name


def rule_matches(rule: Rule, component: Component) -> bool:
    """Evaluate selectors plus rule-type-specific predicates."""

    if not _purl_matches(rule._parsed_purl, component):
        return False
    if not _name_matches(rule.name, component):
        return False

    if rule.type == "deny_missing_supplier":
        return not component.supplier

    if rule.type == "deny_license":
        if not rule.licenses:
            raise PolicyError(f"rule {rule.id!r} requires at least one license")
        return any(license in component.licenses for license in rule.licenses)

    if rule.type == "deny_version":
        if rule.version_range is None:
            raise PolicyError(f"rule {rule.id!r} requires a version_range")
        if not version_in_range(component.version or None, rule.version_range):
            return False

    if rule.type == "deny_component" and rule.version_range is not None:
        if not version_in_range(component.version or None, rule.version_range):
            return False

    return True


def exception_matches(entry: ExceptionEntry, component: Component) -> bool:
    if not _purl_matches(entry._parsed_purl, component):
        return False
    if not _name_matches(entry.name, component):
        return False
    return True


def match_exception(
    policy: Policy,
    rule: Rule,
    component: Component,
    graph: DependencyGraph,
    now: datetime,
) -> ExceptionInfo | None:
    """Return the best exception covering a hit, or None.

    An active exception wins; otherwise an expired one is reported so the
    caller can see the exception is no longer effective.
    """

    fallback: ExceptionInfo | None = None
    for entry in policy.exceptions_for(rule.id):
        if not exception_matches(entry, component):
            continue
        info = entry.evaluate(now)
        if info.active:
            return info
        if fallback is None or fallback.status == "missing_expiry":
            fallback = info
    return fallback
