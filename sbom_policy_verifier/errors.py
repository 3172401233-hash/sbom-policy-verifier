"""Shared error / finding data structures."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class StructuralError:
    """A problem with the SBOM document itself, never silently ignored."""

    code: str
    message: str
    bom_ref: str | None = None


@dataclass(frozen=True)
class ExceptionInfo:
    """Outcome of matching an exception entry against a finding."""

    id: str
    reason: str
    expires_at: str | None
    active: bool
    status: str  # active | expired | missing_expiry


@dataclass
class Finding:
    """A single policy hit, possibly covered by an exception."""

    rule_id: str
    rule_type: str
    component_ref: str
    component: str
    detail: str
    dependency_path: list[str] = field(default_factory=list)
    exception: ExceptionInfo | None = None

    @property
    def exempted(self) -> bool:
        return self.exception is not None and self.exception.active
