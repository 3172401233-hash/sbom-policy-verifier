"""Top-level offline SBOM policy verification engine."""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .errors import Finding, StructuralError
from .graph import DependencyGraph
from .loader import load_sbom
from .policy import Policy, load_policy, match_exception, rule_matches


@dataclass
class Report:
    """Verification result: structural errors plus policy findings."""

    findings: list[Finding] = field(default_factory=list)
    structural_errors: list[StructuralError] = field(default_factory=list)

    @property
    def violations(self) -> list[Finding]:
        return [finding for finding in self.findings if not finding.exempted]

    @property
    def exempted(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.exempted]

    @property
    def passed(self) -> bool:
        return not self.structural_errors and not self.violations

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "structural_errors": [
                {
                    "code": error.code,
                    "message": error.message,
                    "bom_ref": error.bom_ref,
                }
                for error in self.structural_errors
            ],
            "findings": [
                {
                    "rule_id": finding.rule_id,
                    "rule_type": finding.rule_type,
                    "component_ref": finding.component_ref,
                    "component": finding.component,
                    "detail": finding.detail,
                    "dependency_path": finding.dependency_path,
                    "exempted": finding.exempted,
                    "exception": None
                    if finding.exception is None
                    else {
                        "id": finding.exception.id,
                        "reason": finding.exception.reason,
                        "expires_at": finding.exception.expires_at,
                        "active": finding.exception.active,
                        "status": finding.exception.status,
                    },
                }
                for finding in self.findings
            ],
        }


def verify(
    sbom: str | dict[str, Any] | DependencyGraph,
    policy: str | dict[str, Any] | Policy,
    *,
    now: datetime | None = None,
) -> Report:
    """Run all policy rules against an SBOM and return a :class:`Report`."""

    graph = sbom if isinstance(sbom, DependencyGraph) else load_sbom(sbom)
    parsed_policy = policy if isinstance(policy, Policy) else load_policy(policy)
    current = now or datetime.now(timezone.utc)

    report = Report(structural_errors=list(graph.errors))

    for ref, component in graph.component_pairs():
        path_refs = graph.shortest_path(ref)
        path_display = [
            graph.components[node].display()
            for node in path_refs
            if node in graph.components
        ]
        for rule in parsed_policy.rules:
            if not rule_matches(rule, component):
                continue
            detail = rule.message or rule.describe()
            exception = match_exception(
                parsed_policy, rule, component, graph, current
            )
            report.findings.append(
                Finding(
                    rule_id=rule.id,
                    rule_type=rule.type,
                    component_ref=ref,
                    component=component.display(),
                    detail=detail,
                    dependency_path=path_display,
                    exception=exception,
                )
            )

    report.findings.sort(key=lambda finding: (finding.rule_id, finding.component_ref))
    return report
