"""Offline CycloneDX SBOM policy verifier."""

from .errors import ExceptionInfo, Finding, StructuralError
from .graph import DependencyGraph, build_graph
from .identities import Component, normalize_component
from .loader import load_sbom
from .policy import Policy, Rule, load_policy, rule_matches
from .purl import InvalidPurl, Purl, parse_purl
from .verifier import Report, verify
from .versions import InvalidConstraint, Version, version_in_range

__all__ = [
    "Component",
    "DependencyGraph",
    "ExceptionInfo",
    "Finding",
    "InvalidConstraint",
    "InvalidPurl",
    "Policy",
    "Purl",
    "Report",
    "Rule",
    "StructuralError",
    "Version",
    "build_graph",
    "load_policy",
    "load_sbom",
    "normalize_component",
    "parse_purl",
    "rule_matches",
    "verify",
    "version_in_range",
]

__version__ = "1.0.0"
