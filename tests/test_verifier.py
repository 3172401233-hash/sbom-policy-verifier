import unittest
from datetime import datetime, timezone

from sbom_policy_verifier import verify
from tests.helpers import (
    component,
    dependency,
    license_expression,
    license_id,
    make_sbom,
)


def rule(rule_id: str, rule_type: str, **extra) -> dict:
    data = {"id": rule_id, "type": rule_type}
    data.update(extra)
    return data


class TransitiveDependencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sbom = make_sbom(
            [
                component(
                    "app", "gateway", "4.0.0",
                    purl="pkg:npm/gateway@4.0.0",
                    supplier="Acme Corp",
                ),
                component(
                    "framework", "framework", "2.1.0",
                    purl="pkg:npm/framework@2.1.0",
                    supplier="Framework Team",
                ),
                component(
                    "bad-lib", "bad-lib", "1.2.0",
                    purl="pkg:npm/bad-lib@1.2.0",
                    supplier="Evil Inc",
                ),
            ],
            [
                dependency("app", ["framework"]),
                dependency("framework", ["bad-lib"]),
            ],
        )
        self.policy = {
            "rules": [
                rule("R-DENY-BAD", "deny_component", purl="pkg:npm/bad-lib")
            ]
        }

    def test_violation_records_direct_dependency_path(self) -> None:
        report = verify(self.sbom, self.policy)
        self.assertFalse(report.passed)
        self.assertEqual(len(report.violations), 1)
        finding = report.violations[0]
        self.assertEqual(finding.rule_id, "R-DENY-BAD")
        self.assertEqual(
            finding.dependency_path,
            [
                "pkg:npm/gateway@4.0.0",
                "pkg:npm/framework@2.1.0",
                "pkg:npm/bad-lib@1.2.0",
            ],
        )

    def test_purl_match_is_version_agnostic_and_normalized(self) -> None:
        sbom = make_sbom(
            [
                component(
                    "x", "Bad-Lib", "9.9.9",
                    purl="pkg:NPM/bad-lib@9.9.9",
                    supplier="x",
                )
            ]
        )
        report = verify(sbom, self.policy)
        self.assertEqual(len(report.violations), 1)


class VersionRangeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sbom = make_sbom(
            [
                component("v-old", "shared", "1.2.0", purl="pkg:maven/shared@1.2.0"),
                component("v-mid", "shared", "1.5.0", purl="pkg:maven/shared@1.5.0"),
                component("v-new", "shared", "2.0.0", purl="pkg:maven/shared@2.0.0"),
            ]
        )
        self.policy = {
            "rules": [
                rule(
                    "R-OLD-SHARED",
                    "deny_version",
                    purl="pkg:maven/shared",
                    version_range=">=1.0.0, <2.0.0",
                )
            ]
        }

    def test_only_versions_inside_range_are_denied(self) -> None:
        report = verify(self.sbom, self.policy)
        refs = {finding.component_ref for finding in report.violations}
        self.assertEqual(refs, {"v-old", "v-mid"})

    def test_same_name_different_version_is_not_text_confused(self) -> None:
        name_policy = {
            "rules": [
                rule(
                    "R-NAME-V",
                    "deny_component",
                    name="shared",
                    version_range="==1.5.0",
                )
            ]
        }
        report = verify(self.sbom, name_policy)
        self.assertEqual(len(report.violations), 1)
        self.assertEqual(report.violations[0].component_ref, "v-mid")


class LicenseTests(unittest.TestCase):
    def test_license_combinations_and_expressions(self) -> None:
        sbom = make_sbom(
            [
                component(
                    "mit-lib", "mit-lib", "1.0",
                    purl="pkg:generic/mit-lib@1.0",
                    licenses=[license_id("MIT")],
                ),
                component(
                    "dual-lib", "dual-lib", "1.0",
                    purl="pkg:generic/dual-lib@1.0",
                    licenses=[license_expression("MIT OR GPL-3.0-only")],
                ),
                component(
                    "apache-lib", "apache-lib", "1.0",
                    purl="pkg:generic/apache-lib@1.0",
                    licenses=[license_id("Apache-2.0")],
                ),
            ]
        )
        policy = {
            "rules": [
                rule("R-GPL", "deny_license", licenses=["GPL-3.0-only"])
            ]
        }
        report = verify(sbom, policy)
        refs = {finding.component_ref for finding in report.violations}
        self.assertEqual(refs, {"dual-lib"})


class MissingSupplierTests(unittest.TestCase):
    def test_components_without_supplier_are_denied(self) -> None:
        sbom = make_sbom(
            [
                component("ok", "ok", "1.0", purl="pkg:generic/ok@1.0",
                          supplier={"name": "Vendor"}),
                component("naked", "naked", "1.0",
                          purl="pkg:generic/naked@1.0"),
            ]
        )
        policy = {"rules": [rule("R-SUPPLIER", "deny_missing_supplier")]}
        report = verify(sbom, policy)
        self.assertEqual(len(report.violations), 1)
        self.assertEqual(report.violations[0].component_ref, "naked")

    def test_supplier_rule_can_be_scoped_with_a_selector(self) -> None:
        sbom = make_sbom(
            [
                component("a", "alpha", "1.0", purl="pkg:generic/alpha@1.0"),
                component("b", "beta", "1.0", purl="pkg:generic/beta@1.0"),
            ]
        )
        policy = {
            "rules": [
                rule(
                    "R-ALPHA-SUPPLIER",
                    "deny_missing_supplier",
                    purl="pkg:generic/alpha",
                )
            ]
        }
        report = verify(sbom, policy)
        self.assertEqual([f.component_ref for f in report.violations], ["a"])


class ExceptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sbom = make_sbom(
            [
                component(
                    "bad", "bad-lib", "1.0",
                    purl="pkg:npm/bad-lib@1.0",
                    supplier="x",
                )
            ]
        )
        self.rule = rule("R-BAD", "deny_component", purl="pkg:npm/bad-lib")
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def _policy(self, expires_at: str | None, **extra) -> dict:
        exception = {
            "id": "EX-1",
            "rule_id": "R-BAD",
            "reason": "mitigated by WAF rule",
            "expires_at": expires_at,
        }
        exception.update(extra)
        return {"rules": [self.rule], "exceptions": [exception]}

    def test_active_exception_suppresses_violation(self) -> None:
        report = verify(
            self.sbom,
            self._policy("2026-06-01T00:00:00Z"),
            now=self.now,
        )
        self.assertTrue(report.passed)
        self.assertEqual(len(report.exempted), 1)
        info = report.exempted[0].exception
        self.assertEqual(info.status, "active")
        self.assertTrue(info.active)

    def test_expired_exception_does_not_suppress_violation(self) -> None:
        report = verify(
            self.sbom,
            self._policy("2025-12-31T23:59:59Z"),
            now=self.now,
        )
        self.assertFalse(report.passed)
        self.assertEqual(len(report.violations), 1)
        info = report.findings[0].exception
        self.assertIsNotNone(info)
        self.assertEqual(info.status, "expired")
        self.assertFalse(info.active)

    def test_exception_without_expiry_is_invalid(self) -> None:
        report = verify(self.sbom, self._policy(None), now=self.now)
        self.assertEqual(len(report.violations), 1)
        self.assertEqual(report.findings[0].exception.status, "missing_expiry")

    def test_exception_selector_must_match_component(self) -> None:
        report = verify(
            self.sbom,
            self._policy("2026-06-01T00:00:00Z", purl="pkg:npm/other-lib"),
            now=self.now,
        )
        self.assertEqual(len(report.violations), 1)
        self.assertIsNone(report.findings[0].exception)


class RenamedPackageTests(unittest.TestCase):
    def test_text_name_matching_does_not_bypass_purl_rule(self) -> None:
        sbom = make_sbom(
            [
                component(
                    "renamed", "totally-benign-name", "1.0",
                    purl="pkg:npm/bad-lib@1.0",
                    supplier="x",
                )
            ]
        )
        policy = {
            "rules": [
                rule("R-BAD", "deny_component", purl="pkg:npm/bad-lib")
            ]
        }
        report = verify(sbom, policy)
        self.assertEqual(len(report.violations), 1)
        self.assertEqual(report.violations[0].component_ref, "renamed")


class ReportShapeTests(unittest.TestCase):
    def test_clean_sbom_passes_and_serializes(self) -> None:
        sbom = make_sbom(
            [component("ok", "ok", "1.0", purl="pkg:generic/ok@1.0",
                       supplier="Vendor")]
        )
        report = verify(sbom, {"rules": []})
        self.assertTrue(report.passed)
        payload = report.to_dict()
        self.assertTrue(payload["passed"])
        self.assertEqual(payload["structural_errors"], [])
        self.assertEqual(payload["findings"], [])


if __name__ == "__main__":
    unittest.main()
