import unittest

from sbom_policy_verifier.loader import load_sbom
from tests.helpers import component, dependency, make_sbom


def error_codes(graph) -> list[str]:
    return [error.code for error in graph.errors]


class StructuralValidationTests(unittest.TestCase):
    def test_duplicate_bom_ref_is_reported(self) -> None:
        sbom = make_sbom(
            [
                component("ref-a", "left", "1.0"),
                component("ref-a", "right", "2.0"),
            ]
        )
        graph = load_sbom(sbom)
        self.assertIn("duplicate_bom_ref", error_codes(graph))
        self.assertEqual(graph.components["ref-a"].raw_name, "left")

    def test_dangling_dependency_references_are_reported(self) -> None:
        sbom = make_sbom(
            [component("app", "app", "1.0")],
            [dependency("app", ["missing-lib"]), dependency("ghost", ["app"])],
        )
        graph = load_sbom(sbom)
        self.assertEqual(error_codes(graph).count("dangling_reference"), 2)

    def test_unknown_identity_and_invalid_purl_are_reported(self) -> None:
        sbom = make_sbom(
            [
                {"bom-ref": "no-identity", "version": "1.0"},
                component("bad-purl", "named", "1.0", purl="http://not-a-purl"),
            ]
        )
        graph = load_sbom(sbom)
        codes = error_codes(graph)
        self.assertIn("unknown_identity", codes)
        self.assertIn("invalid_purl", codes)

    def test_dependency_cycle_is_detected(self) -> None:
        sbom = make_sbom(
            [
                component("a", "alpha", "1.0"),
                component("b", "bravo", "1.0"),
                component("c", "charlie", "1.0"),
            ],
            [
                dependency("a", ["b"]),
                dependency("b", ["c"]),
                dependency("c", ["a"]),
            ],
        )
        graph = load_sbom(sbom)
        self.assertIn("dependency_cycle", error_codes(graph))

    def test_unsupported_bom_format_is_reported(self) -> None:
        sbom = make_sbom([component("a", "alpha", "1.0")])
        sbom["bomFormat"] = "SPDX"
        graph = load_sbom(sbom)
        self.assertEqual(graph.errors[0].code, "unsupported_format")


class ReachabilityTests(unittest.TestCase):
    def test_shortest_path_follows_transitive_edges(self) -> None:
        sbom = make_sbom(
            [
                component("app", "app", "1.0"),
                component("lib", "lib", "1.0"),
                component("util", "util", "1.0"),
                component("extra", "extra", "1.0"),
            ],
            [
                dependency("app", ["lib", "extra"]),
                dependency("lib", ["util"]),
                dependency("extra", ["util"]),
            ],
        )
        graph = load_sbom(sbom)
        self.assertEqual(graph.roots, ["app"])
        path = graph.shortest_path("util")
        self.assertEqual(len(path), 3)
        self.assertEqual(path[0], "app")
        self.assertEqual(path[-1], "util")

    def test_unreferenced_components_are_roots(self) -> None:
        sbom = make_sbom(
            [component("a", "a", "1.0"), component("b", "b", "1.0")],
            [dependency("a", ["b"])],
        )
        graph = load_sbom(sbom)
        self.assertEqual(graph.roots, ["a"])


if __name__ == "__main__":
    unittest.main()
