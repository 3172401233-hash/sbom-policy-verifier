import unittest

from sbom_policy_verifier.purl import InvalidPurl, parse_purl


class PurlParsingTests(unittest.TestCase):
    def test_canonical_form_normalizes_case_and_qualifiers(self) -> None:
        purl = parse_purl("pkg:NPM/@Acme/Weird-Pkg@1.2.3?B=2&A=1#sub/path")
        self.assertEqual(purl.type, "npm")
        self.assertEqual(purl.namespace, ("@acme",))
        self.assertEqual(purl.name, "weird-pkg")
        self.assertEqual(purl.version, "1.2.3")
        self.assertEqual(purl.qualifiers, (("a", "1"), ("b", "2")))
        self.assertEqual(purl.subpath, ("sub", "path"))
        self.assertEqual(
            purl.canonical(),
            "pkg:npm/%40acme/weird-pkg@1.2.3?a=1&b=2#sub/path",
        )

    def test_same_coordinates_ignores_version_by_default(self) -> None:
        old = parse_purl("pkg:maven/org.example/lib@1.0")
        new = parse_purl("pkg:maven/org.example/lib@2.0")
        self.assertTrue(old.same_coordinates(new))
        self.assertFalse(old.same_coordinates(new, compare_version=True))

    def test_rejects_malformed_purl(self) -> None:
        for bad in ("", "   ", "not-a-purl", "pkg:", "pkg:npm", "pkg:npm/@1.0"):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidPurl):
                    parse_purl(bad)

    def test_url_encoded_segments_are_decoded(self) -> None:
        purl = parse_purl("pkg:generic/group%20name/my%20lib@1.0.0")
        self.assertEqual(purl.namespace, ("group name",))
        self.assertEqual(purl.name, "my lib")
        self.assertEqual(purl.canonical(), "pkg:generic/group%20name/my%20lib@1.0.0")


if __name__ == "__main__":
    unittest.main()
