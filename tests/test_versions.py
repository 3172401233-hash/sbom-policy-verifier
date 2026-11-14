import unittest

from sbom_policy_verifier.versions import InvalidConstraint, Version, version_in_range


class VersionComparisonTests(unittest.TestCase):
    def test_numeric_and_prerelease_ordering(self) -> None:
        self.assertTrue(Version("1.10.2") > Version("1.9.9"))
        self.assertTrue(Version("2.0") > Version("1.99.99"))
        self.assertTrue(Version("1.0.0-alpha") < Version("1.0.0"))
        self.assertEqual(Version("1.2.3"), Version("1.2.3"))

    def test_range_operators(self) -> None:
        self.assertTrue(version_in_range("1.5.0", ">=1.0.0, <2.0.0"))
        self.assertFalse(version_in_range("2.0.0", ">=1.0.0, <2.0.0"))
        self.assertTrue(version_in_range("3.1", "==3.1"))
        self.assertTrue(version_in_range("0.9", "!=1.0"))
        self.assertTrue(version_in_range("2.0", ["<1.0", ">=2.0"]))
        self.assertFalse(version_in_range("1.5", ["<1.0", ">=2.0"]))

    def test_bare_version_means_exact_match(self) -> None:
        self.assertTrue(version_in_range("4.2.1", "4.2.1"))
        self.assertFalse(version_in_range("4.2.2", "4.2.1"))

    def test_missing_version_never_matches(self) -> None:
        self.assertFalse(version_in_range(None, ">=1.0"))

    def test_invalid_constraint_raises(self) -> None:
        with self.assertRaises(InvalidConstraint):
            version_in_range("1.0", ">= ")
        with self.assertRaises(InvalidConstraint):
            version_in_range("1.0", [])


if __name__ == "__main__":
    unittest.main()
