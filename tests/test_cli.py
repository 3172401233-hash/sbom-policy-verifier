import json
import tempfile
import unittest
import contextlib
import io
from pathlib import Path

from sbom_policy_verifier.cli import main
from tests.helpers import component, make_sbom


class CliTests(unittest.TestCase):
    def test_cli_exit_code_and_json_report(self) -> None:
        sbom = make_sbom(
            [component("bad", "bad-lib", "1.0", purl="pkg:npm/bad-lib@1.0")]
        )
        policy = {
            "rules": [
                {"id": "R-BAD", "type": "deny_component", "purl": "pkg:npm/bad-lib"}
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            sbom_path = Path(tmp) / "sbom.json"
            policy_path = Path(tmp) / "policy.json"
            sbom_path.write_text(json.dumps(sbom), encoding="utf-8")
            policy_path.write_text(json.dumps(policy), encoding="utf-8")

            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                exit_code = main(
                    [str(sbom_path), str(policy_path), "--json"]
                )
            payload = json.loads(buffer.getvalue())

        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["passed"])
        self.assertEqual(payload["findings"][0]["rule_id"], "R-BAD")


if __name__ == "__main__":
    unittest.main()
