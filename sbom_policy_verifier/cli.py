"""Command line entry point: ``python -m sbom_policy_verifier``."""

from __future__ import annotations

import argparse
import json
import sys

from .verifier import verify


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbom-policy-verifier",
        description="Offline CycloneDX JSON SBOM policy validator",
    )
    parser.add_argument("sbom", help="path to a CycloneDX JSON SBOM file")
    parser.add_argument("policy", help="path to a policy JSON file")
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="emit the full report as JSON instead of human-readable text",
    )
    return parser


def _print_text(report) -> None:
    if report.structural_errors:
        print("Structural errors:")
        for error in report.structural_errors:
            suffix = f" (bom-ref: {error.bom_ref})" if error.bom_ref else ""
            print(f"  - [{error.code}] {error.message}{suffix}")
    else:
        print("No structural errors.")

    if report.findings:
        print("\nPolicy findings:")
        for finding in report.findings:
            status = "EXEMPTED" if finding.exempted else "VIOLATION"
            print(f"  - [{status}] {finding.rule_id} -> {finding.component}")
            print(f"      {finding.detail}")
            if finding.dependency_path:
                print("      path: " + " -> ".join(finding.dependency_path))
            if finding.exception is not None:
                exc = finding.exception
                print(
                    f"      exception {exc.id} ({exc.status}): "
                    f"{exc.reason!r}, expires_at={exc.expires_at}"
                )
    else:
        print("\nNo policy findings.")

    print(f"\nResult: {'PASS' if report.passed else 'FAIL'}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = verify(args.sbom, args.policy)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json_output:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        _print_text(report)
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
