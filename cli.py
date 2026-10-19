import argparse
import csv
import logging
from pathlib import Path

from scanner import scan_path, mask_secret


# ==========================================
# COMMAND-LINE ARGUMENTS
# ==========================================

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="SecretGuard - Hardcoded Secret Scanner"
    )

    parser.add_argument(
        "path",
        help="File or directory to scan"
    )

    parser.add_argument(
        "-o", "--output",
        help="Export findings to a CSV file"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable detailed logging"
    )

    parser.add_argument(
        "--show-secrets",
        action="store_true",
        help="Display full matches (sensitive)"
    )

    return parser.parse_args()


# ==========================================
# CSV EXPORT
# ==========================================

def export_csv(
    findings,
    output_path,
    show_secrets=False
):
    """
    Export scan results in CSV format.
    Secrets are masked unless explicitly
    requested.
    """
    output = Path(output_path)

    with output.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "Filename",
            "Line Number",
            "Column",
            "Secret Type",
            "Matched String"
        ])

        for finding in findings:
            matched = (
                finding["match"]
                if show_secrets
                else mask_secret(finding["match"])
            )

            # Prevent spreadsheet formula injection
            if matched.startswith(
                ("=", "+", "-", "@", "\t", "\r")
            ):
                matched = "'" + matched

            writer.writerow([
                finding["file"],
                finding["line"],
                finding.get("column", ""),
                finding["type"],
                matched
            ])


# ==========================================
# MAIN PROGRAM
# ==========================================

def main():
    args = parse_arguments()

    logging.basicConfig(
        level=(
            logging.INFO
            if args.verbose
            else logging.WARNING
        ),
        format="%(levelname)s: %(message)s"
    )

    print("=" * 40)
    print("          SECRETGUARD")
    print("     Hardcoded Secret Scanner")
    print("=" * 40)

    try:
        exclusions = (
            [args.output] if args.output else []
        )

        findings = scan_path(
            args.path,
            exclude_paths=exclusions
        )

    except (OSError, ValueError) as error:
        logging.error("Scan failed: %s", error)
        return 1

    print(
        f"\nPotential secrets found: "
        f"{len(findings)}\n"
    )

    if not findings:
        print("No matching patterns detected.")

    for finding in findings:
        matched = (
            finding["match"]
            if args.show_secrets
            else mask_secret(finding["match"])
        )

        print(f"File: {finding['file']}")
        print(f"Line: {finding['line']}")
        print(f"Column: {finding.get('column', '')}")
        print(f"Type: {finding['type']}")
        print(f"Match: {matched}")
        print("-" * 40)

    if args.output:
        try:
            export_csv(
                findings,
                args.output,
                show_secrets=args.show_secrets
            )

            print(
                f"\nCSV report saved: {args.output}"
            )

        except OSError as error:
            logging.error(
                "Export failed: %s", error
            )
            return 1

    print("\nScan completed.")

    return 0


# ==========================================
# PROGRAM ENTRY POINT
# ==========================================

if __name__ == "__main__":
    raise SystemExit(main())
