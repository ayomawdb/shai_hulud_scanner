"""Command-line interface for the scanner."""

import argparse
import asyncio
import json
import shutil
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .models import ScanReport
from .output import log_info, log_error, print_header, print_summary, set_debug
from .scanner import GitHubScanner


def check_prerequisites():
    """Check that required tools are installed and authenticated."""
    if not shutil.which('gh'):
        log_error("GitHub CLI (gh) is required but not installed")
        print("Install it from: https://cli.github.com/", file=sys.stderr)
        sys.exit(1)

    result = subprocess.run(['gh', 'auth', 'status'], capture_output=True)
    if result.returncode != 0:
        log_error("GitHub CLI is not authenticated. Run 'gh auth login' first.")
        sys.exit(1)


def load_libraries(csv_path: str) -> list[tuple[str, str]]:
    """Load libraries from CSV file."""
    libraries = []
    with open(csv_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(',')
            if len(parts) >= 2:
                lib_name = parts[0].strip()
                lib_version = parts[1].strip()
                libraries.append((lib_name, lib_version))
    return libraries


async def async_main(args: argparse.Namespace) -> int:
    """Async entry point."""
    check_prerequisites()

    if not Path(args.file).exists():
        log_error(f"CSV file not found: {args.file}")
        return 1

    libraries = load_libraries(args.file)
    if not libraries:
        log_error("No libraries found in CSV file")
        return 1

    print_header(args.org, len(libraries), args.concurrency, args.output)

    scanner = GitHubScanner(args.org, args.concurrency)
    results = await scanner.scan_libraries(libraries)

    log_info("Scan complete. Generating report...")

    affected_repos = scanner.aggregate_results(results)

    report = ScanReport(
        scan_date=datetime.now(timezone.utc).isoformat(),
        organization=args.org,
        total_libraries_scanned=len(libraries),
        affected_repositories=len(affected_repos),
        results=[asdict(repo) for repo in affected_repos]
    )

    with open(args.output, 'w') as f:
        json.dump(report.to_dict(), f, indent=2)

    log_info(f"Results written to: {args.output}")
    print_summary(report, scanner.detection_count)

    return 0


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog='shai-hulud-scanner',
        description='Scan GitHub organization for compromised npm libraries'
    )
    parser.add_argument(
        '-g', '--org',
        required=True,
        help='GitHub organization to scan'
    )
    parser.add_argument(
        '-f', '--file',
        required=True,
        help='CSV file with compromised libraries (name,version)'
    )
    parser.add_argument(
        '-c', '--concurrency',
        type=int,
        default=10,
        help='Number of parallel searches (default: 10)'
    )
    parser.add_argument(
        '-o', '--output',
        default='scan-results.json',
        help='Output file for results (default: scan-results.json)'
    )

    args = parser.parse_args()
    return asyncio.run(async_main(args))


if __name__ == '__main__':
    sys.exit(main())
