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
from .output import log_info, log_error, log_warn, print_header, print_summary, set_debug
from .scanner import GitHubScanner
from .branches import BranchDiscovery, save_branches, load_branches
from .branch_scanner import BranchScanner


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


def write_output(output_file: str, scanner: GitHubScanner, libraries_count: int):
    """Write final output report."""
    affected_repos = scanner.aggregate_results(scanner.results)

    report = ScanReport(
        scan_date=datetime.now(timezone.utc).isoformat(),
        organization=scanner.org,
        total_libraries_scanned=libraries_count,
        affected_repositories=len(affected_repos),
        results=[asdict(repo) for repo in affected_repos]
    )

    with open(output_file, 'w') as f:
        json.dump(report.to_dict(), f, indent=2)

    return report


async def async_main(args: argparse.Namespace) -> int:
    """Async entry point."""
    if args.debug:
        set_debug(True)

    check_prerequisites()

    if not Path(args.file).exists():
        log_error(f"CSV file not found: {args.file}")
        return 1

    libraries = load_libraries(args.file)
    if not libraries:
        log_error("No libraries found in CSV file")
        return 1

    # Branch scanning mode
    if args.scan_branches:
        return await run_branch_scan(args, libraries)

    # Default: code search mode
    return await run_code_search_scan(args, libraries)


async def run_branch_scan(args: argparse.Namespace, libraries: list[tuple[str, str]]) -> int:
    """Run branch-based scanning."""
    branches_file = args.branches_file or f"{args.output}.branches.json"

    # Phase 1: Discover branches (or load from file)
    discovery = None
    if not args.fresh and Path(branches_file).exists():
        discovery = load_branches(branches_file)
        if discovery:
            if discovery.organization != args.org:
                log_warn(f"Branches file is for different org ({discovery.organization}), re-discovering")
                discovery = None
            else:
                log_info(f"Loaded {discovery.total_branches} branches from {discovery.total_repos} repos")

    if not discovery:
        log_info("Discovering active branches...")
        discoverer = BranchDiscovery(args.org, args.branch_age, args.concurrency)
        discovery = await discoverer.discover()
        save_branches(discovery, branches_file)
        log_info(f"Found {discovery.total_branches} active branches in {discovery.total_repos} repos")

    if discovery.total_branches == 0:
        log_warn("No active branches found to scan")
        return 0

    # Phase 2: Scan branches
    scanner = BranchScanner(
        args.org,
        args.concurrency,
        output_file=args.output
    )

    # Check for existing state to resume
    resumed = False
    if not args.fresh:
        state = scanner.load_state()
        if state:
            if state.organization != args.org:
                log_warn(f"State file is for different org, starting fresh")
                scanner.clear_state()
            else:
                resumed = True
                scanned = len(state.scanned_libraries)
                total = state.total_libraries
                log_info(f"Resuming: {scanned}/{total} branches already scanned")
                log_info(f"Found {len(state.detections)} detections so far")
                if scanner.results:
                    scanner._write_output(discovery.total_branches)

    print_header_branches(args.org, len(libraries), discovery.total_branches, args.concurrency, args.output)

    if resumed and scanner.scan_state:
        print(f"  Resuming from: {scanner.scan_state.started_at}", file=sys.stderr)
        print("", file=sys.stderr)

    try:
        await scanner.scan_branches(discovery, libraries)

        log_info("Scan complete. Generating report...")

        scanner._write_output(discovery.total_branches)
        scanner.clear_state()

        log_info(f"Results written to: {args.output}")

        # Print summary
        print_summary_branches(scanner, discovery.total_branches)

    except (KeyboardInterrupt, asyncio.CancelledError):
        print("", file=sys.stderr)
        log_warn("Scan interrupted. Progress saved - run again to resume.")
        await scanner._save_state(discovery.total_branches)
        scanner._write_output(discovery.total_branches)
        return 130

    return 0


async def run_code_search_scan(args: argparse.Namespace, libraries: list[tuple[str, str]]) -> int:
    """Run code search based scanning (default mode)."""
    scanner = GitHubScanner(
        args.org,
        args.concurrency,
        output_file=args.output
    )

    # Check for existing state to resume
    resumed = False
    if not args.fresh:
        state = scanner.load_state()
        if state:
            if state.organization != args.org:
                log_warn(f"State file is for different org ({state.organization}), starting fresh")
                scanner.clear_state()
            else:
                resumed = True
                scanned = len(state.scanned_libraries)
                total = state.total_libraries
                log_info(f"Resuming previous scan: {scanned}/{total} libraries already scanned")
                log_info(f"Found {len(state.detections)} detections so far")
                # Write output file immediately with existing detections
                if scanner.results:
                    write_output(args.output, scanner, len(libraries))

    print_header(args.org, len(libraries), args.concurrency, args.output)

    if resumed and scanner.scan_state:
        print(f"  Resuming from: {scanner.scan_state.started_at}", file=sys.stderr)
        print("", file=sys.stderr)

    try:
        await scanner.scan_libraries(libraries)

        log_info("Scan complete. Generating report...")

        report = write_output(args.output, scanner, len(libraries))

        # Write detailed findings file
        scanner._write_findings()
        findings_file = scanner._get_findings_file()

        # Clear state file on successful completion
        scanner.clear_state()

        log_info(f"Results written to: {args.output}")
        log_info(f"Detailed findings written to: {findings_file}")
        print_summary(report, scanner.detection_count)

        # Show findings summary
        if scanner.all_findings:
            non_matches = sum(1 for f in scanner.all_findings if not f.is_match)
            if non_matches > 0:
                log_info(f"Found {non_matches} repos with different versions of searched libraries (see {findings_file})")

    except (KeyboardInterrupt, asyncio.CancelledError):
        print("", file=sys.stderr)  # Newline after ^C
        log_warn("Scan interrupted. Progress saved - run again to resume.")
        # Save state one more time to ensure we have latest
        await scanner._save_state(len(libraries))
        scanner._write_output(len(libraries))
        scanner._write_findings()
        return 130  # Standard exit code for SIGINT

    return 0


def print_header_branches(org: str, total_libs: int, total_branches: int, concurrency: int, output_file: str):
    """Print header for branch scanning mode."""
    from .output import Colors
    print("")
    print(f"{Colors.BOLD}════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.BOLD}  SHAI-HULUD SCANNER (Branch Mode){Colors.NC}")
    print(f"{Colors.BOLD}════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"  Organization:    {Colors.CYAN}{org}{Colors.NC}")
    print(f"  Libraries:       {Colors.CYAN}{total_libs}{Colors.NC}")
    print(f"  Branches:        {Colors.CYAN}{total_branches}{Colors.NC}")
    print(f"  Concurrency:     {Colors.CYAN}{concurrency}{Colors.NC}")
    print(f"  Output:          {Colors.CYAN}{output_file}{Colors.NC}")
    print(f"{Colors.BOLD}════════════════════════════════════════════════════════════{Colors.NC}")
    print("")


def print_summary_branches(scanner: BranchScanner, total_branches: int):
    """Print summary for branch scanning mode."""
    from .output import Colors
    affected_repos = scanner.aggregate_results(scanner.results)

    print("")
    print(f"{Colors.BOLD}════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.BOLD}  SCAN COMPLETE{Colors.NC}")
    print(f"{Colors.BOLD}════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"  Branches Scanned:       {Colors.CYAN}{total_branches}{Colors.NC}")
    print(f"  Total Detections:       {Colors.RED}{Colors.BOLD}{scanner.detection_count}{Colors.NC}")
    print(f"  Affected Repositories:  {Colors.RED}{Colors.BOLD}{len(affected_repos)}{Colors.NC}")
    print(f"{Colors.BOLD}════════════════════════════════════════════════════════════{Colors.NC}")

    if affected_repos:
        print("")
        print(f"{Colors.BOLD}Affected Repositories:{Colors.NC}")
        for repo in affected_repos:
            lib_count = len(repo.affected_libraries)
            print(f"  ⚠️  {repo.repository} - {lib_count} compromised package(s)")

    print("")


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
    parser.add_argument(
        '-d', '--debug',
        action='store_true',
        help='Enable debug output (show matched lines)'
    )
    parser.add_argument(
        '--fresh',
        action='store_true',
        help='Start fresh scan, ignoring any saved state'
    )
    parser.add_argument(
        '--scan-branches',
        action='store_true',
        help='Scan all active branches (not just default branch)'
    )
    parser.add_argument(
        '--branch-age',
        type=int,
        default=30,
        help='Only scan branches with commits in last N days (default: 30)'
    )
    parser.add_argument(
        '--branches-file',
        help='JSON file to save/load discovered branches (default: <output>.branches.json)'
    )

    args = parser.parse_args()
    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        log_warn("Scan interrupted.")
        return 130


if __name__ == '__main__':
    sys.exit(main())
