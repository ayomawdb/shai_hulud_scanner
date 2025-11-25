"""Command-line interface for the scanner."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import ScanReport
from .output import log_info, log_error, log_warn, print_header, print_summary, set_debug
from .scanner import GitHubScanner
from .branches import BranchDiscovery, save_branches, load_branches
from .branch_scanner import BranchScanner


# Default paths relative to package root
LISTS_DIR = "lists"
OUTPUTS_DIR = "outputs"


def get_package_root() -> Path:
    """Get the root directory of the package (where lists/ and outputs/ are)."""
    # This file is at src/shai_hulud_scanner/cli.py
    # Package root is 3 levels up
    return Path(__file__).parent.parent.parent


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


def parse_library_line(line: str) -> Optional[tuple[str, str]]:
    """
    Parse a library line in format: package-name-version
    The version is everything after the last hyphen that starts with a digit.
    Handles scoped packages like @scope/package-name-1.0.0
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # Find the last hyphen followed by a digit (version separator)
    last_hyphen = -1
    for i in range(len(line) - 1, -1, -1):
        if line[i] == '-' and i + 1 < len(line) and line[i + 1].isdigit():
            last_hyphen = i
            break

    if last_hyphen == -1:
        return None

    lib_name = line[:last_hyphen]
    lib_version = line[last_hyphen + 1:]

    if not lib_name or not lib_version:
        return None

    return (lib_name, lib_version)


def load_libraries_from_file(file_path: str) -> tuple[set[tuple[str, str]], list[tuple[str, str, str]]]:
    """
    Load libraries from a single file.
    Supports format: package-name-version (one per line)
    Returns (unique_set, duplicates_list) where duplicates_list contains (lib_name, lib_version, source_file).
    """
    libraries_set: set[tuple[str, str]] = set()
    duplicates: list[tuple[str, str, str]] = []
    source_name = Path(file_path).name

    with open(file_path, 'r') as f:
        for line in f:
            parsed = parse_library_line(line)
            if parsed:
                if parsed in libraries_set:
                    duplicates.append((parsed[0], parsed[1], source_name))
                else:
                    libraries_set.add(parsed)

    return libraries_set, duplicates


def load_libraries_from_directory(lists_dir: Path) -> tuple[list[tuple[str, str]], list[tuple[str, str, str]]]:
    """
    Load libraries from all .txt files in a directory.
    Automatically deduplicates and sorts the list.
    Returns (unique_libraries, all_duplicates) where all_duplicates tracks items removed.
    """
    libraries_set: set[tuple[str, str]] = set()
    all_duplicates: list[tuple[str, str, str]] = []

    txt_files = sorted(lists_dir.glob('*.txt'))
    if not txt_files:
        return [], []

    log_info(f"Loading libraries from {lists_dir}")
    for txt_file in txt_files:
        file_libs, file_dups = load_libraries_from_file(str(txt_file))
        log_info(f"  - {txt_file.name}: {len(file_libs)} entries")

        # Track duplicates within the file
        all_duplicates.extend(file_dups)

        # Track cross-file duplicates
        for lib in file_libs:
            if lib in libraries_set:
                all_duplicates.append((lib[0], lib[1], txt_file.name))
            else:
                libraries_set.add(lib)

    # Sort by library name, then by version
    libraries = sorted(libraries_set, key=lambda x: (x[0].lower(), x[1]))

    return libraries, all_duplicates


def write_combined_list(libraries: list[tuple[str, str]], output_path: str):
    """
    Write the combined, deduplicated, sorted list of libraries to a file.
    """
    with open(output_path, 'w') as f:
        f.write(f"# Combined compromised libraries list\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"# Total unique entries: {len(libraries)}\n")
        f.write("#\n")
        for lib_name, lib_version in libraries:
            f.write(f"{lib_name}-{lib_version}\n")


def write_duplicates_list(duplicates: list[tuple[str, str, str]], output_path: str):
    """
    Write the list of duplicate entries that were removed during deduplication.
    Each entry includes the source file where the duplicate was found.
    """
    with open(output_path, 'w') as f:
        f.write(f"# Duplicate entries removed during deduplication\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"# Total duplicates removed: {len(duplicates)}\n")
        f.write("#\n")
        f.write("# Format: library-version (source_file)\n")
        f.write("#\n")
        # Sort by library name, then version, then source file
        sorted_dups = sorted(duplicates, key=lambda x: (x[0].lower(), x[1], x[2]))
        for lib_name, lib_version, source_file in sorted_dups:
            f.write(f"{lib_name}-{lib_version} ({source_file})\n")


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


def get_output_paths(outputs_dir: Path, org: str) -> dict:
    """Get all output file paths for a scan."""
    base = outputs_dir / org
    return {
        'results': f"{base}.json",
        'findings': f"{base}.findings.json",
        'libraries': f"{base}.libraries.txt",
        'duplicates': f"{base}.duplicates.txt",
        'state': f"{base}.json.state",
        'branches': f"{base}.branches.json",
    }


async def async_main(args: argparse.Namespace) -> int:
    """Async entry point."""
    if args.debug:
        set_debug(True)

    check_prerequisites()

    # Determine paths
    pkg_root = get_package_root()
    lists_dir = pkg_root / LISTS_DIR
    outputs_dir = pkg_root / OUTPUTS_DIR

    # Ensure outputs directory exists
    outputs_dir.mkdir(parents=True, exist_ok=True)

    # Check lists directory exists
    if not lists_dir.exists():
        log_error(f"Lists directory not found: {lists_dir}")
        return 1

    # Load libraries from lists directory
    libraries, duplicates = load_libraries_from_directory(lists_dir)
    if not libraries:
        log_error("No libraries found in lists/ directory")
        return 1

    log_info(f"Loaded {len(libraries)} unique libraries (deduplicated and sorted)")
    if duplicates:
        log_info(f"Removed {len(duplicates)} duplicate entries")

    # Get output paths
    paths = get_output_paths(outputs_dir, args.org)
    output_file = paths['results']

    # Write combined list to file for reference
    write_combined_list(libraries, paths['libraries'])
    log_info(f"Combined library list written to: {paths['libraries']}")

    # Write duplicates file if any duplicates were found
    if duplicates:
        write_duplicates_list(duplicates, paths['duplicates'])
        log_info(f"Duplicates list written to: {paths['duplicates']}")

    # Branch scanning mode
    if args.scan_branches:
        return await run_branch_scan(args, libraries, paths)

    # Default: code search mode
    return await run_code_search_scan(args, libraries, paths)


async def run_branch_scan(args: argparse.Namespace, libraries: list[tuple[str, str]], paths: dict) -> int:
    """Run branch-based scanning."""
    branches_file = paths['branches']
    output_file = paths['results']

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
        discoverer = BranchDiscovery(args.org, args.branch_age, args.concurrency, repo_prefix=getattr(args, 'repo_prefix', None))
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
        output_file=output_file
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

    print_header_branches(args.org, len(libraries), discovery.total_branches, args.concurrency, output_file)

    if resumed and scanner.scan_state:
        print(f"  Resuming from: {scanner.scan_state.started_at}", file=sys.stderr)
        print("", file=sys.stderr)

    try:
        await scanner.scan_branches(discovery, libraries)

        log_info("Scan complete. Generating report...")

        scanner._write_output(discovery.total_branches)
        scanner.clear_state()

        log_info(f"Results written to: {output_file}")

        # Print summary
        print_summary_branches(scanner, discovery.total_branches)

    except (KeyboardInterrupt, asyncio.CancelledError):
        print("", file=sys.stderr)
        log_warn("Scan interrupted. Progress saved - run again to resume.")
        await scanner._save_state(discovery.total_branches)
        scanner._write_output(discovery.total_branches)
        return 130

    return 0


async def run_code_search_scan(args: argparse.Namespace, libraries: list[tuple[str, str]], paths: dict) -> int:
    """Run code search based scanning (default mode)."""
    output_file = paths['results']

    scanner = GitHubScanner(
        args.org,
        args.concurrency,
        output_file=output_file,
        repo_prefix=getattr(args, 'repo_prefix', None)
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
                    write_output(output_file, scanner, len(libraries))

    print_header(args.org, len(libraries), args.concurrency, output_file)

    if resumed and scanner.scan_state:
        print(f"  Resuming from: {scanner.scan_state.started_at}", file=sys.stderr)
        print("", file=sys.stderr)

    try:
        await scanner.scan_libraries(libraries)

        log_info("Scan complete. Generating report...")

        report = write_output(output_file, scanner, len(libraries))

        # Write detailed findings file
        scanner._write_findings()
        findings_file = scanner._get_findings_file()

        # Clear state file on successful completion
        scanner.clear_state()

        log_info(f"Results written to: {output_file}")
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
            print(f"  {repo.repository} - {lib_count} compromised package(s)")

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
        '-c', '--concurrency',
        type=int,
        default=1,
        help='Number of parallel searches (default: 1)'
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
        '--repo-prefix',
        help='Only scan repositories starting with this prefix'
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
