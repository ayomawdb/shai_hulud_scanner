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

try:
    import yaml
except ImportError:
    yaml = None

from .models import ScanReport
from .output import log_info, log_error, log_warn, print_header, print_summary, set_debug
from .scanner import GitHubScanner
from .branches import BranchDiscovery, save_branches, load_branches
from .branch_scanner import BranchScanner
from .package_fetcher import PackageFetcher, save_cache, load_cache
from .local_scanner import LocalScanner


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

    # Check if PyYAML is installed (required for pnpm-lock.yaml support)
    if yaml is None:
        log_error("PyYAML is required to scan pnpm-lock.yaml files")
        print("Install it with: pip install pyyaml", file=sys.stderr)
        sys.exit(1)


def parse_repo_url(url: str) -> Optional[str]:
    """
    Parse a GitHub repository URL and return the owner/repo format.
    Supports formats:
    - https://github.com/owner/repo
    - https://github.com/owner/repo.git
    - github.com/owner/repo
    - owner/repo
    """
    url = url.strip()
    if not url or url.startswith('#'):
        return None

    # Remove .git suffix if present
    if url.endswith('.git'):
        url = url[:-4]

    # Handle full URLs
    if 'github.com/' in url:
        parts = url.split('github.com/')[-1].split('/')
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return None

    # Handle owner/repo format
    if '/' in url and not url.startswith('http'):
        parts = url.split('/')
        if len(parts) == 2:
            return url

    return None


def load_repos_from_file(file_path: str) -> list[str]:
    """
    Load repository URLs/names from a file.
    Returns list of repos in owner/repo format.
    One repo per line, supports comments with #.
    """
    repos = []
    with open(file_path, 'r') as f:
        for line in f:
            parsed = parse_repo_url(line)
            if parsed:
                repos.append(parsed)
    return repos


def load_orgs_from_file(file_path: str) -> list[str]:
    """
    Load organization names from a file.
    Returns list of organization names.
    One org per line, supports comments with #.
    """
    orgs = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            # Take first word in case there are inline comments
            org = line.split()[0]
            if org and not org.startswith('#'):
                orgs.append(org)
    return orgs


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
        'cache': f"{base}.packages.json",
    }


async def scan_single_org(
    args: argparse.Namespace,
    org: str,
    libraries: list[tuple[str, str]],
    outputs_dir: Path
) -> int:
    """Scan a single organization. Returns 0 on success, 1 on error."""
    # Get output paths for this org
    paths = get_output_paths(outputs_dir, org)

    # Temporarily set args.org to current org for functions that use it
    original_org = args.org
    args.org = org

    try:
        # Check if we should use local scan mode (default) or legacy search mode
        if args.use_search_api:
            log_info(f"Scanning organization: {org} (using legacy GitHub Code Search API mode)")
            return await run_code_search_scan(args, libraries, paths, None)
        else:
            # Default: local scan mode (much faster)
            # Branch scanning is now handled within PackageFetcher
            mode_desc = "with branch scanning" if args.scan_branches else "default branch only"
            log_info(f"Scanning organization: {org} (using local scan mode, {mode_desc})")
            return await run_local_scan(args, libraries, paths, None, org)
    finally:
        # Restore original org
        args.org = original_org


async def scan_multiple_orgs(args: argparse.Namespace, orgs: list[str]) -> int:
    """Scan multiple organizations sequentially."""
    log_info(f"Starting scan for {len(orgs)} organizations...")

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

    # Load libraries from lists directory (same for all orgs)
    libraries, duplicates = load_libraries_from_directory(lists_dir)
    if not libraries:
        log_error("No libraries found in lists/ directory")
        return 1

    log_info(f"Loaded {len(libraries)} unique libraries (deduplicated)")
    if duplicates:
        log_info(f"Removed {len(duplicates)} duplicate entries")

    # Scan each organization
    success_count = 0
    failed_orgs = []

    for idx, org in enumerate(orgs, 1):
        log_info(f"\n{'=' * 80}")
        log_info(f"Organization {idx}/{len(orgs)}: {org}")
        log_info(f"{'=' * 80}\n")

        try:
            result = await scan_single_org(args, org, libraries, outputs_dir)
            if result == 0:
                success_count += 1
            else:
                failed_orgs.append(org)
        except Exception as e:
            log_error(f"Error scanning organization {org}: {e}")
            failed_orgs.append(org)

    # Print final summary
    log_info(f"\n{'=' * 80}")
    log_info(f"Multi-organization scan complete!")
    log_info(f"Successfully scanned: {success_count}/{len(orgs)} organizations")
    if failed_orgs:
        log_warn(f"Failed organizations: {', '.join(failed_orgs)}")
    log_info(f"{'=' * 80}\n")

    return 0 if success_count == len(orgs) else 1


async def async_main(args: argparse.Namespace) -> int:
    """Async entry point."""
    if args.debug:
        set_debug(True)

    check_prerequisites()

    # Parse organizations if provided
    orgs: list[str] = []
    if args.org:
        # -g always expects a file path
        org_file_path = Path(args.org).resolve()
        if not org_file_path.is_file():
            log_error(f"Organization file not found: {org_file_path}")
            return 1

        log_info(f"Reading organization list from: {org_file_path}")
        orgs = load_orgs_from_file(str(org_file_path))
        log_info(f"Loaded {len(orgs)} organizations from file")

        if not orgs:
            log_error(f"No valid organizations found in {org_file_path}")
            return 1

    # Parse repos if provided
    repos: Optional[list[str]] = None
    if args.repos:
        # Check if it's a file or comma-separated list
        if Path(args.repos).is_file():
            repos = load_repos_from_file(args.repos)
            log_info(f"Loaded {len(repos)} repositories from {args.repos}")
        else:
            # Treat as comma-separated list
            repos = []
            for item in args.repos.split(','):
                parsed = parse_repo_url(item.strip())
                if parsed:
                    repos.append(parsed)
            log_info(f"Scanning {len(repos)} specified repositories")

        if not repos:
            log_error("No valid repositories found in --repos")
            return 1

    # Validate arguments
    if not orgs and not repos:
        log_error("Either --org or --repos is required")
        return 1

    # Determine scan mode
    if repos and orgs:
        # Org + repos mode: scan specific repos within the org
        if len(orgs) > 1:
            log_error("Cannot specify multiple organizations with --repos. Use --repos alone or with a single --org.")
            return 1
        org = orgs[0]
        scan_name = f"{org}-{len(repos)}repos" if len(repos) > 1 else org
        args.org = org
        log_info(f"Scanning {len(repos)} specific repositories in organization {org}")
    elif repos:
        # Repos-only mode: scan specific repos (may be from different orgs)
        org = repos[0].split('/')[0] if repos else 'repos'
        scan_name = f"{org}-{len(repos)}repos" if len(repos) > 1 else repos[0].replace('/', '-')
        args.org = org  # Set for internal functions that expect it
        log_info(f"Scanning {len(repos)} specific repositories")
    elif len(orgs) > 1:
        # Multi-org mode
        return await scan_multiple_orgs(args, orgs)
    else:
        # Single org mode
        org = orgs[0]
        scan_name = org
        args.org = org

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

    log_info(f"Loaded {len(libraries)} unique libraries (deduplicated)")
    if duplicates:
        log_info(f"Removed {len(duplicates)} duplicate entries")

    # Get output paths
    paths = get_output_paths(outputs_dir, scan_name)

    # Write combined list to file for reference
    write_combined_list(libraries, paths['libraries'])
    log_info(f"Combined library list written to: {paths['libraries']}")

    # Write duplicates file if any duplicates were found
    if duplicates:
        write_duplicates_list(duplicates, paths['duplicates'])
        log_info(f"Duplicates list written to: {paths['duplicates']}")

    # Check if we should use local scan mode (default) or legacy search mode
    if args.use_search_api:
        log_info("Using legacy GitHub Code Search API mode")
        return await run_code_search_scan(args, libraries, paths, repos)
    else:
        # Default: local scan mode (much faster)
        # Branch scanning is now handled within PackageFetcher
        return await run_local_scan(args, libraries, paths, repos, scan_name)


async def run_branch_scan(
    args: argparse.Namespace,
    libraries: list[tuple[str, str]],
    paths: dict,
    repos: Optional[list[str]] = None
) -> int:
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
        discoverer = BranchDiscovery(args.org, args.branch_age, args.concurrency, repos)
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


async def run_code_search_scan(
    args: argparse.Namespace,
    libraries: list[tuple[str, str]],
    paths: dict,
    repos: Optional[list[str]] = None
) -> int:
    """Run code search based scanning (legacy mode)."""
    output_file = paths['results']

    scanner = GitHubScanner(
        args.org,
        args.concurrency,
        output_file=output_file,
        repos=repos
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


async def run_local_scan(
    args: argparse.Namespace,
    libraries: list[tuple[str, str]],
    paths: dict,
    repos: Optional[list[str]],
    scan_name: str
) -> int:
    """Run local scan mode - fetch package files once, scan locally (default, fast mode)."""
    output_file = paths['results']
    cache_file = paths['cache']

    # Use org name or repo info for display
    if repos:
        display_name = f"{len(repos)} repositories"
        org_name = repos[0].split('/')[0]  # Use first repo's owner for org field
    else:
        display_name = args.org
        org_name = args.org

    # Phase 1: Fetch/load package file cache
    cache = None
    if not args.refresh_cache:
        cache = load_cache(cache_file)
        if cache:
            log_info(f"Loaded package cache from {cache_file}")
            log_info(f"  Cached at: {cache.fetched_at}")
            log_info(f"  {cache.total_files} package files from {cache.repos_with_packages} repos")

    if not cache or args.refresh_cache:
        log_info("Fetching package files from repositories...")
        # Use repo_age parameter (0 means scan all repos regardless of age)
        max_repo_age = args.repo_age if args.repo_age > 0 else 36500  # ~100 years = effectively no limit
        fetcher = PackageFetcher(
            org_name,
            args.concurrency,
            repos,
            max_repo_age,
            scan_branches=args.scan_branches,
            max_branch_age_days=args.branch_age
        )
        cache = await fetcher.fetch_all()
        save_cache(cache, cache_file)

    if cache.total_files == 0:
        log_warn("No package files found in repositories")
        return 0

    # Phase 2: Scan cached files locally
    print_header(display_name, len(libraries), args.concurrency, output_file)

    scanner = LocalScanner(cache)

    try:
        scanner.scan_libraries(libraries)

        log_info("Scan complete. Generating report...")

        # Write results
        affected_repos = scanner.aggregate_results(scanner.results)
        report = ScanReport(
            scan_date=datetime.now(timezone.utc).isoformat(),
            organization=org_name,
            total_libraries_scanned=len(libraries),
            affected_repositories=len(affected_repos),
            results=[asdict(repo) for repo in affected_repos]
        )

        with open(output_file, 'w') as f:
            json.dump(report.to_dict(), f, indent=2)

        # Write detailed findings
        findings_file = output_file.replace('.json', '.findings.json')
        findings_data = {
            'organization': org_name,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'total_findings': len(scanner.all_findings),
            'matches': sum(1 for f in scanner.all_findings if f.is_match),
            'non_matches': sum(1 for f in scanner.all_findings if not f.is_match),
            'findings': [f.to_dict() for f in scanner.all_findings]
        }
        with open(findings_file, 'w') as f:
            json.dump(findings_data, f, indent=2)

        log_info(f"Results written to: {output_file}")
        log_info(f"Detailed findings written to: {findings_file}")
        print_summary(report, scanner.detection_count)

        # Show findings summary
        if scanner.all_findings:
            non_matches = sum(1 for f in scanner.all_findings if not f.is_match)
            if non_matches > 0:
                log_info(f"Found {non_matches} repos with different versions of searched libraries (see {findings_file})")

    except (KeyboardInterrupt, asyncio.CancelledError):
        print("", file=sys.stderr)
        log_warn("Scan interrupted.")
        return 130

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
        description='Scan GitHub organization or specific repositories for compromised npm libraries'
    )
    parser.add_argument(
        '-g', '--org',
        help='File containing GitHub organization names to scan (one per line). Required unless --repos is used. Can be combined with --repos to limit scanning to specific repos within the orgs.'
    )
    parser.add_argument(
        '-r', '--repos',
        help='File containing repository URLs to scan (one per line), or comma-separated list of repos. Can be used alone or with --org to limit scanning.'
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
        '--repo-age',
        type=int,
        default=30,
        help='Only scan repositories updated in last N days (default: 30, 0=scan all)'
    )
    parser.add_argument(
        '--use-search-api',
        action='store_true',
        help='Use legacy GitHub Code Search API (slow, rate-limited). Default is local scan mode (fast).'
    )
    parser.add_argument(
        '--refresh-cache',
        action='store_true',
        help='Force refresh of package file cache'
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
