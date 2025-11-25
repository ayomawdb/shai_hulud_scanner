"""GitHub code search scanner for compromised libraries."""

from __future__ import annotations

import asyncio
import json
import sys
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable

from dataclasses import asdict

from .models import SearchResult, AffectedRepository, ScanState, ScanReport, LibraryFinding
from .output import Colors, log_progress, log_detection, log_debug, log_info


class GitHubScanner:
    def __init__(
        self,
        org: str,
        concurrency: int = 10,
        output_file: Optional[str] = None,
        on_detection: Optional[Callable[[SearchResult], None]] = None
    ):
        self.org = org
        self.concurrency = concurrency
        self.semaphore = asyncio.Semaphore(concurrency)
        self.rate_limit_delay = 0.3
        self.results: list[SearchResult] = []
        self.results_lock = asyncio.Lock()
        self.detection_count = 0
        self.output_file = output_file
        self.on_detection = on_detection
        self.scanned_libraries: set[str] = set()
        self.scan_state: Optional[ScanState] = None
        # Track seen detections to avoid duplicates on resume (repo:file:lib@version)
        self.seen_detections: set[str] = set()
        # Track all findings (including non-matching versions) for detailed report
        self.all_findings: list[LibraryFinding] = []

    def _get_state_file(self) -> str:
        """Get the state file path based on output file."""
        if self.output_file:
            return f"{self.output_file}.state"
        return "scan-results.json.state"

    def _get_findings_file(self) -> str:
        """Get the detailed findings file path."""
        if self.output_file:
            base = self.output_file.rsplit('.', 1)[0]
            return f"{base}.findings.json"
        return "scan-results.findings.json"

    def _write_findings(self):
        """Write all findings (including non-matches) to detailed file."""
        findings_file = self._get_findings_file()
        findings_data = {
            'organization': self.org,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'total_findings': len(self.all_findings),
            'matches': sum(1 for f in self.all_findings if f.is_match),
            'non_matches': sum(1 for f in self.all_findings if not f.is_match),
            'findings': [f.to_dict() for f in self.all_findings]
        }
        with open(findings_file, 'w') as f:
            json.dump(findings_data, f, indent=2)

    def _write_output(self, total_libraries: int):
        """Write current results to output file."""
        if not self.output_file:
            return

        affected_repos = self.aggregate_results(self.results)

        report = ScanReport(
            scan_date=datetime.now(timezone.utc).isoformat(),
            organization=self.org,
            total_libraries_scanned=total_libraries,
            affected_repositories=len(affected_repos),
            results=[asdict(repo) for repo in affected_repos]
        )

        with open(self.output_file, 'w') as f:
            json.dump(report.to_dict(), f, indent=2)

    async def _save_state(self, total_libraries: int):
        """Save current scan state for resume capability."""
        async with self.results_lock:
            state = ScanState(
                organization=self.org,
                total_libraries=total_libraries,
                scanned_libraries=list(self.scanned_libraries),
                detections=[r.to_dict() for r in self.results],
                started_at=self.scan_state.started_at if self.scan_state else datetime.now(timezone.utc).isoformat(),
                updated_at=datetime.now(timezone.utc).isoformat()
            )
            self.scan_state = state

            state_file = self._get_state_file()
            with open(state_file, 'w') as f:
                json.dump(state.to_dict(), f, indent=2)

    def load_state(self) -> Optional[ScanState]:
        """Load previous scan state if exists."""
        state_file = self._get_state_file()
        if Path(state_file).exists():
            try:
                with open(state_file, 'r') as f:
                    data = json.load(f)
                    state = ScanState.from_dict(data)
                    # Restore state
                    self.scanned_libraries = set(state.scanned_libraries)
                    self.results = []
                    self.seen_detections = set()
                    for d in state.detections:
                        result = SearchResult(
                            repository=d['repository'],
                            file=d['file'],
                            url=d['url'],
                            library=d['library'],
                            version=d['version'],
                            line_number=d.get('line_number')
                        )
                        self.results.append(result)
                        # Build seen_detections set to prevent duplicates on resume
                        detection_key = f"{d['repository']}:{d['file']}:{d['library']}@{d['version']}"
                        self.seen_detections.add(detection_key)
                    self.detection_count = len(self.results)
                    self.scan_state = state
                    return state
            except (json.JSONDecodeError, KeyError) as e:
                log_debug(f"Could not load state file: {e}")
        return None

    def clear_state(self):
        """Remove state file after successful completion."""
        state_file = self._get_state_file()
        if Path(state_file).exists():
            Path(state_file).unlink()

    async def _fetch_and_verify(
        self, repo: str, file_path: str, lib_name: str, lib_version: str
    ) -> tuple[Optional[list[tuple[int, str]]], Optional[str], Optional[int]]:
        """
        Fetch file content, parse JSON, and verify exact package match.
        Returns (matched_lines, found_version, found_line_number):
          - matched_lines: list of (line_number, line_content) if verified match, None otherwise
          - found_version: the actual version found in the file (even if not matching), None if library not found
          - found_line_number: line number where library was found (even for non-matches)
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                'gh', 'api',
                f'repos/{repo}/contents/{file_path}',
                '--jq', '.content',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode != 0:
                return None, None, None

            content = base64.b64decode(stdout.decode().strip()).decode('utf-8')

            # Parse JSON and verify exact match
            try:
                pkg_data = json.loads(content)
            except json.JSONDecodeError:
                return None, None, None

            # Find the actual version of the library in this file
            found_version = self._find_library_version(pkg_data, lib_name)

            if not found_version:
                # Library not actually in this file (search was too broad)
                return None, None, None

            # Find line number where the library appears (for all cases)
            lines = content.split('\n')
            found_line = None
            matched = []
            for line_no, line in enumerate(lines, start=1):
                # Look for exact package name as a JSON key
                if f'"{lib_name}"' in line:
                    if found_line is None:
                        found_line = line_no
                    matched.append((line_no, line))
                elif found_version in line:
                    matched.append((line_no, line))

            # Check if versions match
            is_match = found_version == lib_version or lib_version in found_version

            if not is_match:
                log_debug(f"Version mismatch: {lib_name}@{lib_version} vs found {found_version} in {repo}/{file_path}")
                return None, found_version, found_line

            matched_lines = matched[:10] if matched else [(1, f"{lib_name}@{lib_version}")]
            return matched_lines, found_version, matched_lines[0][0] if matched_lines else found_line

        except Exception as e:
            log_debug(f"Error fetching {repo}/{file_path}: {e}")
            return None, None, None

    def _find_library_version(
        self, pkg_data: dict, lib_name: str
    ) -> Optional[str]:
        """
        Find the version of a library in package.json or package-lock.json.
        Returns the version string if found, None if library not present.
        """
        # Check package-lock.json structure (v2/v3)
        if 'packages' in pkg_data:
            for pkg_path, pkg_info in pkg_data.get('packages', {}).items():
                if pkg_info.get('name') == lib_name:
                    return pkg_info.get('version')
                # Also check nested node_modules path
                if pkg_path.endswith(f'node_modules/{lib_name}'):
                    return pkg_info.get('version')

        # Check package-lock.json v1 dependencies
        if 'dependencies' in pkg_data:
            version = self._find_in_dependencies(pkg_data['dependencies'], lib_name)
            if version:
                return version

        # Check package.json dependencies
        for dep_type in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
            deps = pkg_data.get(dep_type, {})
            if lib_name in deps:
                return deps[lib_name]

        return None

    def _verify_package_match(
        self, pkg_data: dict, lib_name: str, lib_version: str
    ) -> bool:
        """
        Verify that the package.json or package-lock.json contains
        an exact match for lib_name at lib_version.
        """
        found_version = self._find_library_version(pkg_data, lib_name)
        if found_version:
            return found_version == lib_version or lib_version in found_version
        return False

    def _find_in_dependencies(
        self, deps: dict, lib_name: str
    ) -> Optional[str]:
        """Recursively find library version in package-lock.json v1 format."""
        if lib_name in deps:
            dep_info = deps[lib_name]
            if isinstance(dep_info, dict):
                return dep_info.get('version')

        # Check all nested dependencies
        for _, dep_info in deps.items():
            if isinstance(dep_info, dict) and 'dependencies' in dep_info:
                version = self._find_in_dependencies(dep_info['dependencies'], lib_name)
                if version:
                    return version

        return None

    def _check_dependencies(
        self, deps: dict, lib_name: str, lib_version: str
    ) -> bool:
        """Recursively check dependencies in package-lock.json v1 format."""
        found_version = self._find_in_dependencies(deps, lib_name)
        return found_version == lib_version if found_version else False

    async def search_library(
        self, lib_name: str, lib_version: str, index: int, total: int
    ) -> list[SearchResult]:
        """Search for a specific library version in package files."""
        lib_key = f"{lib_name}@{lib_version}"

        # Skip if already scanned (for resume)
        if lib_key in self.scanned_libraries:
            log_debug(f"Skipping already scanned: {lib_key}")
            return []

        async with self.semaphore:
            log_progress(index, total, f"Scanning: {lib_key}")

            search_query = (
                f'"{lib_name}" "{lib_version}" org:{self.org} '
                f'filename:package.json OR filename:package-lock.json'
            )

            log_debug(f"Query: {search_query}")

            try:
                proc = await asyncio.create_subprocess_exec(
                    'gh', 'api', '-X', 'GET', 'search/code',
                    '--field', f'q={search_query}',
                    '--field', 'per_page=100',
                    '--jq', '.items[] | {repository: .repository.full_name, file: .path, url: .html_url}',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await proc.communicate()

                if proc.returncode != 0:
                    error_msg = stderr.decode().strip()
                    log_debug(f"API error: {error_msg}")
                    if 'rate limit' in error_msg.lower():
                        print(
                            f"{Colors.YELLOW}[RATE LIMITED]{Colors.NC} "
                            f"{lib_key} - waiting 60s",
                            file=sys.stderr
                        )
                        await asyncio.sleep(60)
                        return await self.search_library(lib_name, lib_version, index, total)
                    return []

                results = []
                for line in stdout.decode().strip().split('\n'):
                    if line:
                        try:
                            item = json.loads(line)

                            # Verify the match by fetching and parsing the actual file
                            matched_lines, found_version, found_line = await self._fetch_and_verify(
                                item['repository'], item['file'],
                                lib_name, lib_version
                            )

                            # If library was found (even with different version), record it
                            if found_version:
                                is_match = matched_lines is not None
                                # Build URL with line number anchor
                                finding_url = item['url']
                                if found_line:
                                    finding_url = f"{item['url']}#L{found_line}"
                                finding = LibraryFinding(
                                    repository=item['repository'],
                                    file=item['file'],
                                    url=finding_url,
                                    searched_library=lib_name,
                                    searched_version=lib_version,
                                    found_version=found_version,
                                    is_match=is_match,
                                    line_number=found_line
                                )
                                async with self.results_lock:
                                    self.all_findings.append(finding)
                                    # Write findings file immediately
                                    self._write_findings()

                            # Skip false positives (verification returned None)
                            if matched_lines is None:
                                continue

                            # Check if we've already seen this detection (for resume)
                            detection_key = f"{item['repository']}:{item['file']}:{lib_name}@{lib_version}"
                            if detection_key in self.seen_detections:
                                log_debug(f"Skipping duplicate detection: {detection_key}")
                                continue

                            first_line = matched_lines[0][0] if matched_lines else None
                            # Build URL with line number anchor for detections
                            detection_url = item['url']
                            if first_line:
                                detection_url = f"{item['url']}#L{first_line}"

                            result = SearchResult(
                                repository=item['repository'],
                                file=item['file'],
                                url=detection_url,
                                library=lib_name,
                                version=lib_version,
                                line_number=first_line
                            )
                            results.append(result)

                            log_detection(
                                lib_name, lib_version,
                                item['repository'], item['file'], detection_url,
                                matched_lines=matched_lines
                            )

                            # Add to global results, save state, and write output immediately
                            async with self.results_lock:
                                self.results.append(result)
                                self.detection_count += 1
                                self.seen_detections.add(detection_key)
                                # Write output file immediately on each detection
                                self._write_output(total)

                            # Call detection callback if provided
                            if self.on_detection:
                                self.on_detection(result)

                        except json.JSONDecodeError:
                            continue

                # Mark this library as scanned
                async with self.results_lock:
                    self.scanned_libraries.add(lib_key)

                # Save state and output after each library
                await self._save_state(total)
                self._write_output(total)

                await asyncio.sleep(self.rate_limit_delay)
                return results

            except Exception as e:
                print(
                    f"{Colors.RED}[ERROR]{Colors.NC} Searching {lib_key}: {e}",
                    file=sys.stderr
                )
                return []

    async def scan_libraries(
        self, libraries: list[tuple[str, str]]
    ) -> list[SearchResult]:
        """Scan all libraries concurrently with real-time output."""
        total = len(libraries)

        # Initialize scan state
        if not self.scan_state:
            self.scan_state = ScanState(
                organization=self.org,
                total_libraries=total,
                scanned_libraries=[],
                detections=[],
                started_at=datetime.now(timezone.utc).isoformat(),
                updated_at=datetime.now(timezone.utc).isoformat()
            )

        tasks = [
            self.search_library(name, version, idx + 1, total)
            for idx, (name, version) in enumerate(libraries)
        ]

        await asyncio.gather(*tasks)

        # Return all results (including resumed ones)
        return self.results

    def aggregate_results(
        self, results: list[SearchResult]
    ) -> list[AffectedRepository]:
        """Group results by repository."""
        repos: dict[str, AffectedRepository] = {}

        for r in results:
            if r.repository not in repos:
                repos[r.repository] = AffectedRepository(
                    repository=r.repository,
                    affected_libraries=[],
                    files_affected=[]
                )

            lib_entry = {
                'library': r.library,
                'version': r.version,
                'file': r.file,
                'url': r.url,
                'line_number': r.line_number
            }

            if lib_entry not in repos[r.repository].affected_libraries:
                repos[r.repository].affected_libraries.append(lib_entry)

            if r.file not in repos[r.repository].files_affected:
                repos[r.repository].files_affected.append(r.file)

        return list(repos.values())
