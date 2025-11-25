"""Scanner for checking compromised packages across all branches."""

from __future__ import annotations

import asyncio
import json
import base64
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dataclasses import asdict

try:
    import yaml
except ImportError:
    yaml = None

from .models import SearchResult, AffectedRepository, ScanState, ScanReport
from .branches import BranchDiscoveryResult, RepoWithBranches, BranchInfo
from .output import Colors, log_progress, log_detection, log_debug, log_info
from .semver import is_vulnerable_in_range


class BranchScanner:
    """Scans specific branches for compromised packages."""

    def __init__(
        self,
        org: str,
        concurrency: int = 10,
        output_file: Optional[str] = None
    ):
        self.org = org
        self.concurrency = concurrency
        self.semaphore = asyncio.Semaphore(concurrency)
        self.rate_limit_delay = 0.2
        self.results: list[SearchResult] = []
        self.results_lock = asyncio.Lock()
        self.detection_count = 0
        self.output_file = output_file
        # Track seen detections to avoid duplicates (repo:branch:file:lib@version)
        self.seen_detections: set[str] = set()
        # Track scanned combinations
        self.scanned_items: set[str] = set()
        self.scan_state: Optional[ScanState] = None

    def _get_state_file(self) -> str:
        if self.output_file:
            return f"{self.output_file}.state"
        return "scan-results.json.state"

    def _write_output(self, total_items: int):
        """Write current results to output file."""
        if not self.output_file:
            return

        affected_repos = self.aggregate_results(self.results)

        report = ScanReport(
            scan_date=datetime.now(timezone.utc).isoformat(),
            organization=self.org,
            total_libraries_scanned=total_items,
            affected_repositories=len(affected_repos),
            results=[asdict(repo) for repo in affected_repos]
        )

        with open(self.output_file, 'w') as f:
            json.dump(report.to_dict(), f, indent=2)

    async def _save_state(self, total_items: int):
        """Save scan state for resume."""
        async with self.results_lock:
            state = ScanState(
                organization=self.org,
                total_libraries=total_items,
                scanned_libraries=list(self.scanned_items),
                detections=[r.to_dict() for r in self.results],
                started_at=self.scan_state.started_at if self.scan_state else datetime.now(timezone.utc).isoformat(),
                updated_at=datetime.now(timezone.utc).isoformat()
            )
            self.scan_state = state

            state_file = self._get_state_file()
            with open(state_file, 'w') as f:
                json.dump(state.to_dict(), f, indent=2)

    def load_state(self) -> Optional[ScanState]:
        """Load previous scan state."""
        state_file = self._get_state_file()
        if Path(state_file).exists():
            try:
                with open(state_file, 'r') as f:
                    data = json.load(f)
                    state = ScanState.from_dict(data)
                    self.scanned_items = set(state.scanned_libraries)
                    self.results = []
                    self.seen_detections = set()
                    for d in state.detections:
                        result = SearchResult(
                            repository=d['repository'],
                            file=d['file'],
                            url=d['url'],
                            library=d['library'],
                            version=d['version'],
                            line_number=d.get('line_number'),
                            branch=d.get('branch')
                        )
                        self.results.append(result)
                        detection_key = f"{d['repository']}:{d.get('branch', 'default')}:{d['file']}:{d['library']}@{d['version']}"
                        self.seen_detections.add(detection_key)
                    self.detection_count = len(self.results)
                    self.scan_state = state
                    return state
            except (json.JSONDecodeError, KeyError) as e:
                log_debug(f"Could not load state: {e}")
        return None

    def clear_state(self):
        """Remove state file."""
        state_file = self._get_state_file()
        if Path(state_file).exists():
            Path(state_file).unlink()

    async def _fetch_file(
        self, repo: str, file_path: str, branch: str
    ) -> Optional[str]:
        """Fetch file content from a specific branch."""
        try:
            proc = await asyncio.create_subprocess_exec(
                'gh', 'api',
                f'repos/{repo}/contents/{file_path}',
                '--field', f'ref={branch}',
                '--jq', '.content',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                error_msg = stderr.decode().strip()
                log_debug(f"File not found: {repo}/{file_path}@{branch} (error: {error_msg})")
                return None

            content = base64.b64decode(stdout.decode().strip()).decode('utf-8')
            log_debug(f"Successfully fetched: {repo}/{file_path}@{branch} ({len(content)} bytes)")
            return content
        except Exception as e:
            log_debug(f"Error fetching {repo}/{file_path}@{branch}: {e}")
            return None

    def _check_package_json(
        self, content: str, lib_name: str, lib_version: str
    ) -> Optional[list[tuple[int, str]]]:
        """
        Check if package.json contains the compromised library.
        Uses semver range matching to detect if vulnerable version satisfies the range.
        """
        try:
            pkg_data = json.loads(content)
        except json.JSONDecodeError:
            return None

        # Check all dependency types
        for dep_type in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
            deps = pkg_data.get(dep_type, {})
            if lib_name in deps:
                version_spec = deps[lib_name]
                # Check if the vulnerable version satisfies the semver range
                if is_vulnerable_in_range(lib_version, version_spec):
                    # Find line numbers
                    lines = content.split('\n')
                    matched = []
                    for line_no, line in enumerate(lines, start=1):
                        if f'"{lib_name}"' in line:
                            matched.append((line_no, line))
                    return matched if matched else [(1, f"{lib_name}@{lib_version}")]

        return None

    def _check_package_lock(
        self, content: str, lib_name: str, lib_version: str
    ) -> Optional[list[tuple[int, str]]]:
        """Check if package-lock.json contains the compromised library."""
        try:
            pkg_data = json.loads(content)
        except json.JSONDecodeError:
            return None

        found = False

        # Check package-lock v2/v3 (packages)
        if 'packages' in pkg_data:
            for pkg_path, pkg_info in pkg_data.get('packages', {}).items():
                if pkg_info.get('name') == lib_name and pkg_info.get('version') == lib_version:
                    found = True
                    break
                if pkg_path.endswith(f'node_modules/{lib_name}') and pkg_info.get('version') == lib_version:
                    found = True
                    break

        # Check package-lock v1 (dependencies)
        if not found and 'dependencies' in pkg_data:
            found = self._check_deps_recursive(pkg_data['dependencies'], lib_name, lib_version)

        if found:
            lines = content.split('\n')
            matched = []
            for line_no, line in enumerate(lines, start=1):
                if f'"{lib_name}"' in line or lib_version in line:
                    matched.append((line_no, line))
            return matched[:10] if matched else [(1, f"{lib_name}@{lib_version}")]

        return None

    def _check_pnpm_lock(
        self, content: str, lib_name: str, lib_version: str
    ) -> Optional[list[tuple[int, str]]]:
        """Check if pnpm-lock.yaml contains the compromised library."""
        if yaml is None:
            log_debug("PyYAML not installed, skipping pnpm-lock.yaml")
            return None

        try:
            pkg_data = yaml.safe_load(content)
        except Exception as e:
            log_debug(f"Error parsing YAML: {e}")
            return None

        if not isinstance(pkg_data, dict):
            return None

        found = False

        # Check pnpm-lock.yaml format (packages key)
        if 'packages' in pkg_data:
            packages = pkg_data.get('packages', {})
            if isinstance(packages, dict):
                for pkg_path in packages.keys():
                    # pnpm format: '/@babel/core/7.12.0' or '/lodash/4.17.21'
                    if pkg_path.startswith('/'):
                        parts = pkg_path[1:].rsplit('/', 1)
                        if len(parts) == 2:
                            name, version = parts
                            if name == lib_name and version == lib_version:
                                found = True
                                break

        # Also check dependencies section (older pnpm format)
        if not found and 'dependencies' in pkg_data:
            deps = pkg_data.get('dependencies', {})
            if isinstance(deps, dict) and lib_name in deps:
                dep_info = deps[lib_name]
                if isinstance(dep_info, str) and dep_info == lib_version:
                    found = True
                elif isinstance(dep_info, dict) and dep_info.get('version') == lib_version:
                    found = True

        if found:
            lines = content.split('\n')
            matched = []
            for line_no, line in enumerate(lines, start=1):
                if lib_name in line or lib_version in line:
                    matched.append((line_no, line))
            return matched[:10] if matched else [(1, f"{lib_name}@{lib_version}")]

        return None

    def _check_deps_recursive(self, deps: dict, lib_name: str, lib_version: str) -> bool:
        """Recursively check dependencies."""
        if lib_name in deps:
            dep_info = deps[lib_name]
            if isinstance(dep_info, dict) and dep_info.get('version') == lib_version:
                return True

        for dep_info in deps.values():
            if isinstance(dep_info, dict) and 'dependencies' in dep_info:
                if self._check_deps_recursive(dep_info['dependencies'], lib_name, lib_version):
                    return True

        return False

    async def scan_branch(
        self,
        repo: str,
        branch: BranchInfo,
        libraries: list[tuple[str, str]],
        index: int,
        total: int
    ) -> list[SearchResult]:
        """Scan a specific branch for all compromised libraries."""
        scan_key = f"{repo}:{branch.name}"

        if scan_key in self.scanned_items:
            log_debug(f"Skipping already scanned: {scan_key}")
            return []

        async with self.semaphore:
            log_progress(index, total, f"Scanning: {repo} @ {branch.name}")

            results = []

            # Fetch package.json, package-lock.json, and pnpm-lock.yaml for this branch
            pkg_json = await self._fetch_file(repo, 'package.json', branch.name)
            pkg_lock = await self._fetch_file(repo, 'package-lock.json', branch.name)
            pnpm_lock = await self._fetch_file(repo, 'pnpm-lock.yaml', branch.name)

            if not pkg_json and not pkg_lock and not pnpm_lock:
                log_debug(f"No package files in {repo}@{branch.name}")
                async with self.results_lock:
                    self.scanned_items.add(scan_key)
                return []

            # Check each library
            for lib_name, lib_version in libraries:
                # Check package.json
                if pkg_json:
                    matched = self._check_package_json(pkg_json, lib_name, lib_version)
                    if matched:
                        result = await self._record_detection(
                            repo, branch.name, 'package.json',
                            lib_name, lib_version, matched, total
                        )
                        if result:
                            results.append(result)

                # Check package-lock.json
                if pkg_lock:
                    matched = self._check_package_lock(pkg_lock, lib_name, lib_version)
                    if matched:
                        result = await self._record_detection(
                            repo, branch.name, 'package-lock.json',
                            lib_name, lib_version, matched, total
                        )
                        if result:
                            results.append(result)

                # Check pnpm-lock.yaml
                if pnpm_lock:
                    matched = self._check_pnpm_lock(pnpm_lock, lib_name, lib_version)
                    if matched:
                        result = await self._record_detection(
                            repo, branch.name, 'pnpm-lock.yaml',
                            lib_name, lib_version, matched, total
                        )
                        if result:
                            results.append(result)

            # Mark branch as scanned
            async with self.results_lock:
                self.scanned_items.add(scan_key)

            await self._save_state(total)
            self._write_output(total)

            await asyncio.sleep(self.rate_limit_delay)
            return results

    async def _record_detection(
        self,
        repo: str,
        branch: str,
        file: str,
        lib_name: str,
        lib_version: str,
        matched_lines: list[tuple[int, str]],
        total: int
    ) -> Optional[SearchResult]:
        """Record a detection if not already seen."""
        detection_key = f"{repo}:{branch}:{file}:{lib_name}@{lib_version}"

        if detection_key in self.seen_detections:
            log_debug(f"Skipping duplicate: {detection_key}")
            return None

        first_line = matched_lines[0][0] if matched_lines else None
        url = f"https://github.com/{repo}/blob/{branch}/{file}"
        if first_line:
            url = f"{url}#L{first_line}"

        result = SearchResult(
            repository=repo,
            file=file,
            url=url,
            library=lib_name,
            version=lib_version,
            line_number=first_line,
            branch=branch
        )

        log_detection(
            lib_name, lib_version,
            repo, f"{file} @ {branch}", url,
            matched_lines=matched_lines
        )

        async with self.results_lock:
            self.results.append(result)
            self.detection_count += 1
            self.seen_detections.add(detection_key)
            self._write_output(total)

        return result

    async def scan_branches(
        self,
        discovery: BranchDiscoveryResult,
        libraries: list[tuple[str, str]]
    ) -> list[SearchResult]:
        """Scan all discovered branches."""
        # Build list of all (repo, branch) pairs to scan
        scan_items = []
        for repo in discovery.repos:
            for branch in repo.branches:
                scan_items.append((repo.repository, branch))

        total = len(scan_items)
        log_info(f"Scanning {total} branches for {len(libraries)} libraries...")

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
            self.scan_branch(repo, branch, libraries, idx + 1, total)
            for idx, (repo, branch) in enumerate(scan_items)
        ]

        await asyncio.gather(*tasks)

        return self.results

    def aggregate_results(self, results: list[SearchResult]) -> list[AffectedRepository]:
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
                'line_number': r.line_number,
                'branch': r.branch
            }

            if lib_entry not in repos[r.repository].affected_libraries:
                repos[r.repository].affected_libraries.append(lib_entry)

            file_with_branch = f"{r.file}@{r.branch}" if r.branch else r.file
            if file_with_branch not in repos[r.repository].files_affected:
                repos[r.repository].files_affected.append(file_with_branch)

        return list(repos.values())
