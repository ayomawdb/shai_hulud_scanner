"""Local scanner that checks cached package files against a library list."""

from __future__ import annotations

import json
from typing import Optional

from .models import PackageCache, SearchResult, LibraryFinding, AffectedRepository
from .output import log_progress, log_detection, log_debug, log_info
from .semver import is_vulnerable_in_range


class LocalScanner:
    """Scans cached package files for compromised libraries."""

    def __init__(self, cache: PackageCache):
        self.cache = cache
        self.results: list[SearchResult] = []
        self.all_findings: list[LibraryFinding] = []
        self.detection_count = 0
        # Track seen detections to avoid duplicates
        self.seen_detections: set[str] = set()

    def _find_line_number(self, content: str, lib_name: str) -> Optional[int]:
        """Find the line number where a library appears in the file."""
        if not content:
            return None

        lines = content.split('\n')
        for line_no, line in enumerate(lines, start=1):
            # Look for exact package name as a JSON key
            if f'"{lib_name}"' in line:
                return line_no

        return None

    def _check_version_match(self, found_version: str, search_version: str, file_path: str = '') -> bool:
        """
        Check if versions match.

        For lock files (package-lock.json, pnpm-lock.yaml): exact version match
        For package.json: check if vulnerable version satisfies the semver range

        Args:
            found_version: The version found in the file (may be exact or a range)
            search_version: The vulnerable version we're searching for
            file_path: The file path to determine if it's a lock file or package.json
        """
        # For lock files, we have exact versions - do exact match
        if 'lock' in file_path.lower():
            # Remove common prefixes like ^, ~, >=, etc. from both versions
            clean_found = found_version.lstrip('^~>=<')
            clean_search = search_version.lstrip('^~>=<')
            return clean_found == clean_search or clean_search in clean_found

        # For package.json, the found_version might be a range like "^4.17.0"
        # Check if the vulnerable search_version would satisfy this range
        return is_vulnerable_in_range(search_version, found_version)

    def scan_libraries(self, libraries: list[tuple[str, str]]) -> list[SearchResult]:
        """
        Scan all cached package files for the given libraries.
        Returns list of SearchResult objects for detected compromised libraries.
        """
        total_libs = len(libraries)
        log_info(f"Scanning {self.cache.total_files} package files for {total_libs} libraries...")

        for idx, (lib_name, lib_version) in enumerate(libraries):
            log_progress(idx + 1, total_libs, f"Checking: {lib_name}@{lib_version}")
            self._scan_single_library(lib_name, lib_version)

        log_info(f"Scan complete. Found {self.detection_count} detections.")
        return self.results

    def _scan_single_library(self, lib_name: str, lib_version: str):
        """Scan for a single library across all cached files."""
        for pkg_file in self.cache.files:
            # Check if this library exists in the file's dependencies
            if lib_name not in pkg_file.dependencies:
                continue

            # Dependencies is now a list of versions - check all of them
            found_versions = pkg_file.dependencies[lib_name]
            if not isinstance(found_versions, list):
                # Handle old cache format where it was a single string
                found_versions = [found_versions]

            # Find line number in raw content
            line_number = None
            if pkg_file.raw_content:
                line_number = self._find_line_number(pkg_file.raw_content, lib_name)

            # Build URL with line anchor
            url = pkg_file.html_url
            if line_number:
                url = f"{pkg_file.html_url}#L{line_number}"

            # Check each version found
            for found_version in found_versions:
                # Check if versions match (pass file_path for semver range checking)
                is_match = self._check_version_match(found_version, lib_version, pkg_file.file_path)

                # Record finding (even if version doesn't match)
                finding = LibraryFinding(
                    repository=pkg_file.repository,
                    file=pkg_file.file_path,
                    url=url,
                    searched_library=lib_name,
                    searched_version=lib_version,
                    found_version=found_version,
                    is_match=is_match,
                    line_number=line_number,
                )
                self.all_findings.append(finding)

                if not is_match:
                    log_debug(
                        f"Version mismatch: {lib_name}@{lib_version} vs "
                        f"found {found_version} in {pkg_file.repository}/{pkg_file.file_path}"
                    )
                    continue

                # Check if we've already detected this specific version
                detection_key = f"{pkg_file.repository}:{pkg_file.file_path}:{lib_name}@{found_version}"
                if detection_key in self.seen_detections:
                    log_debug(f"Skipping duplicate detection: {detection_key}")
                    continue

                self.seen_detections.add(detection_key)

                # Create detection result
                result = SearchResult(
                    repository=pkg_file.repository,
                    file=pkg_file.file_path,
                    url=url,
                    library=lib_name,
                    version=found_version,  # Use the actual found version
                    line_number=line_number,
                )
                self.results.append(result)
                self.detection_count += 1

                # Log the detection with matched lines
                matched_lines = []
                if pkg_file.raw_content and line_number:
                    lines = pkg_file.raw_content.split('\n')
                    # Get context around the match
                    start = max(0, line_number - 1)
                    end = min(len(lines), line_number + 2)
                    for i in range(start, end):
                        matched_lines.append((i + 1, lines[i]))

                log_detection(
                    lib_name, found_version,
                pkg_file.repository, pkg_file.file_path, url,
                matched_lines=matched_lines if matched_lines else None
            )

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
                'line_number': r.line_number
            }

            if lib_entry not in repos[r.repository].affected_libraries:
                repos[r.repository].affected_libraries.append(lib_entry)

            if r.file not in repos[r.repository].files_affected:
                repos[r.repository].files_affected.append(r.file)

        return list(repos.values())
