"""Fetch and cache package.json, package-lock.json, and pnpm-lock.yaml files from GitHub repositories."""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    yaml = None

from .models import PackageCache, PackageFileInfo
from .output import log_info, log_debug, log_progress, log_warn


class PackageFetcher:
    """Fetches package files from GitHub repositories and caches them locally."""

    # Files to look for in each repository
    PACKAGE_FILES = ['package.json', 'package-lock.json', 'pnpm-lock.yaml']

    def __init__(
        self,
        org: str,
        concurrency: int = 10,
        repos: Optional[list[str]] = None,
        max_repo_age_days: int = 30
    ):
        self.org = org
        self.concurrency = concurrency
        self.semaphore = asyncio.Semaphore(concurrency)
        self.repos = repos  # Optional list of specific repos to scan
        self.max_repo_age_days = max_repo_age_days
        self.repo_age_cutoff = datetime.now(timezone.utc) - timedelta(days=max_repo_age_days)

    async def list_repos(self) -> list[str]:
        """List all repositories in the organization."""
        if self.repos:
            log_info(f"Using {len(self.repos)} specified repositories")
            return self.repos

        log_info(f"Listing repositories in {self.org}...")

        repos = []
        page = 1
        per_page = 100

        while True:
            # Use query parameters in the URL instead of --field
            api_endpoint = f'orgs/{self.org}/repos?per_page={per_page}&page={page}&type=all'
            log_debug(f"API call: gh api {api_endpoint}")

            proc = await asyncio.create_subprocess_exec(
                'gh', 'api',
                api_endpoint,
                '--jq', '.[].full_name',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                error = stderr.decode().strip()
                log_debug(f"API error for '{api_endpoint}': {error}")
                log_warn(f"Error listing repos: {error}")
                break

            output = stdout.decode().strip()
            if not output:
                break

            page_repos = output.split('\n')
            repos.extend(page_repos)
            log_debug(f"Fetched page {page}: {len(page_repos)} repos (total so far: {len(repos)})")

            if len(page_repos) < per_page:
                break

            page += 1

        log_info(f"Found {len(repos)} repositories")
        return repos

    async def _should_skip_repo(self, repo: str) -> bool:
        """
        Check if repository should be skipped based on last update time.
        Returns True if repo is too old, False if it should be scanned.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                'gh', 'api',
                f'repos/{repo}',
                '--jq', '.pushed_at',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode != 0:
                # If we can't get the info, don't skip (safer to scan)
                return False

            pushed_at_str = stdout.decode().strip()
            if not pushed_at_str:
                return False

            # Parse the timestamp
            pushed_at = datetime.fromisoformat(pushed_at_str.replace('Z', '+00:00'))

            # Skip if last push is older than cutoff
            if pushed_at < self.repo_age_cutoff:
                log_debug(f"  Skipping {repo}: last updated {pushed_at.date()} (older than {self.max_repo_age_days} days)")
                return True

            log_debug(f"  Including {repo}: last updated {pushed_at.date()}")
            return False

        except Exception as e:
            log_debug(f"Error checking repo age for {repo}: {e}")
            # If error, don't skip (safer to scan)
            return False

    async def _find_package_files(self, repo: str) -> list[str]:
        """
        Find all package.json, package-lock.json, and pnpm-lock.yaml files in a repository.
        Uses GitHub's Git Tree API to recursively find files.
        Returns a list of file paths.
        """
        try:
            # First, get the default branch SHA
            proc = await asyncio.create_subprocess_exec(
                'gh', 'api',
                f'repos/{repo}',
                '--jq', '.default_branch',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode != 0:
                return []

            default_branch = stdout.decode().strip()

            # Get the tree SHA for the default branch
            proc = await asyncio.create_subprocess_exec(
                'gh', 'api',
                f'repos/{repo}/git/trees/{default_branch}',
                '--jq', '.sha',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode != 0:
                return []

            tree_sha = stdout.decode().strip()

            # Get the full tree recursively
            proc = await asyncio.create_subprocess_exec(
                'gh', 'api',
                f'repos/{repo}/git/trees/{tree_sha}?recursive=1',
                '--jq', '.tree[] | select(.type == "blob") | .path',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode != 0:
                return []

            output = stdout.decode().strip()
            if not output:
                return []

            # Filter for package files
            all_paths = output.split('\n')
            package_paths = []

            for path in all_paths:
                filename = path.split('/')[-1]
                if filename in self.PACKAGE_FILES:
                    package_paths.append(path)

            if package_paths:
                log_debug(f"  Found {len(package_paths)} package file(s) in {repo}")

            return package_paths

        except Exception as e:
            log_debug(f"Error finding package files in {repo}: {e}")
            return []

    async def _fetch_file_content(self, repo: str, file_path: str) -> Optional[tuple[str, str]]:
        """
        Fetch a file's content from a repository.
        Returns (content, html_url) or None if file doesn't exist.
        Uses Git Blob API to handle large files (>1MB).
        """
        try:
            # First, get the file's SHA and metadata using Contents API
            proc = await asyncio.create_subprocess_exec(
                'gh', 'api',
                f'repos/{repo}/contents/{file_path}',
                '--jq', '{sha: .sha, html_url: .html_url, size: .size}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                # File doesn't exist or other error - this is normal
                return None

            metadata = json.loads(stdout.decode().strip())
            file_sha = metadata.get('sha')
            html_url = metadata.get('html_url')
            file_size = metadata.get('size', 0)

            if not file_sha or not html_url:
                log_debug(f"Missing sha or html_url for {repo}/{file_path}")
                return None

            log_debug(f"    File size: {file_size} bytes, SHA: {file_sha[:8]}")

            # Use Git Blob API to fetch content (handles large files)
            proc = await asyncio.create_subprocess_exec(
                'gh', 'api',
                f'repos/{repo}/git/blobs/{file_sha}',
                '--jq', '.content',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                log_debug(f"Error fetching blob for {repo}/{file_path}: {stderr.decode().strip()}")
                return None

            # Decode base64 content
            content_b64 = stdout.decode().strip().strip('"')
            content = base64.b64decode(content_b64).decode('utf-8')
            return content, html_url

        except Exception as e:
            log_debug(f"Error fetching {repo}/{file_path}: {e}")
            return None

    def _extract_dependencies(self, content: str, file_path: str) -> dict[str, str]:
        """
        Extract all dependencies from package.json, package-lock.json, or pnpm-lock.yaml.
        Returns a dict mapping package name to version.
        """
        dependencies: dict[str, str] = {}
        log_debug(f"    _extract_dependencies: Processing {file_path}")

        # Handle pnpm-lock.yaml
        if 'pnpm-lock' in file_path:
            log_debug(f"    Detected pnpm-lock.yaml format")
            if yaml is None:
                raise ImportError(
                    "PyYAML is required to parse pnpm-lock.yaml files. "
                    "Install it with: pip install pyyaml"
                )

            try:
                pkg_data = yaml.safe_load(content)
            except Exception as e:
                log_debug(f"Error parsing YAML: {e}")
                return {}

            if not isinstance(pkg_data, dict):
                return {}

            # pnpm-lock.yaml format has packages or dependencies keys
            # Format: packages key contains entries like '/@babel/core/7.12.0' or '/lodash/4.17.21'
            if 'packages' in pkg_data:
                packages = pkg_data.get('packages', {})
                if isinstance(packages, dict):
                    for pkg_path, pkg_info in packages.items():
                        if not isinstance(pkg_info, dict):
                            continue

                        # Extract package name and version from path like '/@babel/core/7.12.0' or '/lodash/4.17.21'
                        if pkg_path.startswith('/'):
                            parts = pkg_path[1:].rsplit('/', 1)  # Split from the right to get name and version
                            if len(parts) == 2:
                                name, version = parts
                                # Handle scoped packages like '@babel/core'
                                if name.startswith('@') or '/' in name:
                                    dependencies[name] = version
                                else:
                                    dependencies[name] = version
                            elif len(parts) == 1:
                                # Sometimes version is in the pkg_info
                                name = parts[0]
                                version = pkg_info.get('version')
                                if version:
                                    dependencies[name] = version

            # Also check dependencies section (older pnpm format)
            if 'dependencies' in pkg_data:
                deps = pkg_data.get('dependencies', {})
                if isinstance(deps, dict):
                    for name, version_info in deps.items():
                        if isinstance(version_info, str):
                            dependencies[name] = version_info
                        elif isinstance(version_info, dict) and 'version' in version_info:
                            dependencies[name] = version_info['version']

            return dependencies

        # Handle JSON files (package.json and package-lock.json)
        log_debug(f"    Detected JSON format (package.json or package-lock.json)")
        try:
            pkg_data = json.loads(content)
            log_debug(f"    Successfully parsed JSON")
        except json.JSONDecodeError as e:
            log_debug(f"    JSON parse error: {e}")
            return {}

        if 'package-lock' in file_path:
            log_debug(f"    Processing package-lock.json format")
            # package-lock.json v2/v3 format (packages key)
            if 'packages' in pkg_data:
                log_debug(f"    Found 'packages' key (v2/v3 format)")
                packages_count = len(pkg_data.get('packages', {}))
                log_debug(f"    Total packages entries: {packages_count}")

                for pkg_path, pkg_info in pkg_data.get('packages', {}).items():
                    if isinstance(pkg_info, dict):
                        name = pkg_info.get('name')
                        version = pkg_info.get('version')
                        if name and version:
                            dependencies[name] = version
                        # Also extract from node_modules path
                        elif 'node_modules/' in pkg_path and version:
                            # Extract name from path like "node_modules/lodash"
                            parts = pkg_path.split('node_modules/')
                            if len(parts) > 1:
                                name = parts[-1]
                                dependencies[name] = version

                log_debug(f"    Extracted {len(dependencies)} dependencies from packages key")

            # package-lock.json v1 format (dependencies key with nested structure)
            if 'dependencies' in pkg_data:
                log_debug(f"    Found 'dependencies' key (v1 format)")
                deps_before = len(dependencies)
                self._extract_v1_dependencies(pkg_data['dependencies'], dependencies)
                log_debug(f"    Extracted {len(dependencies) - deps_before} additional dependencies from v1 format")

            log_debug(f"    Total dependencies from package-lock.json: {len(dependencies)}")

        else:
            # package.json format
            log_debug(f"    Processing package.json format")
            for dep_type in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
                deps = pkg_data.get(dep_type, {})
                if isinstance(deps, dict):
                    deps_count = 0
                    for name, version in deps.items():
                        if isinstance(version, str):
                            dependencies[name] = version
                            deps_count += 1
                    if deps_count > 0:
                        log_debug(f"    Found {deps_count} {dep_type}")

            log_debug(f"    Total dependencies from package.json: {len(dependencies)}")

        log_debug(f"    Returning {len(dependencies)} total dependencies")
        return dependencies

    def _extract_v1_dependencies(self, deps: dict, result: dict[str, str]):
        """Recursively extract dependencies from package-lock.json v1 format."""
        for name, info in deps.items():
            if isinstance(info, dict):
                version = info.get('version')
                if version:
                    result[name] = version
                # Recurse into nested dependencies
                if 'dependencies' in info:
                    self._extract_v1_dependencies(info['dependencies'], result)

    async def _fetch_repo_packages(
        self, repo: str, index: int, total: int
    ) -> list[PackageFileInfo]:
        """Fetch all package files from a single repository, including subdirectories."""
        async with self.semaphore:
            log_progress(index, total, f"Fetching: {repo}")

            # Check if repo should be skipped based on age
            if await self._should_skip_repo(repo):
                return []

            # First, try to find all package files in the repo (including subdirectories)
            package_file_paths = await self._find_package_files(repo)

            # If search API found nothing, fall back to checking root directory
            if not package_file_paths:
                log_debug(f"  No package files found via tree API, checking root directory")
                package_file_paths = self.PACKAGE_FILES
            else:
                log_debug(f"  Package files to fetch: {package_file_paths}")

            files = []
            for file_path in package_file_paths:
                log_debug(f"  Fetching: {file_path}")
                result = await self._fetch_file_content(repo, file_path)
                if result:
                    content, html_url = result
                    log_debug(f"  Successfully fetched {file_path} ({len(content)} bytes)")
                    dependencies = self._extract_dependencies(content, file_path)
                    log_debug(f"  Extracted {len(dependencies)} dependencies from {file_path}")

                    if dependencies:  # Only include if there are dependencies
                        files.append(PackageFileInfo(
                            repository=repo,
                            file_path=file_path,
                            html_url=html_url,
                            dependencies=dependencies,
                            raw_content=content,
                        ))
                        log_debug(f"  ✓ Added {file_path} with {len(dependencies)} dependencies")
                    else:
                        log_debug(f"  ✗ Skipping {file_path} - no dependencies found")
                else:
                    log_debug(f"  ✗ Failed to fetch {file_path}")

            # Small delay to avoid rate limiting
            await asyncio.sleep(0.1)
            return files

    async def fetch_all(self) -> PackageCache:
        """
        Fetch all package files from the organization.
        Returns a PackageCache with all discovered package files.
        """
        repos = await self.list_repos()
        if not repos:
            return PackageCache(
                organization=self.org,
                fetched_at=datetime.now(timezone.utc).isoformat(),
                total_repos=0,
                total_files=0,
                repos_with_packages=0,
                files=[],
            )

        if self.max_repo_age_days > 0:
            log_info(f"Fetching package files from {len(repos)} repositories (filtering repos older than {self.max_repo_age_days} days)...")
        else:
            log_info(f"Fetching package files from {len(repos)} repositories...")

        # Fetch all repos concurrently with semaphore limiting
        tasks = [
            self._fetch_repo_packages(repo, idx + 1, len(repos))
            for idx, repo in enumerate(repos)
        ]
        results = await asyncio.gather(*tasks)

        # Flatten results and count skipped repos
        all_files: list[PackageFileInfo] = []
        repos_with_packages = 0
        repos_scanned = 0
        repos_skipped = 0

        for repo_files in results:
            if repo_files is None:
                continue
            if len(repo_files) == 0:
                repos_skipped += 1
            else:
                repos_scanned += 1
                repos_with_packages += 1
                all_files.extend(repo_files)

        cache = PackageCache(
            organization=self.org,
            fetched_at=datetime.now(timezone.utc).isoformat(),
            total_repos=len(repos),
            total_files=len(all_files),
            repos_with_packages=repos_with_packages,
            files=all_files,
        )

        log_info(f"Fetched {len(all_files)} package files from {repos_with_packages} repositories")
        if self.max_repo_age_days > 0:
            log_info(f"Skipped {repos_skipped} repositories (not updated in last {self.max_repo_age_days} days)")

        return cache


def save_cache(cache: PackageCache, file_path: str):
    """Save package cache to a JSON file."""
    with open(file_path, 'w') as f:
        json.dump(cache.to_dict(), f, indent=2)
    log_info(f"Package cache saved to: {file_path}")


def load_cache(file_path: str) -> Optional[PackageCache]:
    """Load package cache from a JSON file."""
    if not Path(file_path).exists():
        return None
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            return PackageCache.from_dict(data)
    except (json.JSONDecodeError, KeyError) as e:
        log_warn(f"Could not load cache file: {e}")
        return None
