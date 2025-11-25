"""Fetch and cache package.json and package-lock.json files from GitHub repositories."""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import PackageCache, PackageFileInfo
from .output import log_info, log_debug, log_progress, log_warn


class PackageFetcher:
    """Fetches package files from GitHub repositories and caches them locally."""

    # Files to look for in each repository
    PACKAGE_FILES = ['package.json', 'package-lock.json']

    def __init__(
        self,
        org: str,
        concurrency: int = 10,
        repos: Optional[list[str]] = None
    ):
        self.org = org
        self.concurrency = concurrency
        self.semaphore = asyncio.Semaphore(concurrency)
        self.repos = repos  # Optional list of specific repos to scan

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
            proc = await asyncio.create_subprocess_exec(
                'gh', 'api',
                f'orgs/{self.org}/repos',
                '--field', f'per_page={per_page}',
                '--field', f'page={page}',
                '--field', 'type=all',
                '--jq', '.[].full_name',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                error = stderr.decode().strip()
                log_warn(f"Error listing repos: {error}")
                break

            output = stdout.decode().strip()
            if not output:
                break

            page_repos = output.split('\n')
            repos.extend(page_repos)

            if len(page_repos) < per_page:
                break

            page += 1

        log_info(f"Found {len(repos)} repositories")
        return repos

    async def _fetch_file_content(self, repo: str, file_path: str) -> Optional[tuple[str, str]]:
        """
        Fetch a file's content from a repository.
        Returns (content, html_url) or None if file doesn't exist.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                'gh', 'api',
                f'repos/{repo}/contents/{file_path}',
                '--jq', '{content: .content, html_url: .html_url}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                # File doesn't exist or other error - this is normal
                return None

            data = json.loads(stdout.decode().strip())
            content = base64.b64decode(data['content']).decode('utf-8')
            return content, data['html_url']

        except Exception as e:
            log_debug(f"Error fetching {repo}/{file_path}: {e}")
            return None

    def _extract_dependencies(self, content: str, file_path: str) -> dict[str, str]:
        """
        Extract all dependencies from a package.json or package-lock.json file.
        Returns a dict mapping package name to version.
        """
        try:
            pkg_data = json.loads(content)
        except json.JSONDecodeError:
            return {}

        dependencies: dict[str, str] = {}

        if 'package-lock' in file_path:
            # package-lock.json v2/v3 format (packages key)
            if 'packages' in pkg_data:
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

            # package-lock.json v1 format (dependencies key with nested structure)
            if 'dependencies' in pkg_data:
                self._extract_v1_dependencies(pkg_data['dependencies'], dependencies)

        else:
            # package.json format
            for dep_type in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
                deps = pkg_data.get(dep_type, {})
                if isinstance(deps, dict):
                    for name, version in deps.items():
                        if isinstance(version, str):
                            dependencies[name] = version

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
        """Fetch all package files from a single repository."""
        async with self.semaphore:
            log_progress(index, total, f"Fetching: {repo}")

            files = []
            for file_path in self.PACKAGE_FILES:
                result = await self._fetch_file_content(repo, file_path)
                if result:
                    content, html_url = result
                    dependencies = self._extract_dependencies(content, file_path)

                    if dependencies:  # Only include if there are dependencies
                        files.append(PackageFileInfo(
                            repository=repo,
                            file_path=file_path,
                            html_url=html_url,
                            dependencies=dependencies,
                            raw_content=content,
                        ))
                        log_debug(f"  Found {file_path} with {len(dependencies)} dependencies")

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

        log_info(f"Fetching package files from {len(repos)} repositories...")

        # Fetch all repos concurrently with semaphore limiting
        tasks = [
            self._fetch_repo_packages(repo, idx + 1, len(repos))
            for idx, repo in enumerate(repos)
        ]
        results = await asyncio.gather(*tasks)

        # Flatten results
        all_files: list[PackageFileInfo] = []
        repos_with_packages = 0
        for repo_files in results:
            if repo_files:
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
