"""Branch discovery for scanning all active branches."""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from .output import Colors, log_info, log_debug, log_progress, log_warn


@dataclass
class BranchInfo:
    """Information about a branch."""
    name: str
    last_commit_date: str
    sha: str


@dataclass
class RepoWithBranches:
    """Repository with its active branches."""
    repository: str
    default_branch: str
    branches: list[BranchInfo]

    def to_dict(self) -> dict:
        return {
            'repository': self.repository,
            'default_branch': self.default_branch,
            'branches': [asdict(b) for b in self.branches]
        }

    @classmethod
    def from_dict(cls, data: dict) -> RepoWithBranches:
        return cls(
            repository=data['repository'],
            default_branch=data['default_branch'],
            branches=[
                BranchInfo(
                    name=b['name'],
                    last_commit_date=b['last_commit_date'],
                    sha=b['sha']
                )
                for b in data['branches']
            ]
        )


@dataclass
class BranchDiscoveryResult:
    """Result of branch discovery."""
    organization: str
    discovered_at: str
    max_branch_age_days: int
    total_repos: int
    total_branches: int
    repos: list[RepoWithBranches]

    def to_dict(self) -> dict:
        return {
            'organization': self.organization,
            'discovered_at': self.discovered_at,
            'max_branch_age_days': self.max_branch_age_days,
            'total_repos': self.total_repos,
            'total_branches': self.total_branches,
            'repos': [r.to_dict() for r in self.repos]
        }

    @classmethod
    def from_dict(cls, data: dict) -> BranchDiscoveryResult:
        return cls(
            organization=data['organization'],
            discovered_at=data['discovered_at'],
            max_branch_age_days=data['max_branch_age_days'],
            total_repos=data['total_repos'],
            total_branches=data['total_branches'],
            repos=[RepoWithBranches.from_dict(r) for r in data['repos']]
        )


class BranchDiscovery:
    """Discovers active branches across an organization or specific repositories."""

    def __init__(self, org: str, max_age_days: int = 30, concurrency: int = 10, repos: Optional[list[str]] = None):
        self.org = org
        self.max_age_days = max_age_days
        self.concurrency = concurrency
        self.repos = repos  # Optional list of specific repos to scan
        self.semaphore = asyncio.Semaphore(concurrency)
        self.cutoff_date = datetime.now(timezone.utc) - timedelta(days=max_age_days)

    async def list_repos(self) -> list[str]:
        """List all repositories in the organization or return the specified repos."""
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

    async def get_repo_branches(self, repo: str, index: int, total: int, retry: int = 0) -> Optional[RepoWithBranches]:
        """Get active branches for a repository."""
        async with self.semaphore:
            log_progress(index, total, f"Discovering branches: {repo}")

            try:
                # Get default branch
                api_endpoint = f'repos/{repo}'
                log_debug(f"API call: gh api {api_endpoint}")
                proc = await asyncio.create_subprocess_exec(
                    'gh', 'api',
                    api_endpoint,
                    '--jq', '.default_branch',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr_default = await proc.communicate()

                if proc.returncode != 0:
                    error_msg = stderr_default.decode().strip()
                    log_debug(f"API error for '{api_endpoint}': {error_msg}")
                    if "404" in error_msg or "Not Found" in error_msg:
                        # Retry once for 404s as they might be transient
                        if retry < 1:
                            log_debug(f"Got 404 for {repo}, retrying...")
                            await asyncio.sleep(1)  # Brief delay before retry
                            return await self.get_repo_branches(repo, index, total, retry + 1)
                        log_warn(f"Repository not found or inaccessible: {repo} (API: {api_endpoint})")
                    else:
                        log_warn(f"Error accessing {repo}: {error_msg}")
                    return None

                default_branch = stdout.decode().strip() or 'main'
                log_debug(f"Default branch for {repo}: {default_branch}")

                # Get branches and filter by age
                # Note: We only fetch the first page (100 branches) to avoid excessive API calls
                # Most active branches will be in the first 100 results
                branches_endpoint = f'repos/{repo}/branches?per_page=100'
                log_debug(f"API call: gh api {branches_endpoint}")
                proc = await asyncio.create_subprocess_exec(
                    'gh', 'api',
                    branches_endpoint,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()

                if proc.returncode != 0:
                    error_msg = stderr.decode().strip()
                    log_debug(f"API error for '{branches_endpoint}': {error_msg}")
                    if "404" in error_msg or "Not Found" in error_msg:
                        # Retry once for 404s as they might be transient
                        if retry < 1:
                            log_debug(f"Got 404 for {repo} branches, retrying...")
                            await asyncio.sleep(2)  # Longer delay before retry
                            return await self.get_repo_branches(repo, index, total, retry + 1)
                        log_warn(f"Branches not found for {repo} (may be empty or inaccessible) (API: {branches_endpoint})")
                    elif "rate limit" in error_msg.lower():
                        log_warn(f"Rate limited while fetching branches for {repo}. Consider reducing concurrency.")
                    else:
                        log_warn(f"Error getting branches for {repo}: {error_msg}")
                    return None

                # Parse the JSON array response
                try:
                    all_branches_data = json.loads(stdout.decode().strip())
                    if not isinstance(all_branches_data, list):
                        log_debug(f"Unexpected response format for {repo}/branches")
                        return None
                except json.JSONDecodeError:
                    log_debug(f"Failed to parse branches response for {repo}")
                    return None

                if not all_branches_data:
                    log_debug(f"No branches found in {repo}")
                    return None

                log_debug(f"Found {len(all_branches_data)} branches in {repo}")

                # Filter branches by age
                # We check commit dates to filter, but stop early if we find many old branches in a row
                active_branches = []
                consecutive_old = 0
                checked_count = 0

                for branch_item in all_branches_data:
                    if not isinstance(branch_item, dict):
                        continue

                    branch_name = branch_item.get('name')
                    branch_sha = branch_item.get('commit', {}).get('sha')

                    if not branch_name or not branch_sha:
                        continue

                    # Get commit date for age filtering
                    commit_date = await self._get_commit_date(repo, branch_sha)
                    checked_count += 1

                    if commit_date is None:
                        log_debug(f"Could not get commit date for {repo}:{branch_name}, skipping")
                        continue

                    # Only include branches within the age threshold
                    if commit_date >= self.cutoff_date:
                        active_branches.append(BranchInfo(
                            name=branch_name,
                            last_commit_date=commit_date.isoformat(),
                            sha=branch_sha
                        ))
                        consecutive_old = 0  # Reset counter on finding active branch
                    else:
                        log_debug(f"Skipping old branch {repo}:{branch_name} (last commit: {commit_date.date()})")

                if not active_branches:
                    log_debug(f"No valid branches in {repo}")
                    return None

                log_debug(f"Including {len(active_branches)} branches from {repo}")

                return RepoWithBranches(
                    repository=repo,
                    default_branch=default_branch,
                    branches=active_branches
                )

            except Exception as e:
                log_debug(f"Error processing {repo}: {e}")
                return None

    async def _get_commit_date(self, repo: str, sha: str) -> Optional[datetime]:
        """Get the commit date for a specific SHA."""
        try:
            proc = await asyncio.create_subprocess_exec(
                'gh', 'api',
                f'repos/{repo}/commits/{sha}',
                '--jq', '.commit.committer.date',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()

            if proc.returncode != 0:
                return None

            date_str = stdout.decode().strip()
            if date_str:
                return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            return None

        except Exception:
            return None

    async def discover(self) -> BranchDiscoveryResult:
        """Discover all active branches in the organization."""
        repos = await self.list_repos()

        if not repos:
            return BranchDiscoveryResult(
                organization=self.org,
                discovered_at=datetime.now(timezone.utc).isoformat(),
                max_branch_age_days=self.max_age_days,
                total_repos=0,
                total_branches=0,
                repos=[]
            )

        log_info(f"Discovering active branches (last {self.max_age_days} days)...")

        tasks = [
            self.get_repo_branches(repo, idx + 1, len(repos))
            for idx, repo in enumerate(repos)
        ]

        results = await asyncio.gather(*tasks)

        repos_with_branches = [r for r in results if r is not None]
        total_branches = sum(len(r.branches) for r in repos_with_branches)

        return BranchDiscoveryResult(
            organization=self.org,
            discovered_at=datetime.now(timezone.utc).isoformat(),
            max_branch_age_days=self.max_age_days,
            total_repos=len(repos_with_branches),
            total_branches=total_branches,
            repos=repos_with_branches
        )


def save_branches(result: BranchDiscoveryResult, file_path: str):
    """Save branch discovery result to a JSON file."""
    with open(file_path, 'w') as f:
        json.dump(result.to_dict(), f, indent=2)
    log_info(f"Branches saved to: {file_path}")


def load_branches(file_path: str) -> Optional[BranchDiscoveryResult]:
    """Load branch discovery result from a JSON file."""
    if not Path(file_path).exists():
        return None
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            return BranchDiscoveryResult.from_dict(data)
    except (json.JSONDecodeError, KeyError) as e:
        log_warn(f"Could not load branches file: {e}")
        return None
