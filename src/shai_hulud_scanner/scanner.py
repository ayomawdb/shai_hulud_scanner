"""GitHub code search scanner for compromised libraries."""

import asyncio
import json
import sys

from .models import SearchResult, AffectedRepository
from .output import Colors, log_progress, log_detection, log_debug


class GitHubScanner:
    def __init__(self, org: str, concurrency: int = 10):
        self.org = org
        self.concurrency = concurrency
        self.semaphore = asyncio.Semaphore(concurrency)
        self.rate_limit_delay = 0.3
        self.results: list[SearchResult] = []
        self.results_lock = asyncio.Lock()
        self.detection_count = 0

    async def _fetch_matched_lines(
        self, repo: str, file_path: str, lib_name: str, lib_version: str
    ) -> list[str]:
        """Fetch the actual file content and extract matched lines."""
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
                return []

            import base64
            content = base64.b64decode(stdout.decode().strip()).decode('utf-8')

            matched = []
            for line in content.split('\n'):
                if lib_name in line and lib_version in line:
                    matched.append(line)

            return matched
        except Exception:
            return []

    async def search_library(
        self, lib_name: str, lib_version: str, index: int, total: int
    ) -> list[SearchResult]:
        """Search for a specific library version in package files."""
        async with self.semaphore:
            log_progress(f"({index}/{total}) Scanning: {lib_name}@{lib_version}")

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
                    '--jq', '.items[] | {repository: .repository.full_name, file: .path, url: .html_url, text_matches: .text_matches}',
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
                            f"{lib_name}@{lib_version} - waiting 60s",
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
                            result = SearchResult(
                                repository=item['repository'],
                                file=item['file'],
                                url=item['url'],
                                library=lib_name,
                                version=lib_version
                            )
                            results.append(result)

                            # Extract matched lines from text_matches if available
                            matched_lines = []
                            text_matches = item.get('text_matches') or []
                            for tm in text_matches:
                                fragment = tm.get('fragment', '')
                                if fragment:
                                    matched_lines.append(fragment)

                            log_detection(
                                lib_name, lib_version,
                                item['repository'], item['file'], item['url'],
                                matched_lines=matched_lines
                            )

                            async with self.results_lock:
                                self.detection_count += 1

                        except json.JSONDecodeError:
                            continue

                await asyncio.sleep(self.rate_limit_delay)
                return results

            except Exception as e:
                print(
                    f"{Colors.RED}[ERROR]{Colors.NC} Searching {lib_name}@{lib_version}: {e}",
                    file=sys.stderr
                )
                return []

    async def scan_libraries(
        self, libraries: list[tuple[str, str]]
    ) -> list[SearchResult]:
        """Scan all libraries concurrently with real-time output."""
        total = len(libraries)

        tasks = [
            self.search_library(name, version, idx + 1, total)
            for idx, (name, version) in enumerate(libraries)
        ]

        all_results = await asyncio.gather(*tasks)
        return [r for results in all_results for r in results]

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
                'url': r.url
            }

            if lib_entry not in repos[r.repository].affected_libraries:
                repos[r.repository].affected_libraries.append(lib_entry)

            if r.file not in repos[r.repository].files_affected:
                repos[r.repository].files_affected.append(r.file)

        return list(repos.values())
