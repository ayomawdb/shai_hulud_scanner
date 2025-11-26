"""Data models for scan results."""

from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Optional


@dataclass
class SearchResult:
    repository: str
    file: str
    url: str
    library: str
    version: str
    line_number: Optional[int] = None
    branch: Optional[str] = None  # None means default branch

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AffectedRepository:
    repository: str
    affected_libraries: list
    files_affected: list


@dataclass
class ScanState:
    """Tracks scan progress for resume capability."""
    organization: str
    total_libraries: int
    scanned_libraries: list  # List of "name@version" strings
    detections: list  # List of SearchResult dicts
    started_at: str
    updated_at: str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> ScanState:
        return cls(
            organization=data['organization'],
            total_libraries=data['total_libraries'],
            scanned_libraries=data['scanned_libraries'],
            detections=data['detections'],
            started_at=data['started_at'],
            updated_at=data['updated_at']
        )


@dataclass
class ScanReport:
    scan_date: str
    organization: str
    total_libraries_scanned: int
    affected_repositories: int
    results: list

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LibraryFinding:
    """Record of a library found during scanning (regardless of version match)."""
    repository: str
    file: str
    url: str
    searched_library: str      # The library we were searching for
    searched_version: str      # The version we were looking for
    found_version: str         # The actual version found in the repo
    is_match: bool             # True if versions match (compromised), False if different version
    branch: Optional[str] = None
    line_number: Optional[int] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PackageFileInfo:
    """Information about a package file in a repository."""
    repository: str
    file_path: str
    html_url: str
    dependencies: dict = field(default_factory=dict)  # name -> list of versions (supports multiple versions)
    raw_content: Optional[str] = None  # Original JSON content for line number lookup

    def to_dict(self) -> dict:
        return {
            'repository': self.repository,
            'file_path': self.file_path,
            'html_url': self.html_url,
            'dependencies': self.dependencies,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'PackageFileInfo':
        return cls(
            repository=data['repository'],
            file_path=data['file_path'],
            html_url=data['html_url'],
            dependencies=data.get('dependencies', {}),
        )


@dataclass
class PackageCache:
    """Cache of all package files in an organization."""
    organization: str
    fetched_at: str
    total_repos: int
    total_files: int
    repos_with_packages: int
    files: list[PackageFileInfo] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            'organization': self.organization,
            'fetched_at': self.fetched_at,
            'total_repos': self.total_repos,
            'total_files': self.total_files,
            'repos_with_packages': self.repos_with_packages,
            'files': [f.to_dict() for f in self.files],
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'PackageCache':
        return cls(
            organization=data['organization'],
            fetched_at=data['fetched_at'],
            total_repos=data['total_repos'],
            total_files=data['total_files'],
            repos_with_packages=data['repos_with_packages'],
            files=[PackageFileInfo.from_dict(f) for f in data.get('files', [])],
        )
