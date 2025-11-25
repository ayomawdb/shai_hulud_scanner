"""Data models for scan results."""

from dataclasses import dataclass, asdict


@dataclass
class SearchResult:
    repository: str
    file: str
    url: str
    library: str
    version: str


@dataclass
class AffectedRepository:
    repository: str
    affected_libraries: list
    files_affected: list


@dataclass
class ScanReport:
    scan_date: str
    organization: str
    total_libraries_scanned: int
    affected_repositories: int
    results: list

    def to_dict(self) -> dict:
        return asdict(self)
