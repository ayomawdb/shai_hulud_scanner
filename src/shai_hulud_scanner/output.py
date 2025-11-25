"""Output formatting and logging utilities."""

import sys

# Global debug flag
DEBUG = False


def set_debug(enabled: bool):
    global DEBUG
    DEBUG = enabled


class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    NC = '\033[0m'


def log_info(msg: str):
    print(f"{Colors.GREEN}[INFO]{Colors.NC} {msg}", file=sys.stderr)


def log_error(msg: str):
    print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}", file=sys.stderr)


def log_progress(msg: str):
    print(f"{Colors.CYAN}[SCAN]{Colors.NC} {msg}", file=sys.stderr)


def log_debug(msg: str):
    if DEBUG:
        print(f"{Colors.DIM}[DEBUG]{Colors.NC} {msg}", file=sys.stderr)


def log_detection(
    lib: str,
    version: str,
    repo: str,
    file: str,
    url: str,
    matched_lines: list[str] | None = None
):
    print(f"{Colors.RED}{Colors.BOLD}[🚨 DETECTION]{Colors.NC} {lib}@{version}", file=sys.stderr)
    print(f"           Repository: {Colors.YELLOW}{repo}{Colors.NC}", file=sys.stderr)
    print(f"           File:       {file}", file=sys.stderr)
    print(f"           URL:        {url}", file=sys.stderr)
    if DEBUG and matched_lines:
        print(f"           {Colors.MAGENTA}Matched lines:{Colors.NC}", file=sys.stderr)
        for line in matched_lines[:5]:  # Show up to 5 matched lines
            print(f"             {Colors.DIM}{line.strip()}{Colors.NC}", file=sys.stderr)
    print("", file=sys.stderr)


def print_header(org: str, total_libs: int, concurrency: int, output_file: str):
    print("")
    print(f"{Colors.BOLD}════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.BOLD}  SHAI-HULUD SCANNER{Colors.NC}")
    print(f"{Colors.BOLD}════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"  Organization:    {Colors.CYAN}{org}{Colors.NC}")
    print(f"  Libraries:       {Colors.CYAN}{total_libs}{Colors.NC}")
    print(f"  Concurrency:     {Colors.CYAN}{concurrency}{Colors.NC}")
    print(f"  Output:          {Colors.CYAN}{output_file}{Colors.NC}")
    print(f"{Colors.BOLD}════════════════════════════════════════════════════════════{Colors.NC}")
    print("")


def print_summary(report, detection_count: int):
    print("")
    print(f"{Colors.BOLD}════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.BOLD}  SCAN COMPLETE{Colors.NC}")
    print(f"{Colors.BOLD}════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"  Libraries Scanned:      {Colors.CYAN}{report.total_libraries_scanned}{Colors.NC}")
    print(f"  Total Detections:       {Colors.RED}{Colors.BOLD}{detection_count}{Colors.NC}")
    print(f"  Affected Repositories:  {Colors.RED}{Colors.BOLD}{report.affected_repositories}{Colors.NC}")
    print(f"{Colors.BOLD}════════════════════════════════════════════════════════════{Colors.NC}")

    if report.affected_repositories > 0:
        print("")
        print(f"{Colors.BOLD}Affected Repositories:{Colors.NC}")
        for repo in report.results:
            lib_count = len(repo['affected_libraries'])
            print(f"  ⚠️  {repo['repository']} - {lib_count} compromised package(s)")

    print("")
