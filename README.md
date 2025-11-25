# Shai-Hulud Scanner

Scan GitHub organizations for compromised npm packages in `package.json` and `package-lock.json` files.

## Prerequisites

- Python 3.9+
- [GitHub CLI](https://cli.github.com/) (`gh`) installed and authenticated

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip3 install -e .
```

## Usage

```bash
shai-hulud-scanner -g <github-org> [-c <concurrency>] [-d] [--fresh] [--scan-branches]
```

**From source (no install):**
```bash
PYTHONPATH=src python -m shai_hulud_scanner -g <github-org>
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-g, --org` | GitHub organization to scan | Required |
| `-c, --concurrency` | Number of parallel searches | 10 |
| `-d, --debug` | Show matched lines in output | Off |
| `--fresh` | Start fresh, ignore saved state | Off |
| `--scan-branches` | Scan all active branches (not just default) | Off |
| `--branch-age` | Only scan branches with commits in last N days | 30 |
| `--repo-prefix` | Only scan repositories starting with this prefix | None |

### Example

```bash
# Scan an organization
shai-hulud-scanner -g my-org

# Scan with higher concurrency
shai-hulud-scanner -g my-org -c 20

# Scan all active branches
shai-hulud-scanner -g my-org --scan-branches

# Scan only repositories starting with "service-"
shai-hulud-scanner -g my-org --repo-prefix service-
```

## Directory Structure

```
shai-hulud-scanner/
├── lists/              # Input: compromised library lists (.txt files)
│   ├── wiz_list.txt
│   └── semgrep_list.txt
├── outputs/            # Output: scan results (auto-generated)
│   ├── <org>.json
│   ├── <org>.findings.json
│   └── <org>.libraries.txt
└── src/
```

### Input Format (lists/*.txt)

Each `.txt` file in `lists/` contains one library per line in format `package-name-version`:

```
# Comments start with #
event-stream-3.3.6
ua-parser-js-0.7.29
@scope/package-name-1.0.0
```

The scanner automatically:
- Loads all `.txt` files from `lists/`
- Deduplicates entries across all files
- Sorts libraries alphabetically

## Output Files

All outputs are written to `outputs/<org>.*`:

| File | Description |
|------|-------------|
| `<org>.json` | Compromised package detections (exact version matches) |
| `<org>.findings.json` | Detailed findings including all library occurrences |
| `<org>.libraries.txt` | Combined, deduplicated, sorted list of libraries scanned |

### Findings File

The findings file captures every repository where a searched library was found, even if the version doesn't match:

```json
{
  "repository": "my-org/web-app",
  "file": "package-lock.json",
  "url": "https://github.com/.../package-lock.json#L42",
  "searched_library": "event-stream",
  "searched_version": "3.3.6",
  "found_version": "4.0.1",
  "is_match": false,
  "line_number": 42
}
```

This helps with:
- Understanding library usage across the organization
- Identifying repos that may need updates
- Future analysis if new vulnerable versions are discovered

## Resume Support

Scans can be interrupted (Ctrl+C) and resumed later. Progress is saved to `outputs/<org>.json.state`:

```bash
# Start a scan
shai-hulud-scanner -g my-org

# If interrupted, run the same command to resume
shai-hulud-scanner -g my-org

# To start fresh, ignoring saved state
shai-hulud-scanner -g my-org --fresh
```

## Branch Scanning Mode

By default, the scanner uses GitHub's Code Search API which only searches the default branch. To scan all active branches:

```bash
# Scan all branches with commits in the last 30 days
shai-hulud-scanner -g my-org --scan-branches

# Scan branches with commits in the last 7 days
shai-hulud-scanner -g my-org --scan-branches --branch-age 7
```

Branch scanning works in two phases:
1. **Discovery**: Lists all repos and their active branches, saves to `outputs/<org>.branches.json`
2. **Scanning**: Fetches `package.json` and `package-lock.json` from each branch and checks for compromised packages

**Note**: Branch scanning makes more API calls than code search mode and is slower, but provides complete coverage across all active branches.

## Sample Output

```
════════════════════════════════════════════════════════════
  SHAI-HULUD SCANNER
════════════════════════════════════════════════════════════
  Organization:    my-org
  Libraries:       1234
  Concurrency:     10
  Output:          outputs/my-org.json
════════════════════════════════════════════════════════════

[SCAN] (1/1234)   0.1% | Scanning: event-stream@3.3.6
[🚨 DETECTION] event-stream@3.3.6
           Repository: my-org/web-app
           File:       package-lock.json
           URL:        https://github.com/.../package-lock.json#L42
```
