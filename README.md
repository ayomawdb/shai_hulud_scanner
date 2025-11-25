# Shai-Hulud Scanner

Scan GitHub organizations for compromised npm packages in `package.json` and `package-lock.json` files.

## Prerequisites

- Python 3.9+
- [GitHub CLI](https://cli.github.com/) (`gh`) installed and authenticated

## Installation

```bash
pip install -e .
```

## Usage

**Installed:**
```bash
shai-hulud-scanner -g <github-org> -f <libraries.csv> [-c <concurrency>] [-o <output>]
```

**From source (no install):**
```bash
PYTHONPATH=src python -m shai_hulud_scanner -g <github-org> -f <libraries.csv>
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-g, --org` | GitHub organization to scan | Required |
| `-f, --file` | CSV file with compromised libraries | Required |
| `-c, --concurrency` | Number of parallel searches | 10 |
| `-o, --output` | Output JSON file | scan-results.json |
| `-d, --debug` | Show matched lines in output | Off |
| `--fresh` | Start fresh, ignore saved state | Off |
| `--scan-branches` | Scan all active branches (not just default) | Off |
| `--branch-age` | Only scan branches with commits in last N days | 30 |
| `--branches-file` | JSON file to save/load discovered branches | `<output>.branches.json` |

### Input File Format

The input file should contain one library per line in the format `package-name-version`:

```
# Comments start with #
event-stream-3.3.6
ua-parser-js-0.7.29
@scope/package-name-1.0.0
```

The scanner automatically:
- Deduplicates entries
- Sorts libraries alphabetically

### Example

```bash
shai-hulud-scanner -g my-org -f compromised.txt -c 20 -o results.json
```

## Output

Results stream in real-time as detections are found:

```
════════════════════════════════════════════════════════════
  SHAI-HULUD SCANNER
════════════════════════════════════════════════════════════
  Organization:    my-org
  Libraries:       9
  Concurrency:     10
  Output:          scan-results.json
════════════════════════════════════════════════════════════

[SCAN] (1/9)  11.1% | Scanning: event-stream@3.3.6
[🚨 DETECTION] event-stream@3.3.6
           Repository: my-org/web-app
           File:       package-lock.json
           URL:        https://github.com/...
```

JSON output is saved to the specified file with full details.

## Output Files

The scanner produces two output files:

1. **`<output>.json`** - Compromised package detections (exact version matches)
2. **`<output>.findings.json`** - Detailed findings including all library occurrences

The findings file captures every repository where a searched library was found, even if the version doesn't match. This helps with:
- Understanding library usage across the organization
- Identifying repos that may need updates
- Future analysis if new vulnerable versions are discovered

Example findings entry:
```json
{
  "repository": "my-org/web-app",
  "file": "package-lock.json",
  "url": "https://github.com/...",
  "searched_library": "event-stream",
  "searched_version": "3.3.6",
  "found_version": "4.0.1",
  "is_match": false
}
```

## Resume Support

Scans can be interrupted (Ctrl+C) and resumed later. Progress is saved to `<output>.state`:

```bash
# Start a scan
shai-hulud-scanner -g my-org -f compromised.csv -o results.json

# If interrupted, run the same command to resume
shai-hulud-scanner -g my-org -f compromised.csv -o results.json

# To start fresh, ignoring saved state
shai-hulud-scanner -g my-org -f compromised.csv -o results.json --fresh
```

## Branch Scanning Mode

By default, the scanner uses GitHub's Code Search API which only searches the default branch. To scan all active branches:

```bash
# Scan all branches with commits in the last 30 days
shai-hulud-scanner -g my-org -f compromised.csv --scan-branches

# Scan branches with commits in the last 7 days
shai-hulud-scanner -g my-org -f compromised.csv --scan-branches --branch-age 7

# Use a specific branches file
shai-hulud-scanner -g my-org -f compromised.csv --scan-branches --branches-file branches.json
```

Branch scanning works in two phases:
1. **Discovery**: Lists all repos and their active branches, saves to `<output>.branches.json`
2. **Scanning**: Fetches `package.json` and `package-lock.json` from each branch and checks for compromised packages

The branches file can be reused across runs (unless `--fresh` is specified), saving API calls.

**Note**: Branch scanning makes more API calls than code search mode and is slower, but provides complete coverage across all active branches.
