# Shai-Hulud Scanner

Scan GitHub organizations for compromised npm packages in `package.json`, `package-lock.json`, and `pnpm-lock.yaml` files.

## Prerequisites

- Python 3.9+
- [GitHub CLI](https://cli.github.com/) (`gh`) installed and authenticated
- PyYAML (`pip install pyyaml`) - required for pnpm-lock.yaml support

## Installation

```bash
pip install -e .
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
| `-g, --org` | GitHub organization(s) to scan | Required* |
| `-r, --repos` | Specific repository/repositories to scan | Optional |
| `-c, --concurrency` | Number of parallel searches | 10 |
| `-d, --debug` | Show matched lines in output | Off |
| `--fresh` | Start fresh, ignore saved state | Off |
| `--scan-branches` | Scan all active branches (not just default) | Off |
| `--branch-age` | Only scan branches with commits in last N days | 30 |
| `--use-search-api` | Use legacy GitHub Code Search API (slower) | Off |
| `--refresh-cache` | Refresh package file cache (local scan mode) | Off |

\* Either `--org` or `--repos` is required

### Examples

```bash
# Scan a single organization
shai-hulud-scanner -g my-org

# Scan multiple organizations (comma-separated)
shai-hulud-scanner -g org1,org2,org3

# Scan multiple organizations from a file
shai-hulud-scanner -g orgs.txt

# Scan specific repositories from a file
shai-hulud-scanner -r repos.txt

# Scan specific repositories (comma-separated)
shai-hulud-scanner -r owner/repo1,owner/repo2

# Scan with higher concurrency
shai-hulud-scanner -g my-org -c 20

# Scan all active branches
shai-hulud-scanner -g my-org --scan-branches

# Refresh the package cache and re-scan
shai-hulud-scanner -g my-org --refresh-cache
```

### Multiple Organizations

You can scan multiple organizations in several ways:

1. **From a text file** (one org per line):
   ```bash
   shai-hulud-scanner -g orgs.txt
   ```

   Example `orgs.txt`:
   ```
   # List of organizations to scan
   my-org
   another-org
   third-org
   ```

2. **Comma-separated list**:
   ```bash
   shai-hulud-scanner -g org1,org2,org3
   ```

When scanning multiple organizations:
- Each org is scanned sequentially
- Separate output files are generated for each org in `outputs/`
- The same library list is used for all organizations
- A final summary shows success/failure for each org

### Specific Repositories

Instead of scanning an entire organization, you can scan specific repositories:

1. **From a text file** (one repo per line):
   ```bash
   shai-hulud-scanner -r repos.txt
   ```

   Example `repos.txt`:
   ```
   # List of repositories to scan
   owner/repo-name
   https://github.com/owner/another-repo
   https://github.com/owner/third-repo.git
   ```

2. **Comma-separated list**:
   ```bash
   shai-hulud-scanner -r owner/repo1,owner/repo2
   ```

Supported repository formats:
- `owner/repo` - Direct format
- `https://github.com/owner/repo` - Full URL
- `https://github.com/owner/repo.git` - Git URL
- `github.com/owner/repo` - Short URL

**Branch Scanning**: `--scan-branches` works with both `--org` and `--repos` modes:
```bash
# Scan all active branches in specific repositories
shai-hulud-scanner -r repos.txt --scan-branches

# Scan branches with commits in the last 7 days
shai-hulud-scanner -r repos.txt --scan-branches --branch-age 7
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

## Semantic Versioning Range Detection

The scanner intelligently handles npm's semantic versioning ranges:

- **Lock files** (`package-lock.json`, `pnpm-lock.yaml`): Exact version matching
- **package.json**: Checks if vulnerable version satisfies the semver range

Example: Searching for vulnerable `lodash@4.17.20`:
- `"lodash": "^4.17.0"` → **DETECTED** (range allows 4.17.20)
- `"lodash": "^4.17.21"` → **SAFE** (range requires >=4.17.21)

See [SEMVER_HANDLING.md](SEMVER_HANDLING.md) for detailed documentation.

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
