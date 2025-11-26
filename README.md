# Shai-Hulud Scanner

Scan GitHub organizations for compromised npm packages in `package.json`, `package-lock.json`, and `pnpm-lock.yaml` files.

## Quick Start

```bash
# 1. Install dependencies
pip install pyyaml

# 2. Authenticate with GitHub CLI
gh auth login

# 3. Create organization file
echo "my-org" > orgs.txt

# 4. Run scanner
python3 -m shai_hulud_scanner.cli -g orgs.txt

# Results will be in: outputs/my-org.json
```

## Prerequisites

- Python 3.9+
- [GitHub CLI](https://cli.github.com/) (`gh`) installed and authenticated
- PyYAML (`pip install pyyaml`) - required for pnpm-lock.yaml support

## Installation

### Option 1: Install as Package
```bash
pip install -e .
```

After installation, you can run the scanner from anywhere:
```bash
shai-hulud-scanner -g orgs.txt
```

### Option 2: Run from Source (No Installation)

If you prefer not to install the package, you can run it directly from source:

```bash
# Install dependencies first
pip install pyyaml

# Run the scanner as a module
python3 -m shai_hulud_scanner.cli -g orgs.txt
```

The working directory should be the repository root (where `lists/` and `outputs/` directories are located).

## Usage

```bash
shai-hulud-scanner -g <org-file> [options]
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-g, --org` | **File** containing GitHub organization names (one per line) | Required* |
| `-r, --repos` | File containing repository URLs, or comma-separated list | Optional |
| `-c, --concurrency` | Number of parallel operations | 1 |
| `-d, --debug` | Enable debug output (show matched lines) | Off |
| `--fresh` | Start fresh, ignore saved state | Off |
| `--scan-branches` | Scan all active branches (not just default) | Off |
| `--branch-age` | Only scan branches with commits in last N days | 30 |
| `--repo-age` | Only scan repos updated in last N days (0=all) | 30 |
| `--use-search-api` | Use legacy GitHub Code Search API (slower) | Off |
| `--refresh-cache` | Force refresh of package file cache | Off |

\* Either `--org` or `--repos` is required

**Important:** The `-g` flag now **always requires a file path** (not a direct organization name). See examples below.

### Examples

```bash
# Scan organizations from a file (one org per line)
shai-hulud-scanner -g orgs.txt

# Scan a single organization (create file with one line)
echo "my-org" > org.txt
shai-hulud-scanner -g org.txt

# Scan specific repositories from a file
shai-hulud-scanner -r repos.txt

# Scan specific repositories (comma-separated, no file needed)
shai-hulud-scanner -r owner/repo1,owner/repo2

# Scan with higher concurrency
shai-hulud-scanner -g orgs.txt -c 10

# Scan all active branches (not just default branch)
shai-hulud-scanner -g orgs.txt --scan-branches

# Scan branches updated in the last 7 days
shai-hulud-scanner -g orgs.txt --scan-branches --branch-age 7

# Scan only repositories updated in the last 7 days (faster)
shai-hulud-scanner -g orgs.txt --repo-age 7

# Scan all repositories regardless of age
shai-hulud-scanner -g orgs.txt --repo-age 0

# Refresh the package cache and re-scan
shai-hulud-scanner -g orgs.txt --refresh-cache

# Debug mode - show matched lines in output
shai-hulud-scanner -g orgs.txt -d
```

### Input Requirements

#### Organization File (`-g` flag)

The `-g` flag **requires a file path**. Create a text file with one organization name per line:

**Example `orgs.txt`:**
```
# List of organizations to scan (comments start with #)
my-org
another-org
third-org
```

Then run:
```bash
shai-hulud-scanner -g orgs.txt
```

The tool will log the full path it's reading from:
```
[INFO] Reading organization list from: /full/path/to/orgs.txt
[INFO] Loaded 3 organizations from file
```

**For a single organization**, create a file with one line:
```bash
echo "my-org" > org.txt
shai-hulud-scanner -g org.txt
```

**When scanning multiple organizations:**
- Each org is scanned sequentially
- Separate output files are generated for each org in `outputs/`
- The same library list is used for all organizations
- A final summary shows success/failure for each org

#### Repository File (`-r` flag)

The `-r` flag accepts **either a file path OR a comma-separated list**:

**Option 1: From a text file** (one repo per line):

**Example `repos.txt`:**
```
# List of repositories to scan (comments start with #)
owner/repo-name
https://github.com/owner/another-repo
https://github.com/owner/third-repo.git
```

```bash
shai-hulud-scanner -r repos.txt
```

**Option 2: Comma-separated list** (no file needed):
```bash
shai-hulud-scanner -r owner/repo1,owner/repo2
```

**Option 3: Limit org scan to specific repos** (combine `-g` and `-r`):
```bash
# Scan only specific repos within an organization
echo "my-org" > org.txt
shai-hulud-scanner -g org.txt -r repos.txt

# Or with comma-separated list
shai-hulud-scanner -g org.txt -r my-org/repo1,my-org/repo2
```

**Supported repository formats:**
- `owner/repo` - Direct format (recommended)
- `https://github.com/owner/repo` - Full URL
- `https://github.com/owner/repo.git` - Git URL
- `github.com/owner/repo` - Short URL

## Directory Structure

```
shai-hulud-scanner/
├── lists/                      # Input: compromised library lists (.txt files)
│   ├── wiz_list.txt
│   ├── semgrep_list.txt
│   └── tenable_semgrep_format.txt
├── outputs/                    # Output: scan results (auto-generated)
│   ├── <org>.json             # Main results file
│   ├── <org>.findings.json    # Detailed findings
│   ├── <org>.libraries.txt    # Combined library list
│   ├── <org>.duplicates.txt   # Deduplicated entries
│   ├── <org>.packages.json    # Package file cache
│   └── <org>.json.state       # Resume state (if interrupted)
└── src/
```

**Cache files** (`*.packages.json`): Package file cache containing all fetched `package.json`, `package-lock.json`, and `pnpm-lock.yaml` files. Reused on subsequent runs unless `--refresh-cache` is specified.

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
| `<org>.json` | Main results: compromised package detections (exact version matches) |
| `<org>.findings.json` | Detailed findings including all library occurrences (matches and non-matches) |
| `<org>.libraries.txt` | Combined, deduplicated, sorted list of libraries scanned from all lists/*.txt files |
| `<org>.duplicates.txt` | List of duplicate entries removed during deduplication |
| `<org>.packages.json` | Cached package files from repositories (reused on next run) |
| `<org>.json.state` | Resume state file (created if scan is interrupted) |

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
shai-hulud-scanner -g orgs.txt

# If interrupted (Ctrl+C), run the same command to resume
shai-hulud-scanner -g orgs.txt

# To start fresh, ignoring saved state
shai-hulud-scanner -g orgs.txt --fresh
```

**Note:** Resume support works with the `--use-search-api` mode. For the default local scan mode, use the package cache (`*.packages.json`) to avoid re-fetching files.

## Scanning Modes

### Default Mode: Default Branch Only

By default, the scanner fetches package files from the default branch (usually `main` or `master`) of each repository. This is fast and covers most use cases.

```bash
shai-hulud-scanner -g orgs.txt
```

### Branch Scanning Mode: All Active Branches

To scan all active branches in each repository, use the `--scan-branches` flag:

```bash
# Scan all branches with commits in the last 30 days (default)
shai-hulud-scanner -g orgs.txt --scan-branches

# Scan branches with commits in the last 7 days only
shai-hulud-scanner -g orgs.txt --scan-branches --branch-age 7

# Scan branches from the last 60 days
shai-hulud-scanner -g orgs.txt --scan-branches --branch-age 60
```

**How it works:**
1. For each repository, the scanner fetches all branches
2. Filters branches by age (commits in last N days, default 30)
3. Fetches package files (`package.json`, `package-lock.json`, `pnpm-lock.yaml`) from each active branch
4. Results include branch information: `owner/repo:branch-name`

**Performance notes:**
- Branch scanning makes significantly more API calls
- Use `--branch-age` to limit the number of branches scanned
- Use `--repo-age` to skip old repositories entirely
- Recommended concurrency: 1-5 for branch scanning (to avoid rate limits)

**Example: Fast scan of recently updated code**
```bash
# Only scan repos updated in last 7 days, only branches from last 7 days
shai-hulud-scanner -g orgs.txt --scan-branches --repo-age 7 --branch-age 7 -c 3
```

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
