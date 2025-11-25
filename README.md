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

### CSV Format

```csv
# Comments start with #
library-name,library-version
event-stream,3.3.6
ua-parser-js,0.7.29
```

### Example

```bash
shai-hulud-scanner -g my-org -f compromised.csv -c 20 -o results.json
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

[SCAN] (1/9) Scanning: event-stream@3.3.6
[🚨 DETECTION] event-stream@3.3.6
           Repository: my-org/web-app
           File:       package-lock.json
           URL:        https://github.com/...
```

JSON output is saved to the specified file with full details.
