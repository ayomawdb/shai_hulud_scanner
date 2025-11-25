# Semantic Versioning Range Handling

## Problem

npm packages use semantic versioning ranges in `package.json` files, which means the **actual installed version** at build time could differ from what's specified. A package.json might specify a range like `"lodash": "^4.17.0"`, but the actual installed version could be any version that satisfies that range, including vulnerable versions like `4.17.20`.

### NPM Semver Range Examples

| Range Syntax | Meaning | Example |
|--------------|---------|---------|
| `1.2.3` | Exact version | Only `1.2.3` |
| `^1.2.3` | Compatible with 1.2.3 | `>=1.2.3 <2.0.0` |
| `~1.2.3` | Approximately 1.2.3 | `>=1.2.3 <1.3.0` |
| `>=1.2.3` | Greater than or equal | Any version `>=1.2.3` |
| `1.x` or `1.*` | Any 1.x.x version | `>=1.0.0 <2.0.0` |
| `*` | Any version | All versions |

See: https://docs.npmjs.com/cli/v11/configuring-npm/package-json#dependencies

## Solution

The scanner now uses **semantic version range matching** to correctly identify potential vulnerabilities:

### 1. Lock Files (Exact Versions)
For `package-lock.json` and `pnpm-lock.yaml`:
- These files contain **exact resolved versions**
- Scanner performs **exact version matching**
- Example: `"lodash": "4.17.20"` matches the vulnerable `lodash@4.17.20`

### 2. package.json Files (Ranges)
For `package.json`:
- These files contain **version ranges**
- Scanner checks if the vulnerable version **satisfies the range**
- Example: If searching for `lodash@4.17.20`:
  - `"lodash": "^4.17.0"` → **MATCH** (4.17.20 satisfies ^4.17.0)
  - `"lodash": "^4.17.21"` → **NO MATCH** (4.17.21+ required, safe)
  - `"lodash": "~4.17.0"` → **MATCH** (4.17.20 satisfies ~4.17.0)

## Implementation

### Core Module: `semver.py`

The `semver.py` module provides NPM-compatible semantic version range checking:

```python
from .semver import is_vulnerable_in_range

# Check if vulnerable version 4.17.20 would be installed with range ^4.17.0
is_vulnerable_in_range("4.17.20", "^4.17.0")  # Returns True

# Check if vulnerable version 4.17.20 would be installed with range ^4.17.21
is_vulnerable_in_range("4.17.20", "^4.17.21")  # Returns False (safe)
```

### Supported Range Formats

- **Exact versions**: `1.2.3`
- **Caret ranges**: `^1.2.3` (compatible versions)
- **Tilde ranges**: `~1.2.3` (patch-level changes)
- **Comparison operators**: `>=1.2.3`, `>1.2.3`, `<=1.2.3`, `<1.2.3`
- **Wildcards**: `1.x`, `1.2.x`, `*`
- **Hyphen ranges**: `1.2.3 - 2.3.4`
- **OR conditions**: `1.2.3 || 2.3.4`

### Updated Scanners

All scanner modules now use semver range matching:

1. **LocalScanner** (`local_scanner.py`):
   - Default fast mode
   - Checks cached package files
   - Uses semver ranges for package.json, exact match for lock files

2. **GitHubScanner** (`scanner.py`):
   - Legacy GitHub Code Search API mode
   - Uses semver ranges for package.json, exact match for lock files

3. **BranchScanner** (`branch_scanner.py`):
   - Branch scanning mode
   - Uses semver ranges for package.json, exact match for lock files

## Testing

Run the semver test suite:

```bash
python3 test_semver.py
```

This tests 27+ scenarios including:
- Exact version matching
- Caret range matching (`^`)
- Tilde range matching (`~`)
- Comparison operators (`>=`, `>`, `<=`, `<`)
- Wildcards (`x`, `*`)
- Real-world vulnerable package scenarios

## Examples

### Example 1: lodash Vulnerability

Vulnerable version: `lodash@4.17.20`

| package.json | Detected? | Reason |
|--------------|-----------|--------|
| `"lodash": "^4.17.0"` | ✅ Yes | Range allows 4.17.20 |
| `"lodash": "^4.17.21"` | ❌ No | Range requires >=4.17.21 (safe) |
| `"lodash": "~4.17.19"` | ✅ Yes | Range allows 4.17.20 |
| `"lodash": "4.17.20"` | ✅ Yes | Exact match |

### Example 2: event-stream Vulnerability

Vulnerable version: `event-stream@3.3.6`

| package.json | Detected? | Reason |
|--------------|-----------|--------|
| `"event-stream": "^3.3.0"` | ✅ Yes | Range allows 3.3.6 |
| `"event-stream": "^3.3.7"` | ❌ No | Range requires >=3.3.7 (safe) |
| `"event-stream": "~3.3.5"` | ✅ Yes | Range allows 3.3.6 |
| `"event-stream": "3.x"` | ✅ Yes | Wildcard allows all 3.x.x |

## Output

The scanner output distinguishes between:

1. **Exact matches** in lock files (high confidence)
2. **Range matches** in package.json (potential vulnerability)

Example output:
```
[🚨 DETECTION] lodash@4.17.20
           Repository: my-org/web-app
           File:       package.json
           URL:        https://github.com/my-org/web-app/blob/main/package.json#L15
           Note:       Range "^4.17.0" allows vulnerable version 4.17.20
```

## Recommendations

1. **Prioritize lock file matches**: These are definitive - the vulnerable version is actually installed
2. **Investigate range matches**: package.json matches indicate potential vulnerability depending on when `npm install` was last run
3. **Check package-lock.json**: Always review both package.json and package-lock.json to confirm actual installed versions
4. **Update ranges**: Change vulnerable ranges like `^4.17.0` to safe ranges like `^4.17.21`
