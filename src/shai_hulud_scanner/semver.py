"""Semantic version range checking for npm packages."""

from __future__ import annotations

import re
from typing import Optional


def parse_version(version: str) -> Optional[tuple[int, int, int]]:
    """
    Parse a semantic version string into (major, minor, patch) tuple.
    Returns None if version cannot be parsed.

    Examples:
        "1.2.3" -> (1, 2, 3)
        "1.2" -> (1, 2, 0)
        "1" -> (1, 0, 0)
    """
    # Remove leading 'v' if present
    version = version.lstrip('v')

    # Extract version numbers (handle cases like "1.2.3-beta" or "1.2.3+build")
    match = re.match(r'^(\d+)(?:\.(\d+))?(?:\.(\d+))?', version)
    if not match:
        return None

    major = int(match.group(1))
    minor = int(match.group(2)) if match.group(2) else 0
    patch = int(match.group(3)) if match.group(3) else 0

    return (major, minor, patch)


def version_satisfies_range(version: str, range_spec: str) -> bool:
    """
    Check if a version satisfies an npm semver range.

    Supports common npm range formats:
    - Exact: "1.2.3"
    - Caret: "^1.2.3" (allows changes that do not modify left-most non-zero digit)
    - Tilde: "~1.2.3" (allows patch-level changes)
    - Greater/Less: ">=1.2.3", ">1.2.3", "<=1.2.3", "<1.2.3"
    - Wildcards: "1.x", "1.2.x", "*"
    - Hyphen ranges: "1.2.3 - 2.3.4"
    - X-ranges: "1.2.X", "1.X.X"

    Args:
        version: The version to check (e.g., "4.17.20")
        range_spec: The npm range specification (e.g., "^4.17.0")

    Returns:
        True if version satisfies the range, False otherwise
    """
    # Clean up whitespace
    range_spec = range_spec.strip()
    version = version.strip()

    # Handle wildcard/any version
    if range_spec in ('*', 'x', 'X', ''):
        return True

    # Parse the version to check
    ver = parse_version(version)
    if not ver:
        # If we can't parse the version, fall back to exact string match
        return version == range_spec

    # Handle hyphen ranges (e.g., "1.2.3 - 2.3.4")
    if ' - ' in range_spec:
        parts = range_spec.split(' - ')
        if len(parts) == 2:
            lower_ver = parse_version(parts[0])
            upper_ver = parse_version(parts[1])
            if lower_ver and upper_ver:
                return lower_ver <= ver <= upper_ver

    # Handle OR conditions (e.g., "1.2.3 || 2.3.4")
    if ' || ' in range_spec or '||' in range_spec:
        parts = re.split(r'\s*\|\|\s*', range_spec)
        return any(version_satisfies_range(version, part) for part in parts)

    # Handle AND conditions (multiple ranges separated by space)
    # e.g., ">=1.2.3 <2.0.0"
    if ' ' in range_spec and not range_spec.startswith(('>=', '>', '<=', '<', '^', '~')):
        parts = range_spec.split()
        # Check if all parts look like range operators
        if all(p[0] in '><^~' or p == version for p in parts):
            return all(version_satisfies_range(version, part) for part in parts)

    # Handle caret ranges (^)
    if range_spec.startswith('^'):
        range_ver = parse_version(range_spec[1:])
        if not range_ver:
            return False

        range_major, range_minor, range_patch = range_ver
        ver_major, ver_minor, ver_patch = ver

        # Caret allows changes that do not modify the left-most non-zero digit
        if range_major != 0:
            # ^1.2.3 := >=1.2.3 <2.0.0
            return (ver_major == range_major and
                    (ver_minor > range_minor or
                     (ver_minor == range_minor and ver_patch >= range_patch)))
        elif range_minor != 0:
            # ^0.2.3 := >=0.2.3 <0.3.0
            return (ver_major == 0 and
                    ver_minor == range_minor and
                    ver_patch >= range_patch)
        else:
            # ^0.0.3 := >=0.0.3 <0.0.4
            return ver == range_ver

    # Handle tilde ranges (~)
    if range_spec.startswith('~'):
        range_ver = parse_version(range_spec[1:])
        if not range_ver:
            return False

        range_major, range_minor, range_patch = range_ver
        ver_major, ver_minor, ver_patch = ver

        # Tilde allows patch-level changes
        # ~1.2.3 := >=1.2.3 <1.3.0
        return (ver_major == range_major and
                ver_minor == range_minor and
                ver_patch >= range_patch)

    # Handle comparison operators
    for op in ['>=', '>', '<=', '<']:
        if range_spec.startswith(op):
            range_ver = parse_version(range_spec[len(op):])
            if not range_ver:
                return False

            if op == '>=':
                return ver >= range_ver
            elif op == '>':
                return ver > range_ver
            elif op == '<=':
                return ver <= range_ver
            elif op == '<':
                return ver < range_ver

    # Handle X-ranges (1.2.x, 1.x.x, 1.2.X)
    if 'x' in range_spec.lower():
        range_spec_clean = range_spec.lower().replace('x', '0')
        range_ver = parse_version(range_spec_clean)
        if not range_ver:
            return False

        range_major, range_minor, range_patch = range_ver
        ver_major, ver_minor, ver_patch = ver

        # Count how many x's in the original spec
        parts = range_spec.lower().split('.')
        if len(parts) >= 3 and parts[2] == 'x':
            # 1.2.x := >=1.2.0 <1.3.0
            return ver_major == range_major and ver_minor == range_minor
        elif len(parts) >= 2 and parts[1] == 'x':
            # 1.x := >=1.0.0 <2.0.0
            return ver_major == range_major
        elif len(parts) >= 1 and parts[0] == 'x':
            # x := >=0.0.0 (any version)
            return True

    # Exact version match
    range_ver = parse_version(range_spec)
    if range_ver:
        return ver == range_ver

    # Fall back to exact string match
    return version == range_spec


def is_vulnerable_in_range(vulnerable_version: str, package_range: str) -> bool:
    """
    Check if a known vulnerable version would be installed given a package.json range.

    This is the main function to use when scanning package.json files.

    Args:
        vulnerable_version: The known vulnerable version (e.g., "4.17.20")
        package_range: The range from package.json (e.g., "^4.17.0", "~4.17.19")

    Returns:
        True if the vulnerable version satisfies the range (i.e., could be installed)
    """
    return version_satisfies_range(vulnerable_version, package_range)
