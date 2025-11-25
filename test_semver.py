#!/usr/bin/env python3
"""Quick test for semver range checking."""

from src.shai_hulud_scanner.semver import is_vulnerable_in_range

# Test cases: (vulnerable_version, package_range, expected_result)
test_cases = [
    # Exact version
    ("4.17.20", "4.17.20", True),
    ("4.17.20", "4.17.21", False),

    # Caret ranges (^)
    ("4.17.20", "^4.17.0", True),   # ^4.17.0 allows >=4.17.0 <5.0.0
    ("4.17.20", "^4.17.21", False), # ^4.17.21 requires >=4.17.21
    ("4.17.20", "^4.0.0", True),    # ^4.0.0 allows all 4.x.x
    ("4.17.20", "^3.0.0", False),   # ^3.0.0 only allows 3.x.x

    # Tilde ranges (~)
    ("4.17.20", "~4.17.0", True),   # ~4.17.0 allows >=4.17.0 <4.18.0
    ("4.17.20", "~4.17.21", False), # ~4.17.21 requires >=4.17.21 <4.18.0
    ("4.17.20", "~4.18.0", False),  # ~4.18.0 allows >=4.18.0 <4.19.0

    # Greater than/less than
    ("4.17.20", ">=4.17.0", True),
    ("4.17.20", ">=4.17.21", False),
    ("4.17.20", ">4.17.19", True),
    ("4.17.20", ">4.17.20", False),
    ("4.17.20", "<4.17.21", True),
    ("4.17.20", "<4.17.20", False),

    # Wildcards
    ("4.17.20", "4.x", True),
    ("4.17.20", "4.17.x", True),
    ("4.17.20", "4.18.x", False),
    ("4.17.20", "*", True),

    # Real-world example: lodash vulnerability
    ("4.17.20", "^4.17.0", True),   # VULNERABLE - range allows 4.17.20
    ("4.17.20", "^4.17.21", False), # SAFE - range requires >=4.17.21
    ("4.17.21", "^4.17.0", True),   # Safe version in vulnerable range

    # event-stream example
    ("3.3.6", "^3.3.0", True),      # VULNERABLE
    ("3.3.6", "^3.3.7", False),     # SAFE
    ("3.3.6", "~3.3.5", True),      # VULNERABLE

    # Scoped packages
    ("7.12.0", "^7.0.0", True),
    ("7.12.0", "^7.12.1", False),
]

def run_tests():
    """Run all test cases."""
    passed = 0
    failed = 0

    print("Testing semver range matching...")
    print("=" * 80)

    for vuln_ver, pkg_range, expected in test_cases:
        result = is_vulnerable_in_range(vuln_ver, pkg_range)
        status = "✓ PASS" if result == expected else "✗ FAIL"

        if result == expected:
            passed += 1
        else:
            failed += 1

        print(f"{status}: is_vulnerable_in_range('{vuln_ver}', '{pkg_range}') = {result} (expected {expected})")

    print("=" * 80)
    print(f"Results: {passed} passed, {failed} failed")

    if failed > 0:
        print("\n❌ Some tests failed!")
        return 1
    else:
        print("\n✅ All tests passed!")
        return 0

if __name__ == "__main__":
    exit(run_tests())
