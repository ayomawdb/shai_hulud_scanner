#!/usr/bin/env python3
"""
Convert tenable.json to semgrep_list.txt format.

Input format (tenable.json):
{
    "package-name": {
        "vuln_vers": ["version1", "version2"]
    }
}

Output format (semgrep_list.txt):
package-name-version1
package-name-version2
"""

import json
import sys
from pathlib import Path


def convert_tenable_to_semgrep(input_file: str, output_file: str) -> None:
    """
    Convert tenable.json format to semgrep_list.txt format.

    Args:
        input_file: Path to the tenable.json file
        output_file: Path to the output file
    """
    # Read the tenable.json file
    with open(input_file, 'r') as f:
        tenable_data = json.load(f)

    # Convert to semgrep format
    entries = []
    for package_name, package_data in tenable_data.items():
        vuln_versions = package_data.get('vuln_vers', [])
        for version in vuln_versions:
            entries.append(f"{package_name}-{version}")

    # Sort entries alphabetically
    entries.sort()

    # Write to output file
    with open(output_file, 'w') as f:
        for entry in entries:
            f.write(f"{entry}\n")

    print(f"✓ Converted {len(tenable_data)} packages with {len(entries)} total entries")
    print(f"✓ Output written to: {output_file}")


if __name__ == "__main__":
    # Default paths
    script_dir = Path(__file__).parent
    input_file = script_dir / "lists" / "tenable.json"
    output_file = script_dir / "lists" / "tenable_semgrep_format.txt"

    # Allow command line arguments to override
    if len(sys.argv) > 1:
        input_file = Path(sys.argv[1])
    if len(sys.argv) > 2:
        output_file = Path(sys.argv[2])

    # Validate input file exists
    if not input_file.exists():
        print(f"Error: Input file not found: {input_file}", file=sys.stderr)
        sys.exit(1)

    # Convert
    try:
        convert_tenable_to_semgrep(str(input_file), str(output_file))
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
