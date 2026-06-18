#!/usr/bin/env python3
"""
Extract IAM role ARNs with privilege escalation paths from a CloudSplaining
results JSON file (iam-results-<account>.json).

Usage:
    python3 cloudsplaining_privesc.py --input iam-results-iam-definition.json [--pretty]
"""

import argparse
import json
from collections import defaultdict

# ANSI colour codes
RED   = "\033[91m"
BOLD  = "\033[1m"
RESET = "\033[0m"


def extract_privesc(data):
    results = defaultdict(set)

    # Build role name -> ARN lookup
    role_name_to_arn = {}
    for role_key, role_data in data.get("roles", {}).items():
        arn  = role_data.get("arn")
        name = role_data.get("name")
        if name and arn:
            role_name_to_arn[name] = arn

    def process_policies(policy_section):
        for policy_key, policy_data in policy_section.items():
            if not isinstance(policy_data, dict):
                continue
            privesc = policy_data.get("PrivilegeEscalation", {})
            if not isinstance(privesc, dict):
                continue
            findings = privesc.get("findings", [])
            if not findings:
                continue

            attached_roles = policy_data.get("AttachedTo", {}).get("roles", [])
            for role_name in attached_roles:
                arn = role_name_to_arn.get(role_name)
                if not arn:
                    continue
                for finding in findings:
                    results[arn].add(finding.get("type", str(finding)))

    process_policies(data.get("inline_policies", {}))
    process_policies(data.get("customer_managed_policies", {}))

    return {arn: paths for arn, paths in results.items() if paths}


def main():
    parser = argparse.ArgumentParser(description="CloudSplaining privilege escalation extractor")
    parser.add_argument("--input",  required=True, help="Path to CloudSplaining results JSON file")
    parser.add_argument("--pretty", action="store_true", help="Enable colour output")
    args = parser.parse_args()

    try:
        with open(args.input) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading file: {e}")
        return

    results = extract_privesc(data)

    if not results:
        print("No privilege escalation findings found.")
        return

    def bold(text):
        return f"{BOLD}{text}{RESET}" if args.pretty else text

    def red(text):
        return f"{RED}{text}{RESET}" if args.pretty else text

    print()
    print(bold(f"=== IAM Roles with Privilege Escalation Paths ({len(results)} affected) ==="))
    print()

    # Group by exact combination of escalation types
    combo_map = defaultdict(set)
    for arn, paths in results.items():
        combo_key = tuple(sorted(paths))
        combo_map[combo_key].add(arn)

    for combo, arns in sorted(combo_map.items(), key=lambda x: x[0]):
        print(bold(f"[{', '.join(combo)}]"))
        for arn in sorted(arns):
            print(f"  {red(arn) if args.pretty else arn}")
        print()

    print(f"Total unique roles affected: {len(results)}")
    print()


if __name__ == "__main__":
    main()
