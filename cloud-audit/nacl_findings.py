#!/usr/bin/env python3
"""
Extract and deduplicate VPC ARNs from ScoutSuite NACL finding JSON files,
grouped by issue type.

Usage:
    python3 nacl_findings.py \
        --default-egress vpc-default-network-acls-allow-all-egress.json \
        --default-ingress vpc-default-network-acls-allow-all-ingress.json \
        --subnet-egress vpc-subnet-with-allow-all-egress-acls.json \
        --subnet-ingress vpc-subnet-with-allow-all-ingress-acls.json
"""

import argparse
import json
from collections import defaultdict


def load_arns(filepath):
    if not filepath:
        return set()
    try:
        with open(filepath) as f:
            data = json.load(f)
        arns = set()
        for entry in data:
            arn = entry.get("arn")
            if arn:
                arns.add(arn)
        return arns
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Warning: could not load {filepath}: {e}")
        return set()


def main():
    parser = argparse.ArgumentParser(description="NACL findings ARN extractor")
    parser.add_argument("--default-egress",  help="JSON file: default NACLs allow all egress")
    parser.add_argument("--default-ingress", help="JSON file: default NACLs allow all ingress")
    parser.add_argument("--subnet-egress",   help="JSON file: subnets with allow-all egress NACLs")
    parser.add_argument("--subnet-ingress",  help="JSON file: subnets with allow-all ingress NACLs")
    args = parser.parse_args()

    control_map = {
        "Default NACL allows all egress":   load_arns(args.default_egress),
        "Default NACL allows all ingress":  load_arns(args.default_ingress),
        "Subnet allow-all egress NACL":     load_arns(args.subnet_egress),
        "Subnet allow-all ingress NACL":    load_arns(args.subnet_ingress),
    }

    # Map each ARN to its set of issues
    arn_issues = defaultdict(set)
    for control, arns in control_map.items():
        for arn in arns:
            arn_issues[arn].add(control)

    # Group by exact combination of issues
    combo_map = defaultdict(set)
    for arn, issues in arn_issues.items():
        combo_key = ", ".join(sorted(issues))
        combo_map[combo_key].add(arn)

    # Per-control output
    print("\n=== VPCs/Subnets by Individual Finding ===\n")
    for control, arns in control_map.items():
        if not arns:
            continue
        print(f"[{control}]")
        for arn in sorted(arns):
            print(f"  {arn}")
        print()

    # Deduplicated grouped output
    print("=== Deduplicated List Grouped by Issue Combination ===\n")
    for combo in sorted(combo_map.keys()):
        print(f"[{combo}]")
        for arn in sorted(combo_map[combo]):
            print(f"  {arn}")
        print()

    all_arns = set().union(*control_map.values())
    print(f"Total unique VPCs/subnets affected: {len(all_arns)}")


if __name__ == "__main__":
    main()
