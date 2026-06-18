#!/usr/bin/env python3
"""
Extract and deduplicate IAM role ARNs from ScoutSuite IAM finding JSON files,
grouped by issue type.

Usage:
    python3 iam_findings.py \
        --assume-role-no-mfa iam-assume-role-lacks-external-id-and-mfa.json \
        --inline-passrole iam-inline-role-policy-allows-iam-PassRole.json \
        --inline-notaction iam-inline-role-policy-allows-NotActions.json \
        --inline-assumerole iam-inline-role-policy-allows-sts-AssumeRole.json \
        --managed-passrole iam-managed-policy-allows-iam-PassRole.json \
        --managed-notaction iam-managed-policy-allows-NotActions.json \
        --managed-assumerole iam-managed-policy-allows-sts-AssumeRole.json \
        --managed-full-privileges iam-managed-policy-allows-full-privileges.json
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
    parser = argparse.ArgumentParser(description="IAM role findings ARN extractor")
    parser.add_argument("--assume-role-no-mfa",     help="JSON: cross-account AssumeRole lacks External ID and MFA")
    parser.add_argument("--inline-passrole",         help="JSON: inline policy allows iam:PassRole for all resources")
    parser.add_argument("--inline-notaction",        help="JSON: inline policy allows NotActions")
    parser.add_argument("--inline-assumerole",       help="JSON: inline policy allows sts:AssumeRole for all resources")
    parser.add_argument("--managed-passrole",        help="JSON: managed policy allows iam:PassRole for all resources")
    parser.add_argument("--managed-notaction",       help="JSON: managed policy allows NotActions")
    parser.add_argument("--managed-assumerole",      help="JSON: managed policy allows sts:AssumeRole for all resources")
    parser.add_argument("--managed-full-privileges", help="JSON: managed policy allows all actions")
    args = parser.parse_args()

    control_map = {
        "Cross-account AssumeRole lacks External ID and MFA": load_arns(args.assume_role_no_mfa),
        "Inline policy allows iam:PassRole for all resources": load_arns(args.inline_passrole),
        "Inline policy allows NotActions":                     load_arns(args.inline_notaction),
        "Inline policy allows sts:AssumeRole for all resources": load_arns(args.inline_assumerole),
        "Managed policy allows iam:PassRole for all resources": load_arns(args.managed_passrole),
        "Managed policy allows NotActions":                    load_arns(args.managed_notaction),
        "Managed policy allows sts:AssumeRole for all resources": load_arns(args.managed_assumerole),
        "Managed policy allows all actions":                   load_arns(args.managed_full_privileges),
    }

    # Map each ARN to its set of issues
    arn_issues = defaultdict(set)
    for control, arns in control_map.items():
        for arn in arns:
            arn_issues[arn].add(control)

    # Per-control output
    print("\n=== IAM Roles by Individual Finding ===\n")
    for control, arns in control_map.items():
        if not arns:
            continue
        print(f"[{control}]")
        for arn in sorted(arns):
            print(f"  {arn}")
        print()

    # Group by exact combination of issues
    combo_map = defaultdict(set)
    for arn, issues in arn_issues.items():
        combo_key = ", ".join(sorted(issues))
        combo_map[combo_key].add(arn)

    print("=== Deduplicated List Grouped by Issue Combination ===\n")
    for combo in sorted(combo_map.keys()):
        print(f"[{combo}]")
        for arn in sorted(combo_map[combo]):
            print(f"  {arn}")
        print()

    all_arns = set().union(*control_map.values())
    print(f"Total unique IAM roles affected: {len(all_arns)}")


if __name__ == "__main__":
    main()
