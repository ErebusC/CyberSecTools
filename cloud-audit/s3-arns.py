#!/usr/bin/env python3
"""
Extract and deduplicate S3 bucket ARNs from ScoutSuite JSON output files,
grouped by missing control.

Usage:
    python3 s3_findings.py \
        --cleartext s3-bucket-allowing-cleartext.json \
        --no-encryption s3-bucket-no-encryption.json \
        --no-logging s3-bucket-no-logging.json \
        --no-versioning s3-bucket-no-versioning.json \
        --no-mfa-delete s3-bucket-no-mfa-delete.json
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
            arn = entry.get("BucketArn") or entry.get("arn")
            if arn and arn != "arn:aws:s3:::*":
                arns.add(arn)
        return arns
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Warning: could not load {filepath}: {e}")
        return set()


def main():
    parser = argparse.ArgumentParser(description="S3 findings ARN extractor")
    parser.add_argument("--cleartext",     help="JSON file: buckets allowing cleartext HTTP")
    parser.add_argument("--no-encryption", help="JSON file: buckets without storage encryption")
    parser.add_argument("--no-logging",    help="JSON file: buckets without access logging")
    parser.add_argument("--no-versioning", help="JSON file: buckets without versioning")
    parser.add_argument("--no-mfa-delete", help="JSON file: buckets without MFA delete")
    args = parser.parse_args()

    control_map = {
        "Cleartext HTTP permitted":      load_arns(args.cleartext),
        "Storage encryption disabled":   load_arns(args.no_encryption),
        "Access logging disabled":       load_arns(args.no_logging),
        "Versioning disabled":           load_arns(args.no_versioning),
        "MFA delete disabled":           load_arns(args.no_mfa_delete),
    }

    # Group buckets by their set of missing controls
    bucket_issues = defaultdict(set)
    for control, arns in control_map.items():
        for arn in arns:
            bucket_issues[arn].add(control)

    # Print grouped output
    print("\n=== S3 Buckets by Missing Controls ===\n")
    for control, arns in control_map.items():
        if not arns:
            continue
        print(f"[{control}]")
        for arn in sorted(arns):
            print(f"  {arn}")
        print()

    # Group buckets by their exact combination of missing controls
    combo_map = defaultdict(set)
    for arn, issues in bucket_issues.items():
        combo_key = ", ".join(sorted(issues))
        combo_map[combo_key].add(arn)

    print("=== Combined Deduplicated Bucket List (Grouped by Missing Controls) ===\n")
    for combo in sorted(combo_map.keys()):
        print(f"[{combo}]")
        for arn in sorted(combo_map[combo]):
            print(f"  {arn}")
        print()

    all_arns = set().union(*control_map.values())
    print(f"Total unique buckets affected: {len(all_arns)}")


if __name__ == "__main__":
    main()
