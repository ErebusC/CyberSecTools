#!/usr/bin/env python3
"""
Display IAM role findings in a table.

Usage:
    python3 iam_table.py [--pretty] \
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

# ANSI colour codes
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

COLUMNS = [
    ("assume_role_no_mfa",     "No ExtID/MFA"),
    ("inline_passrole",        "IL PassRole"),
    ("inline_notaction",       "IL NotAction"),
    ("inline_assumerole",      "IL AssumeRole"),
    ("managed_passrole",       "MG PassRole"),
    ("managed_notaction",      "MG NotAction"),
    ("managed_assumerole",     "MG AssumeRole"),
    ("managed_full_privileges","MG FullPriv"),
]


def load_arns(filepath):
    if not filepath:
        return set()
    try:
        with open(filepath) as f:
            data = json.load(f)
        return {entry["arn"] for entry in data if entry.get("arn")}
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Warning: could not load {filepath}: {e}")
        return set()


def short_name(arn):
    return arn.split("/")[-1] if "/" in arn else arn


def main():
    parser = argparse.ArgumentParser(description="IAM role findings table")
    parser.add_argument("--pretty",               action="store_true", help="Enable colour output")
    parser.add_argument("--assume-role-no-mfa",     dest="assume_role_no_mfa")
    parser.add_argument("--inline-passrole",         dest="inline_passrole")
    parser.add_argument("--inline-notaction",        dest="inline_notaction")
    parser.add_argument("--inline-assumerole",       dest="inline_assumerole")
    parser.add_argument("--managed-passrole",        dest="managed_passrole")
    parser.add_argument("--managed-notaction",       dest="managed_notaction")
    parser.add_argument("--managed-assumerole",      dest="managed_assumerole")
    parser.add_argument("--managed-full-privileges", dest="managed_full_privileges")
    args = parser.parse_args()

    control_arns = {key: load_arns(getattr(args, key)) for key, _ in COLUMNS}

    # Build per-role issue map
    role_issues = defaultdict(dict)
    all_arns = set()
    for key, _ in COLUMNS:
        for arn in control_arns[key]:
            all_arns.add(arn)
            role_issues[arn][key] = True

    if not all_arns:
        print("No affected roles found.")
        return

    # Column widths
    name_width = max(len(short_name(arn)) for arn in all_arns)
    name_width = max(name_width, 20)
    col_width  = 13

    def tick(present):
        if args.pretty:
            return f"{RED}✗{RESET}" if present else f"{GREEN}✓{RESET}"
        return "YES" if present else "---"

    def header_fmt(text):
        return f"{BOLD}{text}{RESET}" if args.pretty else text

    # Header
    header = f"{'Role':<{name_width}}"
    for _, label in COLUMNS:
        header += f"  {label:<{col_width}}"
    print()
    print(header_fmt(header))
    print("-" * (name_width + (col_width + 2) * len(COLUMNS)))

    for arn in sorted(all_arns):
        name = short_name(arn)
        row = f"{name:<{name_width}}"
        for key, _ in COLUMNS:
            present = role_issues[arn].get(key, False)
            cell = tick(present)
            # Account for invisible ANSI chars in width
            pad = col_width if not args.pretty else col_width + len(RED) + len(RESET)
            row += f"  {cell:<{pad}}"
        print(row)

    print()
    print(f"Total unique roles affected: {len(all_arns)}")
    print()


if __name__ == "__main__":
    main()
