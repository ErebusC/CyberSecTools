#!/bin/bash
# S3 bucket configuration weakness checker
# Usage: ./s3_check.sh [profile] [region]

PROFILE=${1:-default}
REGION=${2:-eu-west-2}

printf "%-70s %-12s %-10s %-12s %-12s %-12s\n" "Bucket" "Encryption" "Logging" "Versioning" "MFA Delete" "HTTPS Only"
printf "%-70s %-12s %-10s %-12s %-12s %-12s\n" "------" "----------" "-------" "----------" "----------" "----------"

for bucket in $(aws s3api list-buckets --profile "$PROFILE" --query 'Buckets[*].Name' --output text); do
    # Encryption
    encryption=$(aws s3api get-bucket-encryption --bucket "$bucket" --profile "$PROFILE" 2>/dev/null | jq -r '.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm // "DISABLED"')

    # Logging
    logging=$(aws s3api get-bucket-logging --bucket "$bucket" --profile "$PROFILE" 2>/dev/null | jq -r 'if .LoggingEnabled then "ENABLED" else "DISABLED" end')

    # Versioning and MFA Delete
    versioning_output=$(aws s3api get-bucket-versioning --bucket "$bucket" --profile "$PROFILE" 2>/dev/null)
    versioning=$(echo "$versioning_output" | jq -r '.Status // "DISABLED"')
    mfa_delete=$(echo "$versioning_output" | jq -r '.MFADelete // "DISABLED"')

    # HTTPS only (check bucket policy for deny HTTP)
    policy=$(aws s3api get-bucket-policy --bucket "$bucket" --profile "$PROFILE" 2>/dev/null | jq -r '.Policy' | jq -r '[.Statement[] | select(.Condition.Bool."aws:SecureTransport" == "false")] | if length > 0 then "ENFORCED" else "NOT ENFORCED" end' 2>/dev/null || echo "NOT ENFORCED")

    printf "%-70s %-12s %-10s %-12s %-12s %-12s\n" "$bucket" "$encryption" "$logging" "$versioning" "$mfa_delete" "$policy"
done
