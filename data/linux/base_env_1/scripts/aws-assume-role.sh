#!/bin/bash
set -euo pipefail

PROFILE="${1:-staging}"

echo "Assuming role for profile: ${PROFILE}"

# Get temporary credentials
CREDS=$(aws sts assume-role \
    --role-arn "$(aws configure get role_arn --profile "${PROFILE}")" \
    --role-session-name "cli-session-$(date +%s)" \
    --duration-seconds 3600 \
    --profile default \
    --output json)

export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r '.Credentials.SessionToken')

EXPIRY=$(echo "$CREDS" | jq -r '.Credentials.Expiration')
echo "Session active until: ${EXPIRY}"
echo ""
echo "Run: eval \$(./aws-assume-role.sh ${PROFILE})"
