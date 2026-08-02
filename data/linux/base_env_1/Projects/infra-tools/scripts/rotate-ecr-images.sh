#!/bin/bash
set -euo pipefail

REPO_NAME="${1:-data-api}"
KEEP_COUNT="${2:-20}"
REGION="us-west-2"

echo "Cleaning up old images in ECR repo: ${REPO_NAME}"
echo "Keeping the most recent ${KEEP_COUNT} images"

# Get all image tags sorted by push date
IMAGES=$(aws ecr describe-images \
    --repository-name "${REPO_NAME}" \
    --region "${REGION}" \
    --query 'sort_by(imageDetails,&imagePushedAt)[*].imageDigest' \
    --output text)

TOTAL=$(echo "$IMAGES" | wc -w)
TO_DELETE=$((TOTAL - KEEP_COUNT))

if [[ $TO_DELETE -le 0 ]]; then
    echo "Only ${TOTAL} images found, nothing to delete."
    exit 0
fi

echo "Found ${TOTAL} images, will delete ${TO_DELETE} oldest"

DELETE_DIGESTS=$(echo "$IMAGES" | tr '\t' '\n' | head -n "$TO_DELETE")

for digest in $DELETE_DIGESTS; do
    echo "  Deleting: ${digest:0:20}..."
    aws ecr batch-delete-image \
        --repository-name "${REPO_NAME}" \
        --region "${REGION}" \
        --image-ids "imageDigest=${digest}" \
        --output text > /dev/null
done

echo "Done. Deleted ${TO_DELETE} images."
