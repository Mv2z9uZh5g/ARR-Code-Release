#!/bin/bash
set -euo pipefail

ENVIRONMENT="${1:-staging}"
IMAGE_TAG="${2:-latest}"
NAMESPACE="data-pipeline"

echo "Deploying to ${ENVIRONMENT} with image tag: ${IMAGE_TAG}"

if [[ "$ENVIRONMENT" == "production" ]]; then
    echo "Production deploy — checking approval..."
    if [[ -z "${DEPLOY_APPROVED:-}" ]]; then
        echo "ERROR: Production deploys require DEPLOY_APPROVED=1"
        exit 1
    fi
fi

kubectl config use-context "${ENVIRONMENT}-cluster"

helm upgrade --install data-api ./charts/data-api \
    --namespace "${NAMESPACE}" \
    --set image.tag="${IMAGE_TAG}" \
    --set environment="${ENVIRONMENT}" \
    --values "./charts/data-api/values-${ENVIRONMENT}.yaml" \
    --wait \
    --timeout 5m

echo "Deploy complete. Checking rollout status..."
kubectl rollout status deployment/data-api -n "${NAMESPACE}" --timeout=120s

echo "Done."
