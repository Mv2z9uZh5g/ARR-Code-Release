#!/bin/bash
# Quick k8s debugging helper

NAMESPACE="${1:-data-pipeline}"

echo "=== Pod Status ==="
kubectl get pods -n "$NAMESPACE" --sort-by='.status.startTime'
echo ""

echo "=== Recent Events ==="
kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' | tail -20
echo ""

echo "=== Resource Usage ==="
kubectl top pods -n "$NAMESPACE" 2>/dev/null || echo "  (metrics-server not available)"
echo ""

echo "=== Pods not Running ==="
kubectl get pods -n "$NAMESPACE" --field-selector=status.phase!=Running 2>/dev/null
echo ""

# Check for OOMKilled containers
echo "=== OOMKilled (last 24h) ==="
kubectl get pods -n "$NAMESPACE" -o json | \
    jq -r '.items[] | select(.status.containerStatuses[]?.lastState.terminated.reason == "OOMKilled") | .metadata.name'
