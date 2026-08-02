#!/bin/bash
# Quick health check for local dev services

services=(
    "http://localhost:8080/health"
    "http://localhost:5432"
    "http://localhost:6379"
    "http://localhost:9092"
)

echo "=== Service Health Check ==="
echo ""

for url in "${services[@]}"; do
    if curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 "$url" | grep -q "200"; then
        echo "  ✓ $url"
    else
        echo "  ✗ $url (down or unreachable)"
    fi
done

echo ""
echo "=== Docker containers ==="
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "  Docker not running"
