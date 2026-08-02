#!/bin/bash
# Clean up Docker resources — run monthly or when disk gets full

echo "Docker disk usage before cleanup:"
docker system df
echo ""

echo "Removing stopped containers..."
docker container prune -f

echo "Removing dangling images..."
docker image prune -f

echo "Removing unused volumes..."
docker volume prune -f

echo "Removing unused networks..."
docker network prune -f

echo ""
echo "Docker disk usage after cleanup:"
docker system df
