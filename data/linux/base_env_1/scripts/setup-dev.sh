#!/bin/bash
set -euo pipefail

echo "Setting up development environment..."

# Check prerequisites
command -v docker >/dev/null 2>&1 || { echo "docker required but not installed"; exit 1; }
command -v go >/dev/null 2>&1 || { echo "go required but not installed"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 required but not installed"; exit 1; }

# Start infrastructure
echo "Starting local infrastructure..."
docker compose -f ~/Projects/webapi/docker-compose.yml up -d

# Wait for postgres
echo "Waiting for Postgres..."
for i in {1..30}; do
    if pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Run migrations
echo "Running database migrations..."
cd ~/Projects/webapi
go run ./cmd/migrate up

# Install Python deps for dataflow
echo "Setting up Python environment..."
cd ~/Projects/dataflow
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]" --quiet

echo ""
echo "Dev environment ready!"
echo "  API:      http://localhost:8080"
echo "  Postgres: localhost:5432"
echo "  Redis:    localhost:6379"
