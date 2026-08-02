# DataCorp Internal API

REST API for the internal data platform. Handles ingestion scheduling,
pipeline status, and dataset metadata queries.

## Getting started

```bash
cp .env.example .env
docker compose up -d postgres redis
go run ./cmd/server
```

## Architecture

- `cmd/server` — main entrypoint
- `internal/handlers` — HTTP handlers
- `internal/store` — database layer (sqlc generated)
- `internal/queue` — Redis-backed job queue
- `pkg/models` — shared types

## Testing

```bash
go test ./...
```

Integration tests require a running Postgres instance:

```bash
docker compose up -d postgres
go test -tags=integration ./...
```
