-- Initial schema for the data platform API

CREATE TABLE IF NOT EXISTS pipelines (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    schedule TEXT NOT NULL,
    owner_team TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    last_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS datasets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    owner_team TEXT NOT NULL,
    source_pipeline_id TEXT REFERENCES pipelines(id),
    storage_location TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'parquet',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dataset_schemas (
    id SERIAL PRIMARY KEY,
    dataset_id TEXT NOT NULL REFERENCES datasets(id),
    version INT NOT NULL,
    columns JSONB NOT NULL,
    row_count_estimate BIGINT,
    column_count INT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(dataset_id, version)
);

CREATE TABLE IF NOT EXISTS pipeline_runs (
    id TEXT PRIMARY KEY,
    pipeline_id TEXT NOT NULL REFERENCES pipelines(id),
    status TEXT NOT NULL DEFAULT 'running',
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    metrics JSONB
);

CREATE INDEX idx_pipeline_runs_pipeline_id ON pipeline_runs(pipeline_id, started_at DESC);
CREATE INDEX idx_datasets_status ON datasets(status);
CREATE INDEX idx_dataset_schemas_version ON dataset_schemas(dataset_id, version DESC);
