-- Checking why the datasets endpoint is slow
-- Ran this on staging to see the execution plan

EXPLAIN ANALYZE
SELECT
    d.id,
    d.name,
    d.description,
    d.owner_team,
    d.created_at,
    d.updated_at,
    s.column_count,
    s.row_count_estimate
FROM datasets d
LEFT JOIN dataset_schemas s ON s.dataset_id = d.id AND s.version = (
    SELECT MAX(version) FROM dataset_schemas WHERE dataset_id = d.id
)
WHERE d.status = 'active'
ORDER BY d.updated_at DESC
LIMIT 50;

-- Result: Seq Scan on dataset_schemas is the bottleneck
-- Need an index on (dataset_id, version DESC)

-- TODO: CREATE INDEX idx_dataset_schemas_version ON dataset_schemas (dataset_id, version DESC);
