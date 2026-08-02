# Dataflow

ETL pipeline orchestration for DataCorp's data warehouse. Uses Apache Airflow
for scheduling and monitoring.

## Pipelines

- `ingest_clickstream` — hourly ingestion from Kafka into raw layer
- `transform_user_events` — daily aggregation of user events
- `export_analytics` — nightly export to the analytics Redshift cluster
- `data_quality_checks` — runs after each transform to validate row counts and schema

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Deploying DAGs

DAGs are deployed via CI. Push to `main` and ArgoCD syncs the DAG folder
to the Airflow instance within ~3 minutes.
