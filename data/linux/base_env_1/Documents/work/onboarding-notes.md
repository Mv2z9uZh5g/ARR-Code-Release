# Onboarding Notes (for new hires)

## Access you'll need
- GitHub org: datacorp-engineering
- AWS SSO: request via IT ticket (usually takes 1 business day)
- Kubernetes: ask your lead to add you to the RBAC config
- Datadog: self-service through Okta
- Confluence: data-engineering space

## Important repos
- `datacorp/internal-api` — the main API service
- `datacorp/dataflow` — ETL pipelines (Airflow DAGs)
- `datacorp/infra` — Terraform and Helm charts
- `datacorp/schema-registry` — Avro schemas for Kafka topics

## Local dev setup
Run `~/scripts/setup-dev.sh` after cloning the repos.

## Team norms
- PRs need 1 approval, 2 for anything touching prod config
- We deploy to staging automatically on merge to main
- Prod deploys happen Tuesday and Thursday afternoons
- On-call rotation is weekly, check PagerDuty for schedule
- Daily standup at 9:15 AM Pacific (optional on Fridays)

## Useful links
- Runbooks: Confluence > Data Engineering > Runbooks
- Architecture diagrams: Confluence > Data Engineering > Architecture
- Monitoring: Datadog dashboard "Data Platform Overview"
