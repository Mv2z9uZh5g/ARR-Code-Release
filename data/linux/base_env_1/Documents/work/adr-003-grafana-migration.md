# ADR-003: Migrate observability to Grafana Cloud

## Status
Accepted (2024-03-15)

## Context
Our Datadog bill has grown 40% quarter over quarter. We're now spending ~$18k/month
on monitoring for the data platform alone. The team is also frustrated with Datadog's
query language limitations for our use cases.

## Decision
We will migrate our observability stack to Grafana Cloud (Pro tier).

### What moves:
- Metrics (Prometheus-compatible via Mimir)
- Logs (Loki)
- Dashboards (Grafana)
- Alerting (Grafana Alerting)

### What stays on Datadog (for now):
- APM traces (Grafana Tempo evaluation in Q3)
- Infrastructure monitoring for non-K8s hosts

## Consequences
- Cost savings of approximately $8-10k/month
- Team needs to learn PromQL (most already know basics from Kubernetes)
- 2-3 sprint effort to migrate existing dashboards and alerts
- Improved flexibility for custom metrics and long-term storage

## Migration plan
1. Set up Grafana Cloud org and SSO integration
2. Deploy Grafana Agent on all EKS clusters
3. Recreate critical dashboards (top 10 by usage)
4. Migrate alert rules
5. Run in parallel for 2 weeks
6. Decommission Datadog dashboards
