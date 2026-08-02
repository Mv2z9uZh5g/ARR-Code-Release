# Sprint 15 Planning — March 5

## Capacity
- Marcus: 8 pts (out Thursday afternoon for dentist)
- Priya: 10 pts
- Jonas: 6 pts (on-call this week)
- Daniel: 8 pts

## Sprint goal
Ship the Grafana agent deployment and start migrating top dashboards.

## Stories pulled in

### Marcus
- DATA-421: Deploy Grafana Agent to staging EKS (3 pts)
- DATA-418: Fix slow dataset query (index optimization) (2 pts)
- DATA-425: Update S3 lifecycle to 90 days (1 pt)
- DATA-430: Code review backlog (2 pts)

### Priya
- DATA-412: Anomaly detection model v2 training (5 pts)
- DATA-413: Anomaly detection API endpoint (3 pts)
- DATA-429: Update alerting thresholds for Q2 (2 pts)

### Jonas
- DATA-419: Schema registry documentation (3 pts)
- DATA-424: Kafka consumer lag alert runbook (3 pts)

### Daniel
- DATA-420: Fix integration test flakiness (5 pts)
- DATA-426: Add env var validation to API startup (3 pts)

## Risks
- Grafana Agent might need custom config for our Kafka metrics
- Anomaly detection model depends on the new feature store (not yet in prod)
