# Platform Sync — March 12

**Attendees:** Marcus, Priya, Jonas, Sarah K.

## Updates

- Kafka cluster upgrade to 3.7 is done. No issues during the rolling restart.
- Jonas finished the schema registry migration over the weekend, all producers
  now validate against the new schemas.
- Priya's team is still working on the real-time anomaly detection pipeline.
  ETA pushed to end of March.

## Discussion

- We need to decide on the observability stack for the new pipelines. Options:
  1. Stick with Datadog (expensive but everyone knows it)
  2. Move to Grafana Cloud (cheaper, more customizable)
  3. Self-host Grafana + Mimir + Loki (cheapest long term, most effort)

  Decision: going with option 2 for now. Sarah will get the contract sorted.

- Data retention policy: legal wants us to keep raw clickstream for 90 days
  instead of 30. Marcus to update the lifecycle rules on S3.

## Action items

- [ ] Marcus: update S3 lifecycle rules to 90 days
- [ ] Jonas: document the schema registry migration
- [ ] Priya: share updated timeline for anomaly detection
- [ ] Sarah: Grafana Cloud contract by EOW
