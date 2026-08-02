# Notes from Data Council 2024

## Talk: "Streaming at Scale" — Confluent
- They recommend topic compaction for slowly-changing dimensions
- Interesting pattern: "outbox" table in Postgres → Debezium → Kafka
- Tiered storage available in Kafka 3.6+ (we should look into this)

## Talk: "dbt in Production" — dbt Labs
- dbt mesh for multi-team setups — this is relevant for us
- They have a new "contracts" feature for enforcing schemas between projects
- Semantic layer looks promising but still early

## Talk: "Cost Engineering for Data Platforms"
- S3 Intelligent-Tiering has zero retrieval fees now
- Savings Plans vs Reserved Instances: SP more flexible, RI cheaper
- They suggested tagging everything and running regular cost attribution reports
- Tool mentioned: Kubecost for K8s cost allocation

## People met
- Alex from Stripe — they use Flink, happy to chat about their setup
- Jordan from Plaid — also evaluating Grafana Cloud, same Datadog frustration
- Kai from Notion — interesting approach to data catalog, uses OpenLineage

## Follow-ups
- Email Alex about their Flink-on-EKS setup
- Try Kubecost in staging
- Look into OpenLineage for our catalog
