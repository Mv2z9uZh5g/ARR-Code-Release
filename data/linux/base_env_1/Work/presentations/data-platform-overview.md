# Data Platform Architecture Overview
## All-hands presentation, March 2024

---

### Slide 1: What we do
The data engineering team builds and maintains the infrastructure that moves
data from source systems into our analytics warehouse.

Think of us as the plumbing — we make sure the right data gets to the right
place at the right time.

---

### Slide 2: The stack
- **Ingestion:** Kafka, custom connectors, Fivetran
- **Storage:** S3 (raw + processed), Redshift (analytics)
- **Orchestration:** Apache Airflow
- **Transform:** SQL + Python (evaluating dbt)
- **Serving:** Internal REST API, direct Redshift access
- **Monitoring:** Datadog → migrating to Grafana Cloud

---

### Slide 3: Scale
- ~2 TB ingested per day
- 47 active pipelines
- 12 source systems
- ~200 downstream consumers (dashboards, ML models, reports)

---

### Slide 4: What's changing in Q2
- Near-real-time clickstream processing
- Self-service analytics via data catalog
- Cost optimization (saving $10k+/month)

---

### Slide 5: How to work with us
- Data requests: #data-eng-requests in Slack
- Incidents: page via PagerDuty (auto-routes to on-call)
- Questions: #data-engineering in Slack
