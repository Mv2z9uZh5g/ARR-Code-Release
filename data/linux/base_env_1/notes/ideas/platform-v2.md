# Platform v2 — Long-term Vision

Just thinking out loud here. Not a proposal yet.

## Pain points today
- Too many moving parts (Airflow, custom scripts, cron jobs)
- Poor visibility into end-to-end lineage
- Schema changes break downstream consumers silently
- No self-service for analysts — everything goes through us

## What would ideal look like?
- Single control plane for all data movement
- Schema contracts between producers and consumers
- Push-button pipeline creation for common patterns
- Built-in data quality with circuit breakers
- Real cost attribution per pipeline/team

## Inspiration
- Uber's data platform blog posts
- Netflix Maestro (their next-gen orchestrator)
- LinkedIn's datahub for discovery
- Spotify's Backstage for developer portal

## Reality check
- We're a 5-person team, not a FAANG
- Need to balance building vs. buying
- Current system works, it's just hard to extend
- Any migration has to be incremental

## Possible first steps
1. Adopt dbt for transforms (in progress)
2. Add OpenLineage to Airflow for lineage
3. Build a thin abstraction layer over pipeline creation
4. Schema registry already done — enforce contracts next

Revisit this at the Q3 planning offsite.
