# Architecture Review — January 18

Topic: Data Catalog API design

## Context
Product wants a self-service data catalog. Users should be able to:
- Browse available datasets
- See column-level schema information
- Understand data freshness and quality scores
- Request access to new datasets

## Decisions
- Build as a new set of endpoints on the existing internal API (not a separate service)
- Schema info stored in PostgreSQL, not fetched live from the warehouse
- A background job syncs schema changes from the warehouse nightly
- Access requests go through an approval workflow in the API, notifications via Slack

## Open questions
- How do we handle dataset ownership transitions when people leave?
- Should we expose quality scores in the catalog or keep them internal?
- Integration with dbt docs — should the catalog pull from dbt metadata?

## Next steps
- Marcus: prototype the schema sync job
- Priya: draft the data model for the catalog
- Sarah: check with product on the access request requirements
