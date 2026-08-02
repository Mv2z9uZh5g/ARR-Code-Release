# dbt Evaluation Notes

## What is it
SQL-first transformation framework. You write SELECT statements, dbt handles
materialization (table, view, incremental), testing, and documentation.

## Why we're looking at it
- Our transform layer is a mix of raw SQL in Airflow and Python scripts
- No lineage tracking between transforms
- Documentation is manual and always out of date
- dbt gives us all of this for free

## Pros
- SQL-based (low barrier for analysts to contribute)
- Built-in testing (not null, unique, relationships, custom)
- Auto-generated docs and lineage graph
- Incremental models for large tables
- Jinja templating for DRY SQL
- Great community and package ecosystem (dbt-utils, etc.)

## Cons
- Another tool to maintain and learn
- Doesn't handle non-SQL transforms (Python models are limited)
- dbt Cloud is expensive ($100/seat/month for Team plan)
- Need to figure out how it fits with Airflow (dbt-airflow operator?)

## Decision
Start with dbt Core (open source) running inside Airflow tasks.
Evaluate dbt Cloud in Q3 if adoption grows.

## Next steps
- Set up a dbt project in the dataflow repo
- Migrate the user_events transform as a proof of concept
- Show demo to the analytics team
