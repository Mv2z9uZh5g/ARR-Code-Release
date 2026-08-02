#!/usr/bin/env python3
"""Generate test data for local development."""

import os
import json
import random
import uuid
from datetime import datetime, timedelta

import psycopg2

DB_URL = os.getenv("DB_URL")

if not DB_URL:
    raise ValueError("DB_URL environment variable is required")

TEAMS = ["data-eng", "analytics", "ml-platform", "product"]
PIPELINE_TYPES = ["ingestion", "transform", "export", "quality-check"]
FORMATS = ["parquet", "json", "csv", "avro"]


def generate_pipelines(n=10):
    pipelines = []
    for i in range(n):
        pipelines.append({
            "id": f"pipe-{i+1:03d}",
            "name": f"{random.choice(PIPELINE_TYPES)}-{random.choice(['users', 'events', 'orders', 'sessions', 'products'])}",
            "description": f"Auto-generated pipeline for testing",
            "schedule": random.choice(["@hourly", "@daily", "*/15 * * * *", "0 2 * * *"]),
            "owner_team": random.choice(TEAMS),
            "status": random.choice(["active", "active", "active", "paused"]),
        })
    return pipelines


def generate_datasets(n=15):
    datasets = []
    for i in range(n):
        datasets.append({
            "id": f"ds-{uuid.uuid4().hex[:8]}",
            "name": f"{'_'.join(random.sample(['user', 'event', 'order', 'session', 'daily', 'raw', 'agg'], 2))}",
            "owner_team": random.choice(TEAMS),
            "storage_location": f"s3://datacorp-datalake-{'raw' if random.random() > 0.5 else 'processed'}/",
            "format": random.choice(FORMATS),
            "status": "active",
        })
    return datasets


def main():
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()

    pipelines = generate_pipelines()
    for p in pipelines:
        cur.execute(
            """INSERT INTO pipelines (id, name, description, schedule, owner_team, status)
               VALUES (%(id)s, %(name)s, %(description)s, %(schedule)s, %(owner_team)s, %(status)s)
               ON CONFLICT (id) DO NOTHING""",
            p,
        )

    datasets = generate_datasets()
    for d in datasets:
        cur.execute(
            """INSERT INTO datasets (id, name, owner_team, storage_location, format, status)
               VALUES (%(id)s, %(name)s, %(owner_team)s, %(storage_location)s, %(format)s, %(status)s)
               ON CONFLICT (id) DO NOTHING""",
            d,
        )

    conn.commit()
    cur.close()
    conn.close()

    print(f"Seeded {len(pipelines)} pipelines and {len(datasets)} datasets")


if __name__ == "__main__":
    main()
