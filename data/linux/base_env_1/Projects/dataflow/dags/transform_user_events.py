"""Daily aggregation of user events into the analytics layer."""

from datetime import datetime, timedelta

from airflow import DAG
from airflow.providers.common.sql.operators.sql import SQLExecuteQueryOperator

default_args = {
    "owner": "data-eng",
    "depends_on_past": True,
    "email_on_failure": True,
    "email": [""],
    "retries": 2,
    "retry_delay": timedelta(minutes=10),
}

dag = DAG(
    "transform_user_events",
    default_args=default_args,
    description="Daily user event aggregation",
    schedule_interval="@daily",
    start_date=datetime(2024, 1, 1),
    catchup=False,
    tags=["transform", "analytics"],
)

aggregate_events = SQLExecuteQueryOperator(
    task_id="aggregate_daily_events",
    conn_id="redshift_default",
    sql="""
        INSERT INTO analytics.daily_user_events (
            event_date,
            user_id,
            page_views,
            clicks,
            session_duration_sec,
            unique_pages
        )
        SELECT
            DATE(event_timestamp) as event_date,
            user_id,
            COUNT(*) FILTER (WHERE event_type = 'page_view') as page_views,
            COUNT(*) FILTER (WHERE event_type = 'click') as clicks,
            EXTRACT(EPOCH FROM MAX(event_timestamp) - MIN(event_timestamp)) as session_duration_sec,
            COUNT(DISTINCT page_url) as unique_pages
        FROM raw.clickstream
        WHERE DATE(event_timestamp) = '{{ ds }}'
        GROUP BY 1, 2
        ON CONFLICT (event_date, user_id) DO UPDATE SET
            page_views = EXCLUDED.page_views,
            clicks = EXCLUDED.clicks,
            session_duration_sec = EXCLUDED.session_duration_sec,
            unique_pages = EXCLUDED.unique_pages;
    """,
    dag=dag,
)

update_user_metrics = SQLExecuteQueryOperator(
    task_id="update_user_lifetime_metrics",
    conn_id="redshift_default",
    sql="""
        INSERT INTO analytics.user_lifetime_metrics (
            user_id,
            total_page_views,
            total_clicks,
            total_sessions,
            first_seen,
            last_seen
        )
        SELECT
            user_id,
            SUM(page_views),
            SUM(clicks),
            COUNT(DISTINCT event_date),
            MIN(event_date),
            MAX(event_date)
        FROM analytics.daily_user_events
        GROUP BY user_id
        ON CONFLICT (user_id) DO UPDATE SET
            total_page_views = EXCLUDED.total_page_views,
            total_clicks = EXCLUDED.total_clicks,
            total_sessions = EXCLUDED.total_sessions,
            last_seen = EXCLUDED.last_seen;
    """,
    dag=dag,
)

aggregate_events >> update_user_metrics
