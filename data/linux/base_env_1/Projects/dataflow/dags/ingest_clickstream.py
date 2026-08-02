"""Clickstream ingestion DAG — pulls from Kafka and lands in S3 raw layer."""

from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.providers.amazon.aws.hooks.s3 import S3Hook
from airflow.providers.apache.kafka.hooks.consume import KafkaConsumerHook

default_args = {
    "owner": "data-eng",
    "depends_on_past": False,
    "email_on_failure": True,
    "email": [""],
    "retries": 3,
    "retry_delay": timedelta(minutes=5),
}

dag = DAG(
    "ingest_clickstream",
    default_args=default_args,
    description="Hourly clickstream ingestion from Kafka to S3 raw layer",
    schedule_interval="@hourly",
    start_date=datetime(2024, 1, 15),
    catchup=False,
    tags=["ingestion", "clickstream"],
)


def consume_and_upload(**context):
    execution_date = context["execution_date"]
    hook = KafkaConsumerHook(
        topics=["user.clickstream.v2"],
        kafka_config_id="prod-kafka",
    )

    messages = hook.consume(num_messages=10000, timeout=60)

    s3 = S3Hook(aws_conn_id="aws_default")
    key = f"raw/clickstream/dt={execution_date.strftime('%Y-%m-%d')}/hour={execution_date.hour:02d}/batch.parquet"

    # convert messages to parquet and upload
    import pandas as pd
    import pyarrow as pa
    import pyarrow.parquet as pq
    from io import BytesIO

    records = [msg.value() for msg in messages]
    df = pd.DataFrame(records)

    buffer = BytesIO()
    table = pa.Table.from_pandas(df)
    pq.write_table(table, buffer)
    buffer.seek(0)

    s3.load_bytes(
        bytes_data=buffer.read(),
        key=key,
        bucket_name="datacorp-datalake-raw",
        replace=True,
    )

    return len(records)


ingest_task = PythonOperator(
    task_id="consume_and_upload",
    python_callable=consume_and_upload,
    dag=dag,
)
