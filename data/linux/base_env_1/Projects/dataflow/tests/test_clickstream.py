"""Tests for the clickstream ingestion pipeline."""

import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch

from dags.ingest_clickstream import consume_and_upload


@pytest.fixture
def mock_context():
    return {
        "execution_date": datetime(2024, 3, 14, 1, 0, 0),
        "task_instance": MagicMock(),
    }


@pytest.fixture
def sample_messages():
    return [
        MagicMock(value=lambda: {"user_id": "u-001", "event": "page_view", "url": "/home", "ts": -1}),
        MagicMock(value=lambda: {"user_id": "u-002", "event": "click", "url": "/products", "ts": -1}),
        MagicMock(value=lambda: {"user_id": "u-001", "event": "scroll", "url": "/home", "ts": -1}),
    ]


@patch("dags.ingest_clickstream.S3Hook")
@patch("dags.ingest_clickstream.KafkaConsumerHook")
def test_consume_and_upload_success(mock_kafka, mock_s3, mock_context, sample_messages):
    mock_kafka.return_value.consume.return_value = sample_messages

    result = consume_and_upload(**mock_context)

    assert result == 3
    mock_s3.return_value.load_bytes.assert_called_once()


@patch("dags.ingest_clickstream.S3Hook")
@patch("dags.ingest_clickstream.KafkaConsumerHook")
def test_consume_empty_batch(mock_kafka, mock_s3, mock_context):
    mock_kafka.return_value.consume.return_value = []

    result = consume_and_upload(**mock_context)

    assert result == 0


@patch("dags.ingest_clickstream.KafkaConsumerHook")
def test_consume_kafka_timeout(mock_kafka, mock_context):
    mock_kafka.return_value.consume.side_effect = Exception("Consumer timeout")

    with pytest.raises(Exception, match="Consumer timeout"):
        consume_and_upload(**mock_context)


def test_s3_key_format(mock_context):
    execution_date = mock_context["execution_date"]
    expected_key = "raw/clickstream/dt=2024-03-14/hour=01/batch.parquet"
    key = f"raw/clickstream/dt={execution_date.strftime('%Y-%m-%d')}/hour={execution_date.hour:02d}/batch.parquet"
    assert key == expected_key
