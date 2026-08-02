"""Shared test fixtures for the dataflow test suite."""

import pytest
from datetime import datetime
from unittest.mock import MagicMock


@pytest.fixture
def airflow_context():
    """Standard Airflow task context for testing."""
    return {
        "execution_date": datetime(2024, 3, 14, 0, 0, 0),
        "ds": "2024-03-14",
        "ds_nodash": "20240314",
        "task_instance": MagicMock(),
        "dag_run": MagicMock(),
    }


@pytest.fixture
def sample_clickstream_records():
    """Sample clickstream records for testing."""
    return [
        {
            "user_id": "u-001",
            "event_type": "page_view",
            "page_url": "/home",
            "timestamp": "2024-03-14T00:01:23Z",
            "session_id": "sess-abc123",
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        },
        {
            "user_id": "u-001",
            "event_type": "click",
            "page_url": "/home",
            "timestamp": "2024-03-14T00:01:45Z",
            "session_id": "sess-abc123",
            "element_id": "cta-signup",
        },
        {
            "user_id": "u-002",
            "event_type": "page_view",
            "page_url": "/pricing",
            "timestamp": "2024-03-14T00:02:01Z",
            "session_id": "sess-def456",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        },
    ]


@pytest.fixture
def mock_s3_hook():
    """Mocked S3Hook for testing without AWS access."""
    hook = MagicMock()
    hook.load_bytes = MagicMock(return_value=None)
    hook.check_for_key = MagicMock(return_value=False)
    return hook
