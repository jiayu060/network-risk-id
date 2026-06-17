"""Shared test fixtures."""

import os
import pytest

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR


@pytest.fixture
def sample_syslog_file():
    path = os.path.join(FIXTURES_DIR, "sample_syslog.txt")
    if not os.path.exists(path):
        pytest.skip(f"Fixture not found: {path}")
    return path
