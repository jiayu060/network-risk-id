"""Abstract base class for log parsers."""

from abc import ABC, abstractmethod
from typing import Iterator

import pyarrow as pa


class LogParser(ABC):
    """Interface that every log parser must implement."""

    @abstractmethod
    def parse_line(self, line: str) -> dict:
        """Parse a single raw log line into the unified schema dict."""

    def parse_batch(self, lines: Iterator[str]) -> pa.Table:
        """Parse a batch of lines, returning a PyArrow Table.

        Default implementation calls parse_line per line. Override for bulk-optimized parsing.
        """
        from src.core.schema import UNIFIED_LOG_SCHEMA
        records = []
        for line in lines:
            try:
                record = self.parse_line(line)
                if record:
                    records.append(record)
            except Exception:
                continue  # skip corrupt lines
        if not records:
            return pa.Table.from_pylist([], schema=UNIFIED_LOG_SCHEMA)
        return pa.Table.from_pylist(records, schema=UNIFIED_LOG_SCHEMA)
