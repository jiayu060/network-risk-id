"""Log normalization pipeline: parse raw logs → write normalized Parquet."""

import os
from pathlib import Path
from typing import Optional

import pyarrow as pa
import pyarrow.parquet as pq
from tqdm import tqdm

from src.parsers.parser_registry import ParserRegistry


class LogNormalizer:
    """Reads raw logs, parses them, and writes normalized Parquet files."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}

    def normalize_file(
        self,
        input_path: str,
        source_type: str,
        output_path: str,
        chunk_size: int = 100_000,
    ) -> str:
        """Normalize a single raw log file.

        Returns the path to the output Parquet file.
        """
        parser = ParserRegistry.get_parser(source_type)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        total_lines = self._count_lines(input_path)
        tables = []

        with open(input_path, "r", encoding="utf-8", errors="replace") as f:
            batch = []
            with tqdm(total=total_lines, desc=f"Parsing {os.path.basename(input_path)}") as pbar:
                for line in f:
                    line = line.strip()
                    if not line:
                        pbar.update(1)
                        continue
                    try:
                        record = parser.parse_line(line)
                        if record:
                            batch.append(record)
                    except Exception:
                        pass
                    if len(batch) >= chunk_size:
                        tables.append(pa.Table.from_pylist(batch))
                        batch = []
                    pbar.update(1)
                if batch:
                    tables.append(pa.Table.from_pylist(batch))

        if not tables:
            print(f"Warning: No valid records parsed from {input_path}")
            return output_path

        combined = pa.concat_tables(tables)
        pq.write_table(combined, output_path, compression="zstd")
        print(f"Normalized {len(combined)} records → {output_path}")
        return output_path

    def normalize_directory(
        self,
        input_dir: str,
        source_type: str,
        output_dir: str,
        pattern: str = "*.log",
    ) -> list[str]:
        """Normalize all matching log files in a directory.

        Returns list of output Parquet file paths.
        """
        input_path = Path(input_dir)
        files = sorted(input_path.glob(pattern))
        if not files:
            print(f"No files matching '{pattern}' found in {input_dir}")
            return []

        output_paths = []
        for f in files:
            rel = f.relative_to(input_path)
            out_file = os.path.join(output_dir, str(rel.with_suffix(".parquet")))
            output_paths.append(self.normalize_file(str(f), source_type, out_file))
        return output_paths

    @staticmethod
    def _count_lines(path: str) -> int:
        """Count lines efficiently on large files."""
        count = 0
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for _ in f:
                count += 1
        return count
