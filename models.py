from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class ScanConfig:
    max_file_size: int = 1024 * 1024
    max_binary_extract_size: int = 2 * 1024 * 1024
    max_files: int = 10000
    max_total_bytes: int = 100 * 1024 * 1024
    include_raw_values: bool = False
    max_iterations: int = 3
    max_llm_calls: int = 8
    max_agent_actions: int = 32
    max_semantic_files: int = 2000
    skip_dir_names: tuple[str, ...] = (
        ".cache",
        ".git",
        "__pycache__",
        "node_modules",
        ".venv",
        "venv",
        "dist",
        "build",
    )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["skip_dir_names"] = list(self.skip_dir_names)
        return data


@dataclass
class FileRecord:
    path: str
    relative_path: str
    size: int
    is_symlink: bool = False


@dataclass
class SkippedFile:
    relative_path: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    finding_id: str
    type: str
    category: str
    relative_path: str
    line: int | None
    offset: int | None
    redacted_value: str
    raw_value: str | None
    full_value_sha256: str
    confidence: float
    source: str
    discovery_source: str
    evidence: str
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Inventory:
    files: list[FileRecord] = field(default_factory=list)
    skipped: list[SkippedFile] = field(default_factory=list)
