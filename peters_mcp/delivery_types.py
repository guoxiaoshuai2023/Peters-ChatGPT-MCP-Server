"""Shared contracts for explicitly enabled, original-byte package delivery."""

from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict


@dataclass(frozen=True)
class DeliveryLimits:
    max_file_bytes: int = 10 * 1024 * 1024
    max_package_bytes: int = 50 * 1024 * 1024
    max_archive_bytes: int = 64 * 1024 * 1024
    max_files: int = 100
    max_depth: int = 12
    max_compression_ratio: int = 200
    max_staging_bytes: int = 1024 * 1024 * 1024
    staging_ttl_seconds: int = 72 * 60 * 60
    preview_ttl_seconds: int = 60 * 60
    max_manifest_bytes: int = 128 * 1024


@dataclass(frozen=True)
class DeliveryTarget:
    target_id: str
    label: str
    project_id: str
    root: Path
    parent_parts: tuple[str, ...]
    repository_id: str
    root_identity: tuple[int, int]
    parent_identity: tuple[int, int]
    policy_version: str


class OpenAIFile(BaseModel):
    """Native ChatGPT file parameter; temporary URLs are never persisted or logged."""
    model_config = ConfigDict(extra="forbid")
    download_url: str
    file_id: str
    mime_type: str = ""
    file_name: str = ""
