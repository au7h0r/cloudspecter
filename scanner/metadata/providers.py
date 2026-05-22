from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class MetadataProvider(Protocol):
    name: str

    @property
    def token_path(self) -> str: ...

    @property
    def token_ttl_header(self) -> str: ...

    @property
    def token_header(self) -> str: ...

    @property
    def root_path(self) -> str: ...

    @property
    def safe_paths(self) -> list[str]: ...

    def auth_headers(self, token: str) -> dict[str, str]: ...


@dataclass(frozen=True)
class AwsMetadataProvider:
    name: str = "aws"

    @property
    def token_path(self) -> str:
        return "/latest/api/token"

    @property
    def token_ttl_header(self) -> str:
        return "X-aws-ec2-metadata-token-ttl-seconds"

    @property
    def token_header(self) -> str:
        return "X-aws-ec2-metadata-token"

    @property
    def root_path(self) -> str:
        return "/latest/meta-data/"

    @property
    def safe_paths(self) -> list[str]:
        return [
            "/latest/meta-data/",
            "/latest/meta-data/iam/",
            "/latest/meta-data/iam/security-credentials/",
        ]

    def auth_headers(self, token: str) -> dict[str, str]:
        return {self.token_header: token}


@dataclass(frozen=True)
class PlaceholderMetadataProvider:
    name: str

    @property
    def token_path(self) -> str:
        return "/metadata/token"

    @property
    def token_ttl_header(self) -> str:
        return "Metadata-Token-TTL-Seconds"

    @property
    def token_header(self) -> str:
        return "Metadata-Token"

    @property
    def root_path(self) -> str:
        return "/metadata/"

    @property
    def safe_paths(self) -> list[str]:
        return ["/metadata/"]

    def auth_headers(self, token: str) -> dict[str, str]:
        return {self.token_header: token}


def get_metadata_provider(name: str) -> MetadataProvider:
    normalized = name.lower().strip()
    if normalized == "aws":
        return AwsMetadataProvider()
    if normalized in {"azure", "gcp"}:
        return PlaceholderMetadataProvider(name=normalized)
    raise ValueError(f"Unsupported metadata provider: {name}")
