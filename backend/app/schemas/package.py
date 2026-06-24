"""Watched-package API schemas."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class PackageImportIn(BaseModel):
    filename: str           # used to pick the parser (package-lock.json, requirements.txt, go.sum)
    content: str            # the file contents
    source: str | None = None  # label for where these deps came from (defaults to filename)


class WatchedPackageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ecosystem: str
    name: str
    version: str
    source: str
    first_seen: datetime
