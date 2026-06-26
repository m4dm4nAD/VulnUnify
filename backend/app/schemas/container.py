"""Container scan import schemas."""
from __future__ import annotations

from pydantic import BaseModel


class ContainerImportIn(BaseModel):
    tool: str = "snyk"   # which report format to parse
    content: str         # the report file contents
