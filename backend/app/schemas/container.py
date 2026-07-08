"""Container scan import schemas."""
from __future__ import annotations

from pydantic import BaseModel, Field

# Upper bound on uploaded file contents (matches the 32 MB request-body cap and
# enforces it even for chunked bodies that omit Content-Length).
MAX_CONTENT_LEN = 32 * 1024 * 1024


class ContainerImportIn(BaseModel):
    tool: str = Field("snyk", max_length=64)          # which report format to parse
    content: str = Field(max_length=MAX_CONTENT_LEN)  # the report file contents
