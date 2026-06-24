"""ConnectorCredential: an encrypted, UI-managed override for a connector setting.

One row per (connector, key). The stored `value` is Fernet-encrypted. When
present, it overrides the corresponding environment/.env value at resolve time.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.models.base import Base


class ConnectorCredential(Base):
    __tablename__ = "connector_credentials"
    __table_args__ = (UniqueConstraint("connector", "key", name="uq_connector_key"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    connector: Mapped[str] = mapped_column(String(64), index=True)
    key: Mapped[str] = mapped_column(String(128))
    value: Mapped[str] = mapped_column(Text)  # Fernet-encrypted
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
