"""Importing this package registers all models on the declarative Base."""
from backend.app.models.asset import Asset
from backend.app.models.base import Base
from backend.app.models.connector_credential import ConnectorCredential
from backend.app.models.connector_run import ConnectorRun
from backend.app.models.finding import Finding
from backend.app.models.session import Session
from backend.app.models.user import User
from backend.app.models.watched_package import WatchedPackage

__all__ = [
    "Base", "Asset", "Finding", "ConnectorRun", "ConnectorCredential", "User", "Session",
    "WatchedPackage",
]
