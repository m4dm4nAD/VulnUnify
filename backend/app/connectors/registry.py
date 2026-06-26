"""Connector registry.

Every connector registers here. The sync service and the API iterate over this
list, so adding a tool is: write the class, add it below. A connector can talk
REST, GraphQL, a PowerShell subprocess, or an MCP server — they all look the
same from here because they all subclass BaseConnector.
"""
from __future__ import annotations

from backend.app.connectors.base import BaseConnector
from backend.app.connectors.aikido import AikidoConnector
from backend.app.connectors.defender import DefenderForCloudConnector
from backend.app.connectors.osv import OsvConnector
from backend.app.connectors.rapid7 import Rapid7Connector
from backend.app.connectors.semgrep import SemgrepConnector
from backend.app.connectors.snyk import SnykConnector
from backend.app.connectors.sonarqube import SonarQubeConnector
from backend.app.connectors.tenable import TenableConnector
from backend.app.connectors.trend import TrendConnector
from backend.app.connectors.wiz import WizConnector

# Order is cosmetic (grouped by category for the UI).
_CONNECTOR_CLASSES: list[type[BaseConnector]] = [
    # Vulnerability scanning
    TenableConnector,
    Rapid7Connector,
    # Cloud security posture (CSPM)
    WizConnector,
    TrendConnector,
    DefenderForCloudConnector,
    # SAST
    SonarQubeConnector,
    SemgrepConnector,
    AikidoConnector,
    # Supply chain (package observation; no credentials)
    OsvConnector,
    # Container image scanning
    SnykConnector,
]


_BY_NAME: dict[str, type[BaseConnector]] = {cls.name: cls for cls in _CONNECTOR_CLASSES}


def all_connectors() -> list[BaseConnector]:
    return [cls() for cls in _CONNECTOR_CLASSES]


def get_connector(name: str) -> BaseConnector | None:
    cls = _BY_NAME.get(name)
    return cls() if cls else None
