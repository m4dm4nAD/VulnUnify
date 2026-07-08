"""Microsoft Defender for Cloud connector  (modality: PowerShell subprocess, CSPM).

Rather than calling Azure REST directly, this connector invokes `pwsh` and runs
an Az PowerShell query — demonstrating the PowerShell integration path for tools
that are easiest to reach that way. Auth uses the host's existing Az context
(`Connect-AzAccount`, a service principal, or a managed identity).

Requirements on the host running this connector:
  * PowerShell 7+ (`pwsh`)
  * Az PowerShell modules: `Install-Module Az.Accounts, Az.ResourceGraph`
  * An authenticated Az context with reader access to the subscription
"""
from __future__ import annotations

import json
import subprocess

from backend.app.connectors.base import (
    BaseConnector,
    ConfigField,
    NormalizedAsset,
    NormalizedFinding,
)
from backend.app.connectors.enums import AssetType, FindingCategory, FindingStatus
from backend.app.normalize import severity as sev

# Pulls Defender for Cloud security assessments (CSPM misconfigurations) via
# Azure Resource Graph, including the severity carried in assessment metadata.
_PWSH_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
Set-AzContext -Subscription '{subscription_id}' | Out-Null
$query = @"
securityresources
| where type == 'microsoft.security/assessments'
| where properties.status.code != 'Healthy'
| extend resourceId = tostring(properties.resourceDetails.Id)
| project
    name,
    displayName   = tostring(properties.displayName),
    statusCode    = tostring(properties.status.code),
    statusCause   = tostring(properties.status.cause),
    description   = tostring(properties.metadata.description),
    severity      = tostring(properties.metadata.severity),
    remediation   = tostring(properties.metadata.remediationDescription),
    resourceId    = resourceId
"@
$results = Search-AzGraph -Query $query -First 1000
$results | ConvertTo-Json -Depth 6 -Compress
"""

_STATUS_MAP = {
    "Unhealthy": FindingStatus.OPEN,
    "NotApplicable": FindingStatus.SUPPRESSED,
}


class DefenderForCloudConnector(BaseConnector):
    name = "defender_for_cloud"
    category = FindingCategory.CLOUD_POSTURE
    config_fields = [
        ConfigField(key="defender_subscription_id", label="Azure subscription ID"),
        ConfigField(key="defender_pwsh_path", label="pwsh path", required=False,
                    placeholder="pwsh"),
    ]

    def fetch(self) -> list[NormalizedFinding]:
        script = _PWSH_SCRIPT.format(subscription_id=self.config("defender_subscription_id"))
        pwsh = self.config("defender_pwsh_path") or "pwsh"
        proc = subprocess.run(
            [pwsh, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"Defender PowerShell query failed: {proc.stderr.strip()}")

        out = proc.stdout.strip()
        if not out:
            return []
        data = json.loads(out)
        # ConvertTo-Json emits a single object (not a list) when there's one row.
        if isinstance(data, dict):
            data = [data]
        return [self._normalize(item) for item in data]

    def _normalize(self, item: dict) -> NormalizedFinding:
        resource_id = item.get("resourceId") or "unknown-resource"
        return NormalizedFinding(
            source=self.name,
            source_finding_id=f"{item.get('name')}:{resource_id}",
            category=self.category,
            title=item.get("displayName") or "Defender for Cloud assessment",
            description=item.get("description") or item.get("statusCause"),
            severity=sev.from_label(item.get("severity")),
            raw_severity=item.get("severity"),
            status=_STATUS_MAP.get(item.get("statusCode", ""), FindingStatus.OPEN),
            asset=NormalizedAsset(
                asset_type=AssetType.CLOUD_RESOURCE,
                identifier=resource_id,
                name=resource_id.split("/")[-1] if "/" in resource_id else resource_id,
                cloud_provider="azure",
                metadata={"subscription_id": self.config("defender_subscription_id")},
            ),
            remediation=item.get("remediation"),
            location={"resource_id": resource_id},
            raw=item,
        )
