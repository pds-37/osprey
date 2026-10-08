"""Remediation plan and Pull Request proposal generator."""

import uuid
from typing import Optional
from guardianos.attackpath.models import AttackPath
from guardianos.intel.models import VulnerabilityFinding
from guardianos.inventory.models import Component
from guardianos.remediation.models import (
    PullRequestProposal,
    RemediationActionType,
    RemediationStatus,
    RemediationTask,
)


def generate_remediation_task(
    finding: VulnerabilityFinding,
    component: Component,
    attack_path: Optional[AttackPath] = None
) -> RemediationTask:
    """Generate a version recommendation; no repository files or pull requests are created."""
    # A missing advisory fixed boundary is explicitly unknown. Never turn it
    # into an invented registry target such as "latest".
    target_ver = finding.fixed_version or "UNKNOWN"
    task_id = f"rem-{component.observation_id}-{finding.vulnerability_id.lower().replace(':', '-')}"

    target_text = (
        f"- **Target Remediated Version**: `{target_ver}`\n\n"
        if finding.fixed_version
        else "- **Target Remediated Version**: `UNKNOWN` (advisory has no supported fixed version)\n\n"
    )
    pr_body = (
        f"## Osprey Remediation Recommendation\n\n"
        f"This is a recommendation only. Osprey did not edit a repository, create a branch, or open a pull request.\n\n"
        f"### Vulnerability Summary\n"
        f"- **Vulnerability**: `{finding.vulnerability_id}` ({finding.severity.value})\n"
        f"- **Component**: `{component.name}`\n"
        f"- **Observed Component Version**: `{component.version}`\n"
        f"{target_text}"
        f"### Recommended action\n"
        f"Update the manifest, lockfile, or image build that supplies this component, then submit a fresh inventory observation. "
        f"The input artifact does not identify a repository file or package-manager edit location.\n"
    )

    pr = PullRequestProposal(
        title=(f"Upgrade {component.name} from {component.version} to {target_ver}"
               if finding.fixed_version else f"Review remediation for {component.name}"),
        body=pr_body,
        branch_name=None,
        target_file=None,
        diff_content=None
    )

    return RemediationTask(
        id=task_id,
        vulnerability_id=finding.vulnerability_id,
        component_name=component.name,
        current_version=component.version,
        target_version=target_ver,
        action_type=RemediationActionType.UPGRADE_PACKAGE,
        status=RemediationStatus.PENDING_APPROVAL,
        pull_request=pr,
        associated_attack_path_id=attack_path.id if attack_path else None,
        fixture=bool(attack_path and attack_path.fixture),
    )
