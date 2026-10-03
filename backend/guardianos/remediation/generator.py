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
    """Generate a structured remediation plan and non-destructive PR proposal."""
    target_ver = finding.fixed_version or "latest"
    task_id = f"rem-{component.name}-{uuid.uuid4().hex[:6]}"
    branch_name = f"guardianos/fix-{finding.vulnerability_id.lower()}-{component.name}"

    diff_content = (
        "--- a/Dockerfile\n"
        "+++ b/Dockerfile\n"
        "@@ -1,4 +1,4 @@\n"
        f"-FROM debian:12-slim  # running {component.name}={component.version}\n"
        f"+FROM debian:12-slim  # patched {component.name}={target_ver}\n"
        " RUN apt-get update && apt-get install -y --no-install-recommends \\\n"
        f"-    {component.name}={component.version} \\\n"
        f"+    {component.name}={target_ver} \\\n"
        "     imagemagick \\\n"
    )

    pr_body = (
        f"## GuardianOS Security Remediation Proposal\n\n"
        f"### Vulnerability Summary\n"
        f"- **Vulnerability**: `{finding.vulnerability_id}` ({finding.severity.value})\n"
        f"- **Component**: `{component.name}`\n"
        f"- **Current Installed Version**: `{component.version}`\n"
        f"- **Target Remediated Version**: `{target_ver}`\n\n"
        f"### Context & Real-world Threat\n"
        f"- An external unauthenticated entry point (`POST /upload`) connects to this component.\n"
        f"- If left unpatched, an open attack path leads to compromise of cloud storage.\n\n"
        f"### Verification Step\n"
        f"After merging and deploying this container rebuild, GuardianOS will automatically rescan the workload "
        f"and close the active attack path.\n"
    )

    pr = PullRequestProposal(
        title=f"fix(security): upgrade {component.name} from {component.version} to {target_ver} ({finding.vulnerability_id})",
        body=pr_body,
        branch_name=branch_name,
        target_file="Dockerfile",
        diff_content=diff_content
    )

    return RemediationTask(
        id=task_id,
        vulnerability_id=finding.vulnerability_id,
        component_name=component.name,
        current_version=component.version,
        target_version=target_ver,
        action_type=RemediationActionType.UPGRADE_BASE_IMAGE,
        status=RemediationStatus.PENDING_APPROVAL,
        pull_request=pr,
        associated_attack_path_id=attack_path.id if attack_path else None
    )
