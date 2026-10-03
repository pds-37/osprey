"""End-to-End Test for the GuardianOS Flagship Demonstration Scenario."""

from guardianos.demo.scenario import run_flagship_demo


def test_flagship_demo_end_to_end():
    result = run_flagship_demo()

    assert result["status"] == "DEMO_COMPLETED_SUCCESSFULLY"
    assert result["remediation_verified"] is True
    assert result["attack_path_status"] == "CLOSED"

    timeline = result["timeline"]
    assert len(timeline) == 11

    # Step 1: Upstream fix detected
    assert timeline[0]["step"] == 1
    assert "SUSPECTED_SECURITY_CHANGE" in timeline[0]["status"]
    assert "integer conversion" in timeline[0]["signals"]

    # Step 2: Lineage mapped
    assert timeline[1]["step"] == 2
    assert timeline[1]["components_count"] >= 2

    # Step 3: Vulnerability matched
    assert timeline[2]["step"] == 3
    assert timeline[2]["vulnerability_id"] == "CVE-2023-44398"
    assert timeline[2]["fixed_version"] == "1.19.8"

    # Step 4: Patch propagation lag identified
    assert timeline[3]["step"] == 4
    assert timeline[3]["bottleneck_stage"] == "BASE_IMAGE_REBUILD"

    # Step 5: Runtime exposure
    assert timeline[4]["step"] == 5
    assert timeline[4]["network_exposure"] == "INTERNET_FACING"

    # Step 6: Attack path
    assert timeline[5]["step"] == 6
    assert timeline[5]["target_resource"] == "s3://customer-media-production"

    # Step 7: Risk
    assert timeline[6]["step"] == 7
    assert timeline[6]["risk_level"] == "CRITICAL"

    # Step 8: AI Analyst
    assert timeline[7]["step"] == 8
    assert len(timeline[7]["evidence_citations"]) >= 3

    # Step 9: Remediation generated
    assert timeline[8]["step"] == 9
    assert timeline[8]["status"] == "PENDING_APPROVAL"

    # Step 10: Approved
    assert timeline[9]["step"] == 10
    assert timeline[9]["status"] == "APPROVED"

    # Step 11: Verified & Closed
    assert timeline[10]["step"] == 11
    assert timeline[10]["attack_path_status"] == "CLOSED"
    assert "Remediation verified. Attack path CLOSED." in timeline[10]["verification_message"]
