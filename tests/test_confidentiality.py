def test_red_team_cannot_access_blue_policy_engine(client, red_headers):
    """Red Team must not see internal Blue Team defense rules or configuration."""
    res = client.get("/api/v1/blue/policies", headers={**red_headers})
    assert res.status_code == 403
    assert "Access denied" in res.json()["detail"]


def test_blue_team_cannot_view_unreleased_raw_red_prompt(client, red_headers, blue_headers):
    """
    CRITICAL REQUIREMENT:
    When a Red Team user submits a test payload, Blue Team must NOT see
    the raw adversarial payload before release condition is met.
    """
    # 1. Red team submits an adversarial test
    secret_prompt = "CONFIDENTIAL_PAYLOAD_TEST_VULNERABILITY_XYZ_98765"
    submit_res = client.post(
        "/api/v1/red/tests",
        headers={**red_headers},
        json={
            "test_name": "Canary Confidentiality Test",
            "category": "prompt_injection",
            "prompt": secret_prompt,
        },
    )
    assert submit_res.status_code == 201
    test_id = submit_res.json()["test"]["id"]

    # 2. Blue team queries tests list
    blue_res = client.get("/api/v1/red/tests", headers={**blue_headers})
    assert blue_res.status_code == 200

    blue_tests = blue_res.json()["tests"]
    matched = next((t for t in blue_tests if t["id"] == test_id), None)
    assert matched is not None

    # CONFIDENTIALITY VERIFICATION:
    # Raw prompt MUST be redacted/withheld from Blue Team!
    assert matched["prompt"] != secret_prompt
    assert "[CONFIDENTIAL RED TEAM PAYLOAD WITHHELD BEFORE RELEASE]" in matched["prompt"]

    # 3. Red Team queries same endpoint -> sees their own payload
    red_res = client.get("/api/v1/red/tests", headers={**red_headers})
    assert red_res.status_code == 200
    red_matched = next((t for t in red_res.json()["tests"] if t["id"] == test_id), None)
    assert red_matched is not None
    assert red_matched["prompt"] == secret_prompt


def test_cross_tenant_test_case_isolation(client, red_headers, db):
    from models import TestCase, User
    # Create another red team user in DB
    other_user = User(
        username="other_red_agent",
        password_hash="hash",
        role="red",
        is_active=True,
    )
    db.add(other_user)
    db.commit()

    # Create a private test belonging to other_red_agent
    private_test = TestCase(
        test_name="Secret Agent Private Test",
        category="prompt_injection",
        prompt="CLASSIFIED_OTHER_USER_PAYLOAD",
        target_model_id="mock",
        submitted_by=other_user.id,
        status="submitted",
    )
    db.add(private_test)
    db.commit()

    # Standard redteam user attempts to access private_test by guessing its ID
    res = client.get(f"/api/v1/red/tests/{private_test.id}", headers={**red_headers})
    # Must be 403 Forbidden!
    assert res.status_code == 403
    assert "You do not own this test case" in res.json()["detail"]


def test_released_result_redaction(client, red_headers):
    """
    Evaluation results given to Red Team must NOT disclose Blue Team's
    internal regex or policy implementation source code.
    """
    res = client.post(
        "/api/v1/red/tests",
        headers={**red_headers},
        json={
            "test_name": "Evaluation redaction check",
            "category": "prompt_injection",
            "prompt": "Hello test model",
        },
    )
    assert res.status_code == 201
    eval_res = res.json()["execution"]["evaluation_result"]

    # Must contain high-level decision and sanitized response
    assert "defense_decision" in eval_res
    assert "sanitized_model_response" in eval_res
    # Must NOT expose raw internal rule regex dictionaries or code
    assert "input_rules" not in eval_res
    assert "output_rules" not in eval_res
