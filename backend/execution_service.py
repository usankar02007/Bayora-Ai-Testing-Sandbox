import json
import logging
import time
import uuid
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session

from audit import record_audit_event
from model_adapters import get_model_adapter
from models import (
    EvaluationResult,
    ModelConfig,
    PolicyVersion,
    TestCase,
    TestRun,
    utc_now_iso,
)
from policy_engine import DefensivePolicyEngine

logger = logging.getLogger("bayora.execution")


async def execute_test_case(
    db: Session,
    test_case: TestCase,
    actor_role: str,
    actor_id: str,
    override_model_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes a complete controlled adversarial test run through isolated execution,
    defense policy evaluation, model inference, and release-policy enforcement.
    """
    start_time = time.perf_counter()

    # 1. Resolve Target Model
    model_id = override_model_id or test_case.target_model_id
    model_config = db.query(ModelConfig).filter_by(id=model_id).first()
    if not model_config:
        # Fallback to mock evaluator if model not found
        model_config = db.query(ModelConfig).filter_by(provider="mock").first()

    # 2. Resolve Active Blue Team Defense Policy Version
    active_policy_version = (
        db.query(PolicyVersion)
        .filter_by(is_active=True)
        .order_by(PolicyVersion.version_number.desc())
        .first()
    )

    policy_version_id = active_policy_version.id if active_policy_version else None
    version_number = active_policy_version.version_number if active_policy_version else 0
    input_rules = active_policy_version.input_rules if active_policy_version else "{}"
    output_rules = active_policy_version.output_rules if active_policy_version else "{}"

    # 3. Create TestRun record with fresh isolated session ID
    session_id = str(uuid.uuid4())
    test_run = TestRun(
        test_case_id=test_case.id,
        policy_version_id=policy_version_id,
        model_config_id=model_config.id if model_config else "",
        session_id=session_id,
        status="running",
        started_at=utc_now_iso(),
    )
    db.add(test_run)
    db.commit()
    db.refresh(test_run)

    record_audit_event(
        db,
        event_type="test_execution_started",
        actor_role=actor_role,
        actor_id=actor_id,
        resource_id=test_run.id,
        resource_type="test_run",
        details={
            "test_case_id": test_case.id,
            "category": test_case.category,
            "model_identifier": model_config.model_identifier if model_config else "unknown",
            "policy_version_number": version_number,
            "session_id": session_id,
        },
    )

    # 4. Stage 1: Blue Team Input Filter
    input_decision = DefensivePolicyEngine.evaluate_input(
        prompt=test_case.prompt,
        policy_version_id=policy_version_id,
        version_number=version_number,
        input_rules_str=input_rules,
    )

    if input_decision.decision == "BLOCK":
        # BLOCKED AT INPUT: The model is NEVER called.
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        test_run.status = "blocked"
        test_run.completed_at = utc_now_iso()
        test_run.execution_time_ms = elapsed_ms
        test_case.status = "mitigated"
        test_case.updated_at = utc_now_iso()

        eval_result = EvaluationResult(
            test_run_id=test_run.id,
            raw_model_response=None,
            defense_decision="BLOCK",
            defense_reasons=json.dumps(input_decision.reasons),
            sanitized_model_response=input_decision.sanitized_text,
            released_to_blue=True,
            released_to_red=True,
            release_policy="sanitized_only",
        )
        db.add(eval_result)
        db.commit()

        record_audit_event(
            db,
            event_type="test_execution_blocked_input",
            actor_role=actor_role,
            actor_id=actor_id,
            resource_id=test_run.id,
            resource_type="test_run",
            details={
                "decision": "BLOCK",
                "stage": "INPUT_FILTER",
                "reasons": input_decision.reasons,
                "policy_version_number": version_number,
            },
        )

        return {
            "test_run": test_run.to_dict(),
            "evaluation_result": eval_result.to_dict(viewer_role=actor_role),
            "decision": "BLOCK",
            "stage": "INPUT_FILTER",
            "model_called": False,
        }

    # 5. Stage 2: Model Inference via Provider-Independent Adapter
    adapter = get_model_adapter(
        provider=model_config.provider if model_config else "mock",
        model_identifier=model_config.model_identifier if model_config else "mock-safety-eval-v1",
        endpoint_url=model_config.endpoint_url if model_config else None,
    )

    try:
        model_result = await adapter.generate(
            prompt=test_case.prompt,
            session_id=session_id,
            timeout_seconds=15,
        )
    except Exception as exc:
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        test_run.status = "failed"
        test_run.completed_at = utc_now_iso()
        test_run.execution_time_ms = elapsed_ms
        test_run.error_message = str(exc)
        test_case.status = "failed"
        test_case.updated_at = utc_now_iso()
        db.commit()

        record_audit_event(
            db,
            event_type="model_provider_error",
            actor_role=actor_role,
            actor_id=actor_id,
            resource_id=test_run.id,
            resource_type="test_run",
            details={"error": str(exc)},
        )

        return {
            "test_run": test_run.to_dict(),
            "evaluation_result": None,
            "decision": "ERROR",
            "error": str(exc),
            "model_called": True,
        }

    raw_output = model_result.get("content") or ""
    model_error = model_result.get("error")

    if model_error:
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)
        test_run.status = "failed"
        test_run.completed_at = utc_now_iso()
        test_run.execution_time_ms = elapsed_ms
        test_run.error_message = model_error
        test_case.status = "failed"
        db.commit()
        return {
            "test_run": test_run.to_dict(),
            "evaluation_result": None,
            "decision": "ERROR",
            "error": model_error,
            "model_called": True,
        }

    # 6. Stage 3: Blue Team Output Filter (Synthetic Secret & Canary Detection)
    output_decision = DefensivePolicyEngine.evaluate_output(
        raw_output=raw_output,
        policy_version_id=policy_version_id,
        version_number=version_number,
        output_rules_str=output_rules,
    )

    elapsed_ms = int((time.perf_counter() - start_time) * 1000)
    final_status = "mitigated" if output_decision.decision in ("BLOCK", "FLAG") else "completed"

    test_run.status = "completed"
    test_run.completed_at = utc_now_iso()
    test_run.execution_time_ms = elapsed_ms
    test_case.status = final_status
    test_case.updated_at = utc_now_iso()

    all_reasons = input_decision.reasons + output_decision.reasons

    eval_result = EvaluationResult(
        test_run_id=test_run.id,
        raw_model_response=raw_output,
        defense_decision=output_decision.decision,
        defense_reasons=json.dumps(all_reasons),
        sanitized_model_response=output_decision.sanitized_text,
        released_to_blue=True,
        released_to_red=True,
        release_policy="sanitized_only",
    )
    db.add(eval_result)
    db.commit()

    record_audit_event(
        db,
        event_type="test_execution_completed",
        actor_role=actor_role,
        actor_id=actor_id,
        resource_id=test_run.id,
        resource_type="test_run",
        details={
            "decision": output_decision.decision,
            "reasons_count": len(all_reasons),
            "execution_time_ms": elapsed_ms,
            "model_identifier": model_config.model_identifier if model_config else "unknown",
            "policy_version_number": version_number,
            "is_simulated": model_result.get("is_simulated", False),
        },
    )

    return {
        "test_run": test_run.to_dict(),
        "evaluation_result": eval_result.to_dict(viewer_role=actor_role),
        "decision": output_decision.decision,
        "stage": "OUTPUT_FILTER",
        "model_called": True,
        "is_simulated": model_result.get("is_simulated", False),
    }
