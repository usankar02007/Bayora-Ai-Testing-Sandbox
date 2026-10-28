import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy.orm import Session

from audit import record_audit_event, verify_audit_chain
from config import APP_NAME, TINYFISH_API_KEY
from database import get_db, get_db_status, hash_password, init_engine
from execution_service import execute_test_case
from models import (
    AuditEvent,
    DefensePolicy,
    EvaluationResult,
    ModelConfig,
    PolicyVersion,
    TestCase,
    TestRun,
    User,
    utc_now_iso,
)
from sandbox_manager import get_sandbox_status, run_sandbox_smoke_test
from security import AuthContext, authenticate, require_roles, verify_test_ownership
from tinyfish_client import run_tinyfish_agent

logger = logging.getLogger("bayora.main")
logging.basicConfig(level=logging.INFO)

# Initialize Database on module load
init_engine()

app = FastAPI(
    title=APP_NAME,
    description="Bayora - Securing Adversarial AI Safety Testing Infrastructure",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Pydantic Request / Response Schemas
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class RedTestCreateRequest(BaseModel):
    test_name: str = Field(min_length=1, max_length=150)
    category: str = Field(
        default="prompt_injection",
        description="prompt_injection, jailbreak_bypass, secret_disclosure, unauthorized_tool_use, output_policy_violation",
    )
    prompt: str = Field(min_length=1, max_length=4000)
    target_model_id: Optional[str] = None
    idempotency_key: Optional[str] = None


class BluePolicyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    description: Optional[str] = None


class BluePolicyVersionCreateRequest(BaseModel):
    input_rules: Dict[str, Any] = Field(default_factory=dict)
    output_rules: Dict[str, Any] = Field(default_factory=dict)
    protected_categories: List[str] = Field(default_factory=list)
    notes: Optional[str] = None
    activate_now: bool = True


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=100)
    role: str = Field(description="'red', 'blue', or 'admin'")


class TinyFishAgentRequest(BaseModel):
    url: str
    goal: str = Field(min_length=1, max_length=1000)


# ---------------------------------------------------------------------------
# Public Health & Discovery Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
def home():
    return {
        "project": "Bayora",
        "status": "operational",
        "version": "1.0.0",
        "docs_url": "/docs",
        "message": "Bayora AI Safety Platform backend is running.",
    }


@app.get("/health")
@app.get("/api/v1/health")
def health(db: Session = Depends(get_db)):
    db_status = get_db_status()
    sandbox = get_sandbox_status()
    return {
        "status": "healthy" if db_status.get("healthy") else "degraded",
        "database": db_status,
        "sandbox": sandbox,
        "tinyfish_configured": bool(TINYFISH_API_KEY),
    }


# ---------------------------------------------------------------------------
# Authentication Endpoints
# ---------------------------------------------------------------------------

@app.get("/team/me")
@app.get("/api/v1/auth/me")
def get_current_identity(auth: AuthContext = Depends(authenticate)):
    return {
        "authenticated": True,
        "user_id": auth.user_id,
        "username": auth.username,
        "role": auth.role,
        "auth_method": auth.auth_method,
    }


@app.post("/api/v1/auth/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    from database import verify_password
    user = db.query(User).filter_by(username=request.username).first()
    if not user or not verify_password(request.password, user.password_hash):
        record_audit_event(
            db,
            event_type="authentication_failure",
            actor_role="anonymous",
            details={"attempted_username": request.username},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled. Contact an administrator.",
        )

    record_audit_event(
        db,
        event_type="authentication_success",
        actor_role=user.role,
        actor_id=user.id,
        details={"username": user.username},
    )

    return {
        "authenticated": True,
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
        "token": user.username,  # User token
    }


# ---------------------------------------------------------------------------
# Aggregated Dashboard Summary
# ---------------------------------------------------------------------------

@app.get("/api/v1/dashboard/summary")
@app.get("/workspace/data")
def dashboard_summary(
    auth: AuthContext = Depends(require_roles("red", "blue", "admin")),
    db: Session = Depends(get_db),
):
    total_tests = db.query(TestCase).count()
    completed_tests = db.query(TestCase).filter_by(status="completed").count()
    mitigated_tests = db.query(TestCase).filter_by(status="mitigated").count()
    failed_tests = db.query(TestCase).filter_by(status="failed").count()

    active_policy = db.query(DefensePolicy).filter_by(is_active=True).first()
    active_version = (
        db.query(PolicyVersion)
        .filter_by(is_active=True)
        .order_by(PolicyVersion.version_number.desc())
        .first()
    )

    models = db.query(ModelConfig).all()
    audit_count = db.query(AuditEvent).count()

    # Recent activity according to role confidentiality
    if auth.role == "red":
        user_tests = (
            db.query(TestCase)
            .filter_by(submitted_by=auth.user_id)
            .order_by(TestCase.created_at.desc())
            .limit(10)
            .all()
        )
        recent_tests = [t.to_dict(is_red_or_admin=True) for t in user_tests]
    else:
        all_tests = (
            db.query(TestCase)
            .order_by(TestCase.created_at.desc())
            .limit(10)
            .all()
        )
        # Blue Team gets sanitized view without unreleased raw prompts!
        recent_tests = [
            t.to_dict(is_red_or_admin=(auth.role == "admin")) for t in all_tests
        ]

    response = {
        "viewer_role": auth.role,
        "summary": {
            "total_tests": total_tests,
            "completed": completed_tests,
            "mitigated": mitigated_tests,
            "failed": failed_tests,
            "active_policy_name": active_policy.name if active_policy else "None",
            "active_policy_version": active_version.version_number if active_version else None,
            "models_available": len(models),
            "audit_events_count": audit_count,
        },
        "recent_tests": recent_tests,
    }

    if auth.role == "admin":
        response["audit_integrity"] = verify_audit_chain(db)

    return response


# ---------------------------------------------------------------------------
# Red Team Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/v1/red/tests", status_code=201)
@app.post("/tests/red", status_code=201)
async def submit_red_test(
    request: RedTestCreateRequest,
    auth: AuthContext = Depends(require_roles("red", "admin")),
    db: Session = Depends(get_db),
):
    # Check Idempotency Key to prevent duplicate submissions
    if request.idempotency_key:
        existing = db.query(TestCase).filter_by(idempotency_key=request.idempotency_key).first()
        if existing:
            return {
                "message": "Duplicate submission detected via idempotency key.",
                "test": existing.to_dict(is_red_or_admin=True),
                "is_duplicate": True,
            }

    # Resolve Target Model
    model = None
    if request.target_model_id:
        model = db.query(ModelConfig).filter_by(id=request.target_model_id).first()
    if not model:
        model = db.query(ModelConfig).filter_by(provider="mock").first()

    test_case = TestCase(
        test_name=request.test_name.strip(),
        category=request.category,
        prompt=request.prompt,
        target_model_id=model.id if model else "",
        submitted_by=auth.user_id,
        status="submitted",
        idempotency_key=request.idempotency_key,
    )
    db.add(test_case)
    db.commit()
    db.refresh(test_case)

    record_audit_event(
        db,
        event_type="red_test_submitted",
        actor_role=auth.role,
        actor_id=auth.user_id,
        resource_id=test_case.id,
        resource_type="test_case",
        details={
            "test_name": test_case.test_name,
            "category": test_case.category,
            "prompt_length": len(test_case.prompt),
            "model_id": test_case.target_model_id,
        },
    )

    # Immediately execute through controlled execution lifecycle
    execution_result = await execute_test_case(
        db=db,
        test_case=test_case,
        actor_role=auth.role,
        actor_id=auth.user_id,
    )

    db.refresh(test_case)

    return {
        "message": "Adversarial test case submitted and evaluated.",
        "test": test_case.to_dict(is_red_or_admin=True),
        "execution": execution_result,
    }


@app.get("/api/v1/red/tests")
@app.get("/tests")
def list_red_tests(
    auth: AuthContext = Depends(require_roles("red", "blue", "admin")),
    db: Session = Depends(get_db),
):
    """
    CRITICAL CONFIDENTIALITY:
    - Red Team ONLY sees tests submitted by themselves!
    - Blue Team sees metadata for defensive evaluation, NOT raw unreleased prompts!
    - Admin has oversight.
    """
    query = db.query(TestCase).order_by(TestCase.created_at.desc())

    if auth.role == "red":
        query = query.filter(TestCase.submitted_by == auth.user_id)

    tests = query.all()
    is_admin = auth.role == "admin"
    is_red = auth.role == "red"

    return {
        "viewer_role": auth.role,
        "count": len(tests),
        "tests": [t.to_dict(is_red_or_admin=(is_admin or is_red)) for t in tests],
    }


@app.get("/api/v1/red/tests/{test_id}")
def get_red_test_details(
    test_id: str,
    auth: AuthContext = Depends(require_roles("red", "blue", "admin")),
    db: Session = Depends(get_db),
):
    test_case = db.query(TestCase).filter_by(id=test_id).first()
    if not test_case:
        raise HTTPException(status_code=404, detail="Test case not found.")

    verify_test_ownership(test_case, auth)

    runs = db.query(TestRun).filter_by(test_case_id=test_case.id).all()
    runs_data = []
    for r in runs:
        r_dict = r.to_dict()
        if r.evaluation_result:
            r_dict["evaluation_result"] = r.evaluation_result.to_dict(viewer_role=auth.role)
        runs_data.append(r_dict)

    is_red_or_admin = (auth.role == "admin") or (auth.role == "red" and test_case.submitted_by == auth.user_id)
    return {
        "test": test_case.to_dict(is_red_or_admin=is_red_or_admin),
        "runs": runs_data,
    }


@app.post("/api/v1/tests/{test_id}/execute")
async def execute_existing_test(
    test_id: str,
    auth: AuthContext = Depends(require_roles("red", "admin")),
    db: Session = Depends(get_db),
):
    test_case = db.query(TestCase).filter_by(id=test_id).first()
    if not test_case:
        raise HTTPException(status_code=404, detail="Test case not found.")

    verify_test_ownership(test_case, auth)

    result = await execute_test_case(
        db=db,
        test_case=test_case,
        actor_role=auth.role,
        actor_id=auth.user_id,
    )

    return {
        "message": "Test execution completed.",
        "result": result,
    }


# ---------------------------------------------------------------------------
# Blue Team Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/v1/blue/tasks")
def list_blue_defensive_tasks(
    auth: AuthContext = Depends(require_roles("blue", "admin")),
    db: Session = Depends(get_db),
):
    """
    Blue Team views safety tasks to defend against.
    NEVER displays confidential Red Team unreleased raw payloads!
    """
    tests = db.query(TestCase).order_by(TestCase.created_at.desc()).all()
    sanitized_tasks = []

    for t in tests:
        latest_run = (
            db.query(TestRun)
            .filter_by(test_case_id=t.id)
            .order_by(TestRun.started_at.desc())
            .first()
        )
        task_info = {
            "test_id": t.id,
            "test_name": t.test_name,
            "category": t.category,
            "status": t.status,
            "created_at": t.created_at,
            "latest_run_id": latest_run.id if latest_run else None,
            "latest_decision": latest_run.evaluation_result.defense_decision if latest_run and latest_run.evaluation_result else "PENDING",
            "sanitized_preview": "[Red Team payload sanitized for defensive task definition]",
        }
        sanitized_tasks.append(task_info)

    return {
        "count": len(sanitized_tasks),
        "tasks": sanitized_tasks,
    }


@app.get("/api/v1/blue/policies")
def list_blue_policies(
    auth: AuthContext = Depends(require_roles("blue", "admin")),
    db: Session = Depends(get_db),
):
    policies = db.query(DefensePolicy).all()
    return {
        "count": len(policies),
        "policies": [p.to_dict(include_versions=True) for p in policies],
    }


@app.post("/api/v1/blue/policies", status_code=201)
def create_blue_policy(
    request: BluePolicyCreateRequest,
    auth: AuthContext = Depends(require_roles("blue", "admin")),
    db: Session = Depends(get_db),
):
    policy = DefensePolicy(
        name=request.name.strip(),
        description=request.description,
        created_by=auth.user_id,
        is_active=True,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)

    record_audit_event(
        db,
        event_type="blue_policy_created",
        actor_role=auth.role,
        actor_id=auth.user_id,
        resource_id=policy.id,
        resource_type="defense_policy",
        details={"name": policy.name},
    )

    return {
        "message": "Defense policy created.",
        "policy": policy.to_dict(),
    }


@app.post("/api/v1/blue/policies/{policy_id}/versions", status_code=201)
def create_policy_version(
    policy_id: str,
    request: BluePolicyVersionCreateRequest,
    auth: AuthContext = Depends(require_roles("blue", "admin")),
    db: Session = Depends(get_db),
):
    policy = db.query(DefensePolicy).filter_by(id=policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Defense policy not found.")

    latest_ver = (
        db.query(PolicyVersion)
        .filter_by(policy_id=policy_id)
        .order_by(PolicyVersion.version_number.desc())
        .first()
    )
    next_ver_number = (latest_ver.version_number + 1) if latest_ver else 1

    if request.activate_now:
        # Deactivate previous versions
        db.query(PolicyVersion).filter_by(is_active=True).update({"is_active": False})

    new_version = PolicyVersion(
        policy_id=policy.id,
        version_number=next_ver_number,
        is_active=request.activate_now,
        input_rules=json.dumps(request.input_rules),
        output_rules=json.dumps(request.output_rules),
        protected_categories=json.dumps(request.protected_categories),
        notes=request.notes,
        created_by=auth.user_id,
    )
    db.add(new_version)
    policy.updated_at = utc_now_iso()
    db.commit()
    db.refresh(new_version)

    record_audit_event(
        db,
        event_type="blue_policy_version_created",
        actor_role=auth.role,
        actor_id=auth.user_id,
        resource_id=new_version.id,
        resource_type="policy_version",
        details={
            "policy_id": policy.id,
            "version_number": next_ver_number,
            "activated": request.activate_now,
        },
    )

    return {
        "message": f"Policy version {next_ver_number} published successfully.",
        "version": new_version.to_dict(confidential=True),
    }


@app.post("/api/v1/blue/policies/{policy_id}/versions/{version_id}/activate")
def activate_policy_version(
    policy_id: str,
    version_id: str,
    auth: AuthContext = Depends(require_roles("blue", "admin")),
    db: Session = Depends(get_db),
):
    version = db.query(PolicyVersion).filter_by(id=version_id, policy_id=policy_id).first()
    if not version:
        raise HTTPException(status_code=404, detail="Policy version not found.")

    # Deactivate all others
    db.query(PolicyVersion).filter_by(is_active=True).update({"is_active": False})
    version.is_active = True
    db.commit()

    record_audit_event(
        db,
        event_type="blue_policy_version_activated",
        actor_role=auth.role,
        actor_id=auth.user_id,
        resource_id=version.id,
        resource_type="policy_version",
        details={"version_number": version.version_number},
    )

    return {
        "message": f"Version {version.version_number} is now active.",
        "version": version.to_dict(confidential=True),
    }


@app.get("/api/v1/blue/effectiveness")
def get_defense_effectiveness(
    auth: AuthContext = Depends(require_roles("blue", "admin")),
    db: Session = Depends(get_db),
):
    total_evals = db.query(EvaluationResult).count()
    blocked = db.query(EvaluationResult).filter_by(defense_decision="BLOCK").count()
    allowed = db.query(EvaluationResult).filter_by(defense_decision="ALLOW").count()
    flagged = db.query(EvaluationResult).filter_by(defense_decision="FLAG").count()

    categories_stats = {}
    test_cases = db.query(TestCase).all()
    for tc in test_cases:
        cat = tc.category
        if cat not in categories_stats:
            categories_stats[cat] = {"total": 0, "mitigated": 0}
        categories_stats[cat]["total"] += 1
        if tc.status == "mitigated":
            categories_stats[cat]["mitigated"] += 1

    return {
        "total_evaluations": total_evals,
        "blocked": blocked,
        "allowed": allowed,
        "flagged": flagged,
        "block_rate_percentage": round((blocked / total_evals * 100), 1) if total_evals else 0.0,
        "category_breakdown": categories_stats,
    }


# Backward compatibility for legacy blue notes
class LegacyBlueDefenseRequest(BaseModel):
    test_id: Optional[str] = None
    test_name: str
    defense_notes: str


@app.post("/tests/blue", status_code=201)
def submit_legacy_blue_defense(
    request: LegacyBlueDefenseRequest,
    auth: AuthContext = Depends(require_roles("blue", "admin")),
    db: Session = Depends(get_db),
):
    record_audit_event(
        db,
        event_type="blue_defense_notes_recorded",
        actor_role=auth.role,
        actor_id=auth.user_id,
        details={"test_name": request.test_name, "notes_len": len(request.defense_notes)},
    )
    return {
        "message": "Defense notes recorded successfully.",
        "defense": {
            "test_name": request.test_name,
            "defense_notes": request.defense_notes,
            "submitted_by": auth.role,
            "created_at": utc_now_iso(),
        },
    }


@app.get("/tests/defenses")
def get_legacy_defenses(
    auth: AuthContext = Depends(require_roles("red", "blue", "admin")),
    db: Session = Depends(get_db),
):
    policies = db.query(DefensePolicy).all()
    return {
        "viewer_role": auth.role,
        "count": len(policies),
        "defenses": [p.to_dict(include_versions=(auth.role != "red")) for p in policies],
    }


# ---------------------------------------------------------------------------
# Admin Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/v1/admin/users")
def list_users(
    auth: AuthContext = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
):
    users = db.query(User).all()
    return {"users": [u.to_dict() for u in users]}


@app.post("/api/v1/admin/users", status_code=201)
def create_user(
    request: UserCreateRequest,
    auth: AuthContext = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
):
    if request.role not in ("red", "blue", "admin"):
        raise HTTPException(status_code=400, detail="Invalid role. Must be 'red', 'blue', or 'admin'.")

    existing = db.query(User).filter_by(username=request.username).first()
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists.")

    user = User(
        username=request.username,
        password_hash=hash_password(request.password),
        role=request.role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    record_audit_event(
        db,
        event_type="admin_user_created",
        actor_role=auth.role,
        actor_id=auth.user_id,
        resource_id=user.id,
        resource_type="user",
        details={"username": user.username, "role": user.role},
    )

    return {"message": "User created successfully.", "user": user.to_dict()}


@app.patch("/api/v1/admin/users/{user_id}/status")
def toggle_user_status(
    user_id: str,
    active: bool,
    auth: AuthContext = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    user.is_active = active
    db.commit()

    record_audit_event(
        db,
        event_type="admin_user_status_changed",
        actor_role=auth.role,
        actor_id=auth.user_id,
        resource_id=user.id,
        resource_type="user",
        details={"username": user.username, "active": active},
    )

    return {"message": f"User status updated to {active}.", "user": user.to_dict()}


@app.get("/api/v1/admin/models")
def list_models(
    auth: AuthContext = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
):
    models = db.query(ModelConfig).all()
    return {"models": [m.to_dict() for m in models]}


@app.get("/api/v1/admin/audit/events")
@app.get("/audit/events")
def list_audit_events(
    auth: AuthContext = Depends(require_roles("admin")),
    limit: int = 100,
    db: Session = Depends(get_db),
):
    events = (
        db.query(AuditEvent)
        .order_by(AuditEvent.id.desc())
        .limit(limit)
        .all()
    )
    return {"count": len(events), "events": [e.to_dict() for e in reversed(events)]}


@app.get("/api/v1/admin/audit/verify")
@app.get("/audit/verify")
def verify_audit_trail(
    auth: AuthContext = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
):
    result = verify_audit_chain(db)
    record_audit_event(
        db,
        event_type="audit_chain_verification_run",
        actor_role=auth.role,
        actor_id=auth.user_id,
        details={"result": result["valid"], "events_verified": result.get("events_verified", 0)},
    )
    return result


@app.get("/api/v1/admin/sandbox/status")
@app.get("/sandbox/status")
def get_sandbox(
    auth: AuthContext = Depends(require_roles("admin")),
):
    return get_sandbox_status()


@app.post("/api/v1/admin/sandbox/smoke-test")
@app.post("/sandbox/smoke-test")
def run_sandbox_smoke(
    auth: AuthContext = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
):
    result = run_sandbox_smoke_test()
    record_audit_event(
        db,
        event_type="sandbox_smoke_test",
        actor_role=auth.role,
        actor_id=auth.user_id,
        details={"success": result["success"], "isolation_verified": result.get("isolation_verified", False)},
    )
    return result


@app.get("/api/v1/admin/agent/status")
@app.get("/agent/status")
def get_agent_status(
    auth: AuthContext = Depends(require_roles("admin")),
):
    return {
        "provider": "TinyFish",
        "api_key_configured": bool(TINYFISH_API_KEY),
        "ssrf_protection_active": True,
    }


@app.post("/api/v1/admin/agent/run")
@app.post("/agent/run")
async def run_agent(
    request: TinyFishAgentRequest,
    auth: AuthContext = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
):
    try:
        result = await run_tinyfish_agent(request.url, request.goal)
        record_audit_event(
            db,
            event_type="tinyfish_agent_executed",
            actor_role=auth.role,
            actor_id=auth.user_id,
            details={"url": request.url},
        )
        return result
    except ValueError as ve:
        record_audit_event(
            db,
            event_type="tinyfish_ssrf_blocked",
            actor_role=auth.role,
            actor_id=auth.user_id,
            details={"url": request.url, "error": str(ve)},
        )
        raise HTTPException(status_code=400, detail=str(ve)) from ve
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"TinyFish request failed: {str(exc)}") from exc