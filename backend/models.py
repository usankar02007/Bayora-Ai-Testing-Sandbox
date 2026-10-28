import json
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    Column,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def generate_uuid() -> str:
    return str(uuid.uuid4())


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(20), nullable=False)  # 'red', 'blue', 'admin'
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(String(64), default=utc_now_iso, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at,
        }


class ModelConfig(Base):
    __tablename__ = "model_configs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False)
    provider = Column(String(50), nullable=False)  # 'mock', 'local', 'remote'
    model_identifier = Column(String(100), nullable=False)
    endpoint_url = Column(String(500), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_approved = Column(Boolean, default=True, nullable=False)
    requires_api_key = Column(Boolean, default=False, nullable=False)
    created_at = Column(String(64), default=utc_now_iso, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "provider": self.provider,
            "model_identifier": self.model_identifier,
            "endpoint_url": self.endpoint_url,
            "is_active": self.is_active,
            "is_approved": self.is_approved,
            "requires_api_key": self.requires_api_key,
            "created_at": self.created_at,
        }


class DefensePolicy(Base):
    __tablename__ = "defense_policies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_by = Column(String(36), nullable=True)
    created_at = Column(String(64), default=utc_now_iso, nullable=False)
    updated_at = Column(String(64), default=utc_now_iso, nullable=False)

    versions = relationship(
        "PolicyVersion",
        back_populates="policy",
        cascade="all, delete-orphan",
        order_by="desc(PolicyVersion.version_number)",
    )

    def to_dict(self, include_versions=False):
        data = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "is_active": self.is_active,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
        if include_versions:
            data["versions"] = [v.to_dict() for v in self.versions]
        return data


class PolicyVersion(Base):
    __tablename__ = "policy_versions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    policy_id = Column(String(36), ForeignKey("defense_policies.id"), nullable=False)
    version_number = Column(Integer, nullable=False)
    is_active = Column(Boolean, default=False, nullable=False)
    input_rules = Column(Text, nullable=False, default="{}")
    output_rules = Column(Text, nullable=False, default="{}")
    protected_categories = Column(Text, nullable=False, default="[]")
    notes = Column(Text, nullable=True)
    created_by = Column(String(36), nullable=True)
    created_at = Column(String(64), default=utc_now_iso, nullable=False)

    policy = relationship("DefensePolicy", back_populates="versions")

    def to_dict(self, confidential: bool = False):
        data = {
            "id": self.id,
            "policy_id": self.policy_id,
            "version_number": self.version_number,
            "is_active": self.is_active,
            "notes": self.notes,
            "created_by": self.created_by,
            "created_at": self.created_at,
        }
        if confidential:
            try:
                data["input_rules"] = json.loads(self.input_rules)
            except Exception:
                data["input_rules"] = {}
            try:
                data["output_rules"] = json.loads(self.output_rules)
            except Exception:
                data["output_rules"] = {}
            try:
                data["protected_categories"] = json.loads(self.protected_categories)
            except Exception:
                data["protected_categories"] = []
        return data


class TestCase(Base):
    __tablename__ = "test_cases"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    test_name = Column(String(150), nullable=False)
    category = Column(String(50), nullable=False)
    # CONFIDENTIAL Red Team payload!
    prompt = Column(Text, nullable=False)
    target_model_id = Column(String(36), ForeignKey("model_configs.id"), nullable=False)
    submitted_by = Column(String(36), nullable=False)
    status = Column(String(30), default="submitted", nullable=False)
    idempotency_key = Column(String(100), nullable=True, index=True)
    created_at = Column(String(64), default=utc_now_iso, nullable=False)
    updated_at = Column(String(64), default=utc_now_iso, nullable=False)

    runs = relationship("TestRun", back_populates="test_case", cascade="all, delete-orphan")

    def to_dict(self, is_red_or_admin: bool = False):
        data = {
            "id": self.id,
            "test_name": self.test_name,
            "category": self.category,
            "target_model_id": self.target_model_id,
            "submitted_by": self.submitted_by,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
        # CRITICAL CONFIDENTIALITY: Raw prompt only visible to Red Team author/Admin!
        if is_red_or_admin:
            data["prompt"] = self.prompt
        else:
            data["prompt"] = "[CONFIDENTIAL RED TEAM PAYLOAD WITHHELD BEFORE RELEASE]"
        return data


class TestRun(Base):
    __tablename__ = "test_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    test_case_id = Column(String(36), ForeignKey("test_cases.id"), nullable=False)
    policy_version_id = Column(String(36), ForeignKey("policy_versions.id"), nullable=True)
    model_config_id = Column(String(36), ForeignKey("model_configs.id"), nullable=False)
    session_id = Column(String(36), default=generate_uuid, nullable=False)
    status = Column(String(30), default="running", nullable=False)
    started_at = Column(String(64), default=utc_now_iso, nullable=False)
    completed_at = Column(String(64), nullable=True)
    execution_time_ms = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)

    test_case = relationship("TestCase", back_populates="runs")
    evaluation_result = relationship("EvaluationResult", back_populates="test_run", uselist=False, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "test_case_id": self.test_case_id,
            "policy_version_id": self.policy_version_id,
            "model_config_id": self.model_config_id,
            "session_id": self.session_id,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "execution_time_ms": self.execution_time_ms,
            "error_message": self.error_message,
        }


class EvaluationResult(Base):
    __tablename__ = "evaluation_results"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    test_run_id = Column(String(36), ForeignKey("test_runs.id"), nullable=False)
    # Raw output from model (confidential before release)
    raw_model_response = Column(Text, nullable=True)
    defense_decision = Column(String(20), nullable=False)  # 'ALLOW', 'BLOCK', 'FLAG'
    defense_reasons = Column(Text, nullable=False, default="[]")
    sanitized_model_response = Column(Text, nullable=True)
    released_to_blue = Column(Boolean, default=False, nullable=False)
    released_to_red = Column(Boolean, default=True, nullable=False)
    release_policy = Column(String(30), default="sanitized_only", nullable=False)
    created_at = Column(String(64), default=utc_now_iso, nullable=False)

    test_run = relationship("TestRun", back_populates="evaluation_result")

    def to_dict(self, viewer_role: str = "red"):
        try:
            reasons = json.loads(self.defense_reasons)
        except Exception:
            reasons = []

        data = {
            "id": self.id,
            "test_run_id": self.test_run_id,
            "defense_decision": self.defense_decision,
            "defense_reasons": reasons,
            "release_policy": self.release_policy,
            "created_at": self.created_at,
        }

        # Release logic:
        # If Admin: sees everything
        if viewer_role == "admin":
            data["raw_model_response"] = self.raw_model_response
            data["sanitized_model_response"] = self.sanitized_model_response
            data["released_to_blue"] = self.released_to_blue
            data["released_to_red"] = self.released_to_red
            return data

        # If Blue Team:
        if viewer_role == "blue":
            if not self.released_to_blue:
                data["status"] = "WITHHELD_BEFORE_RELEASE"
                data["sanitized_model_response"] = "[EVALUATION RESULT NOT YET RELEASED TO BLUE TEAM]"
            else:
                data["sanitized_model_response"] = self.sanitized_model_response
                if self.release_policy == "full_evidence":
                    data["raw_model_response"] = self.raw_model_response
            return data

        # If Red Team:
        if viewer_role == "red":
            if not self.released_to_red:
                data["status"] = "PENDING_RELEASE"
                data["sanitized_model_response"] = "[EVALUATION UNDER PROCESS]"
            else:
                data["sanitized_model_response"] = self.sanitized_model_response
            # Confidential defense implementation internal logic is NOT given to Red Team
            return data

        return data


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(36), unique=True, nullable=False, default=generate_uuid)
    timestamp = Column(String(64), nullable=False, default=utc_now_iso)
    event_type = Column(String(80), nullable=False)
    actor_id = Column(String(100), nullable=True)
    actor_role = Column(String(20), nullable=False)
    resource_id = Column(String(100), nullable=True)
    resource_type = Column(String(50), nullable=True)
    details = Column(Text, nullable=False, default="{}")
    previous_hash = Column(String(64), nullable=False)
    event_hash = Column(String(64), nullable=False)

    def to_dict(self):
        try:
            parsed_details = json.loads(self.details)
        except Exception:
            parsed_details = {}

        return {
            "id": self.id,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "actor_id": self.actor_id,
            "actor_role": self.actor_role,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "details": parsed_details,
            "previous_hash": self.previous_hash,
            "event_hash": self.event_hash,
        }
