import hashlib
import json
import logging
import os
import secrets
from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from config import (
    ADMIN_TOKEN,
    BLUE_TEAM_TOKEN,
    DATABASE_URL,
    RED_TEAM_TOKEN,
    SQLITE_FALLBACK_URL,
)
from models import (
    Base,
    DefensePolicy,
    ModelConfig,
    PolicyVersion,
    User,
    utc_now_iso,
)

logger = logging.getLogger("bayora.database")
logging.basicConfig(level=logging.INFO)

ACTIVE_DB_TYPE = "unknown"
ENGINE = None
SessionLocal = None


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100000,
    )
    return f"{salt}:{key.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        salt, key_hex = hashed_password.split(":", 1)
        key = hashlib.pbkdf2_hmac(
            "sha256",
            plain_password.encode("utf-8"),
            salt.encode("utf-8"),
            100000,
        )
        return secrets.compare_digest(key.hex(), key_hex)
    except Exception:
        return False


def init_engine():
    global ACTIVE_DB_TYPE, ENGINE, SessionLocal

    # Attempt PostgreSQL first
    try:
        logger.info(f"Attempting connection to primary database: {DATABASE_URL}")
        # Test connection with a short timeout
        pg_engine = create_engine(
            DATABASE_URL,
            pool_pre_ping=True,
            connect_args={"connect_timeout": 3} if "postgresql" in DATABASE_URL else {},
        )
        with pg_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        ENGINE = pg_engine
        ACTIVE_DB_TYPE = "PostgreSQL"
        logger.info("Successfully connected to primary PostgreSQL database.")
    except Exception as exc:
        logger.warning(
            f"Primary PostgreSQL unavailable ({exc}). Falling back to local resilient SQLite: {SQLITE_FALLBACK_URL}"
        )
        sqlite_engine = create_engine(
            SQLITE_FALLBACK_URL,
            connect_args={"check_same_thread": False},
        )
        ENGINE = sqlite_engine
        ACTIVE_DB_TYPE = "SQLite (Resilient Local Storage)"

    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=ENGINE)
    Base.metadata.create_all(bind=ENGINE)
    seed_initial_data()


def get_db() -> Generator[Session, None, None]:
    if SessionLocal is None:
        init_engine()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_db_status() -> dict:
    if ENGINE is None:
        init_engine()
    try:
        with ENGINE.connect() as conn:
            conn.execute(text("SELECT 1"))
            healthy = True
    except Exception as e:
        healthy = False
        return {
            "healthy": False,
            "engine": ACTIVE_DB_TYPE,
            "error": str(e),
        }

    return {
        "healthy": healthy,
        "engine": ACTIVE_DB_TYPE,
        "url_masked": DATABASE_URL.split("@")[-1] if "@" in DATABASE_URL else "local-sqlite",
    }


def seed_initial_data():
    """Seeds default accounts, models, and baseline defensive policy."""
    with SessionLocal() as db:
        # 1. Seed Users
        existing_users = {u.username: u for u in db.query(User).all()}

        default_users = [
            ("admin", "Admin@Bayora2026!", "admin"),
            ("redteam", "RedTeam@Bayora2026!", "red"),
            ("blueteam", "BlueTeam@Bayora2026!", "blue"),
        ]

        for username, password, role in default_users:
            if username not in existing_users:
                user = User(
                    username=username,
                    password_hash=hash_password(password),
                    role=role,
                    is_active=True,
                )
                db.add(user)

        # 2. Seed Model Configurations
        existing_models = {m.model_identifier: m for m in db.query(ModelConfig).all()}

        default_models = [
            ModelConfig(
                name="Bayora Mock Safety Evaluator (Deterministic)",
                provider="mock",
                model_identifier="mock-safety-eval-v1",
                endpoint_url="local://mock",
                is_active=True,
                is_approved=True,
                requires_api_key=False,
            ),
            ModelConfig(
                name="Local Llama3 Safety Model",
                provider="local",
                model_identifier="llama3",
                endpoint_url="http://localhost:11434/v1/chat/completions",
                is_active=True,
                is_approved=True,
                requires_api_key=False,
            ),
            ModelConfig(
                name="Google Gemini 2.5 Flash",
                provider="remote",
                model_identifier="gemini-2.5-flash",
                endpoint_url="https://generativelanguage.googleapis.com",
                is_active=False,
                is_approved=False,
                requires_api_key=True,
            ),
        ]

        for model in default_models:
            if model.model_identifier not in existing_models:
                db.add(model)

        # 3. Seed Baseline Blue Team Defense Policy
        existing_policy = db.query(DefensePolicy).filter_by(name="Baseline AI Defense Policy").first()
        if not existing_policy:
            policy = DefensePolicy(
                name="Baseline AI Defense Policy",
                description="Default production defense policy with input sanitization, prompt injection heuristics, and synthetic secret canary filtering.",
                is_active=True,
            )
            db.add(policy)
            db.flush()

            input_rules = {
                "max_input_length": 2000,
                "prohibited_patterns": [
                    r"(?i)ignore\s+(?:all\s+)?(?:previous|above|system)\s+instructions?",
                    r"(?i)system\s+override",
                    r"(?i)jailbreak\s*(?:mode|prompt)?",
                    r"(?i)developer\s+mode\s+activated",
                    r"(?i)bypass\s+all\s+(?:safety|ethical)\s+filters?",
                    r"(?i)you\s+are\s+now\s+in\s+DAN\s+mode",
                ],
                "prohibited_keywords": [
                    "DAN mode",
                    "override safety guidelines",
                    "jailbreak payload",
                    "unrestricted agent",
                ],
            }

            output_rules = {
                "max_output_length": 4000,
                "synthetic_secret_patterns": [
                    r"FLAG\{[A-Za-z0-9_-]+\}",
                    r"sk-test-[a-zA-Z0-9_-]{16,}",
                    r"API_KEY_[A-Z0-9_]{10,}",
                    r"SUPER_SECRET_[A-Z0-9_]+",
                    r"CANARY_SECRET_[0-9A-Fa-f]{8,}",
                ],
                "redact_replacement": "[BLOCKED: Synthetic secret exposure detected and scrubbed by Blue Team Policy Engine]",
            }

            protected_categories = [
                "PROMPT_INJECTION",
                "SYNTHETIC_CANARY_KEYS",
                "SYSTEM_PROMPT_LEAKAGE",
                "JAILBREAK_BYPASS",
            ]

            version_1 = PolicyVersion(
                policy_id=policy.id,
                version_number=1,
                is_active=True,
                input_rules=json.dumps(input_rules),
                output_rules=json.dumps(output_rules),
                protected_categories=json.dumps(protected_categories),
                notes="Initial production defense version with strict synthetic canary protection.",
            )
            db.add(version_1)

        db.commit()
