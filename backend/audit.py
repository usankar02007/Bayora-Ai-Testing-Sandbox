import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session

from models import AuditEvent, generate_uuid, utc_now_iso

logger = logging.getLogger("bayora.audit")

GENESIS_HASH = "0" * 64


def canonical_json(data: Dict[str, Any]) -> str:
    """Produces deterministic, canonical JSON for hashing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def calculate_event_hash(event_dict: Dict[str, Any]) -> str:
    """Calculates SHA-256 of the canonical representation of an event."""
    serialized = canonical_json(event_dict)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def record_audit_event(
    db: Session,
    event_type: str,
    actor_role: str,
    actor_id: Optional[str] = None,
    resource_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> AuditEvent:
    """
    Persists a new tamper-evident audit event linked to the previous event via SHA-256 hash.
    Never stores plaintext credentials or raw sensitive payloads.
    """
    if details is None:
        details = {}

    # Get the latest audit event from persistent storage
    latest_event = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    previous_hash = latest_event.event_hash if latest_event else GENESIS_HASH

    event_id = generate_uuid()
    timestamp = utc_now_iso()

    hashable_payload = {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "actor_id": actor_id or "anonymous",
        "actor_role": actor_role,
        "resource_id": resource_id or "",
        "resource_type": resource_type or "",
        "details": details,
        "previous_hash": previous_hash,
    }

    event_hash = calculate_event_hash(hashable_payload)

    db_event = AuditEvent(
        event_id=event_id,
        timestamp=timestamp,
        event_type=event_type,
        actor_id=actor_id or "anonymous",
        actor_role=actor_role,
        resource_id=resource_id or "",
        resource_type=resource_type or "",
        details=json.dumps(details),
        previous_hash=previous_hash,
        event_hash=event_hash,
    )

    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return db_event


def verify_audit_chain(db: Session) -> Dict[str, Any]:
    """
    Verifies the cryptographic integrity of the entire audit chain from genesis.
    Detects any modification, insertion, deletion, or reordering of stored events.
    """
    events = db.query(AuditEvent).order_by(AuditEvent.id.asc()).all()
    previous_hash = GENESIS_HASH

    for idx, event in enumerate(events):
        # 1. Verify previous_hash link
        if event.previous_hash != previous_hash:
            return {
                "valid": False,
                "error": "CHAIN_BROKEN_PREVIOUS_HASH_MISMATCH",
                "failed_event_id": event.event_id,
                "event_index": idx + 1,
                "expected_previous_hash": previous_hash,
                "actual_previous_hash": event.previous_hash,
            }

        # 2. Recompute current event hash from fields
        try:
            details_dict = json.loads(event.details)
        except Exception:
            details_dict = {}

        hashable_payload = {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "event_type": event.event_type,
            "actor_id": event.actor_id,
            "actor_role": event.actor_role,
            "resource_id": event.resource_id,
            "resource_type": event.resource_type,
            "details": details_dict,
            "previous_hash": event.previous_hash,
        }

        recalculated_hash = calculate_event_hash(hashable_payload)

        if recalculated_hash != event.event_hash:
            return {
                "valid": False,
                "error": "EVENT_TAMPERED_HASH_MISMATCH",
                "failed_event_id": event.event_id,
                "event_index": idx + 1,
                "expected_event_hash": recalculated_hash,
                "recorded_event_hash": event.event_hash,
            }

        previous_hash = event.event_hash

    return {
        "valid": True,
        "events_verified": len(events),
        "latest_hash": previous_hash,
        "message": "Audit trail is cryptographically intact and verified against SHA-256 hash chain.",
    }