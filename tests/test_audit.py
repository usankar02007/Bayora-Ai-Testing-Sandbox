import json
from audit import record_audit_event, verify_audit_chain
from models import AuditEvent


def test_audit_chain_validity_on_clean_chain(client, admin_headers, db):
    # Record two valid events
    record_audit_event(db, "test_event_1", actor_role="admin", details={"action": "step1"})
    record_audit_event(db, "test_event_2", actor_role="admin", details={"action": "step2"})

    res = client.get("/api/v1/admin/audit/verify", headers={**admin_headers})
    assert res.status_code == 200
    assert res.json()["valid"] is True
    assert res.json()["events_verified"] >= 2


def test_audit_verification_detects_tampered_event(client, admin_headers, db):
    # Record event
    record_audit_event(db, "tamper_target_event", actor_role="admin", details={"value": "original"})

    # Fetch event and tamper with its details without recalculating hash
    event = db.query(AuditEvent).filter_by(event_type="tamper_target_event").first()
    assert event is not None
    event.details = json.dumps({"value": "MALICIOUSLY_MODIFIED_DATA"})
    db.commit()

    # Chain verification MUST fail!
    verification = verify_audit_chain(db)
    assert verification["valid"] is False
    assert verification["error"] == "EVENT_TAMPERED_HASH_MISMATCH"
    assert verification["failed_event_id"] == event.event_id


def test_audit_verification_detects_deleted_event(client, admin_headers, db):
    # Record three events in sequence
    e1 = record_audit_event(db, "seq_1", actor_role="admin", details={"n": 1})
    e2 = record_audit_event(db, "seq_2", actor_role="admin", details={"n": 2})
    e3 = record_audit_event(db, "seq_3", actor_role="admin", details={"n": 3})

    # Delete middle event (e2)
    db.delete(e2)
    db.commit()

    # Chain verification MUST detect break in chain!
    verification = verify_audit_chain(db)
    assert verification["valid"] is False
    assert verification["error"] == "CHAIN_BROKEN_PREVIOUS_HASH_MISMATCH"
