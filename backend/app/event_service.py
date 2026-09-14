from datetime import UTC, datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .audit import write_audit
from .detection import ALERT_THRESHOLD, MODEL_VERSION, UNATTRIBUTABLE_IPS, DetectionEngine
from .models import Alert, SecurityEvent
from .schemas import EventCreate

detection_engine = DetectionEngine()


def utc_aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def ingest_event(payload: EventCreate, db: Session) -> tuple[SecurityEvent, Alert | None, bool]:
    timestamp = payload.timestamp or datetime.now(UTC)
    if timestamp > datetime.now(UTC) + timedelta(minutes=5):
        raise HTTPException(status_code=422, detail="Event timestamp cannot be more than five minutes in the future")
    if payload.source_event_id:
        duplicate = db.scalar(
            select(SecurityEvent).where(
                SecurityEvent.source == payload.source,
                SecurityEvent.source_event_id == payload.source_event_id,
            )
        )
        if duplicate:
            return duplicate, duplicate.alert, False

    window_start = timestamp - timedelta(minutes=10)
    recent_by_user = list(
        db.scalars(
            select(SecurityEvent)
            .where(
                SecurityEvent.timestamp >= window_start,
                SecurityEvent.timestamp <= timestamp,
                SecurityEvent.user_id == payload.user_id,
            )
            .order_by(SecurityEvent.timestamp.desc())
            .limit(1_000)
        )
    )
    recent_by_ip = []
    if str(payload.ip_address) not in UNATTRIBUTABLE_IPS:
        recent_by_ip = list(
            db.scalars(
                select(SecurityEvent)
                .where(
                    SecurityEvent.timestamp >= window_start,
                    SecurityEvent.timestamp <= timestamp,
                    SecurityEvent.ip_address == str(payload.ip_address),
                )
                .order_by(SecurityEvent.timestamp.desc())
                .limit(1_000)
            )
        )
    recent = sorted(
        {event.id: event for event in recent_by_user + recent_by_ip}.values(),
        key=lambda event: utc_aware(event.timestamp),
        reverse=True,
    )
    baseline = list(
        db.scalars(
            select(SecurityEvent)
            .where(
                SecurityEvent.user_id == payload.user_id,
                SecurityEvent.outcome == "success",
                SecurityEvent.timestamp < timestamp,
            )
            .order_by(SecurityEvent.timestamp.desc())
            .limit(500)
        )
    )
    event = SecurityEvent(
        timestamp=timestamp,
        user_id=payload.user_id,
        event_type=payload.event_type,
        outcome=payload.outcome,
        ip_address=str(payload.ip_address),
        country=payload.country.upper(),
        endpoint=payload.endpoint,
        role=payload.role,
        source=payload.source,
        source_event_id=payload.source_event_id,
        details=payload.details,
        model_version=MODEL_VERSION,
    )
    result = detection_engine.analyze(event, recent, baseline)
    event.risk_score = result.risk_score
    event.anomaly_score = result.anomaly_score
    alert = None
    try:
        with db.begin_nested():
            db.add(event)
            db.flush()
            if result.risk_score >= ALERT_THRESHOLD:
                alert = Alert(
                    event_id=event.id,
                    title=result.title,
                    severity=result.severity,
                    risk_score=result.risk_score,
                    mitre_technique=result.mitre_technique,
                    explanation=result.explanation,
                    evidence=result.evidence,
                )
                db.add(alert)
                db.flush()
                write_audit(
                    db,
                    "detection-engine",
                    "alert_created",
                    "alert",
                    str(alert.id),
                    {"rules": result.triggered_rules, "model_version": result.model_version},
                )
    except IntegrityError:
        if payload.source_event_id:
            duplicate = db.scalar(
                select(SecurityEvent).where(
                    SecurityEvent.source == payload.source,
                    SecurityEvent.source_event_id == payload.source_event_id,
                )
            )
            if duplicate:
                return duplicate, duplicate.alert, False
        raise
    return event, alert, True
