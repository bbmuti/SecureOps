from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..auth import require_analyst
from ..database import get_db
from ..event_service import ingest_event
from ..models import Alert, AnalystUser, AuditLog
from ..schemas import AlertRead, AuditLogRead, StatusUpdate
from ..simulation import build_scenario

router = APIRouter(prefix="/api/v1", tags=["analyst workflow"])


@router.get("/alerts", response_model=list[AlertRead])
def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=100_000),
    status: Literal["open", "investigating", "resolved", "false_positive"] | None = None,
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    _: AnalystUser = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> list[Alert]:
    statement = select(Alert)
    if status:
        statement = statement.where(Alert.status == status)
    if severity:
        statement = statement.where(Alert.severity == severity)
    return list(db.scalars(statement.order_by(Alert.created_at.desc()).offset(offset).limit(limit)))


@router.get("/alerts/{alert_id}", response_model=AlertRead)
def get_alert(
    alert_id: int,
    _: AnalystUser = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> Alert:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/alerts/{alert_id}", response_model=AlertRead)
def update_alert(
    alert_id: int,
    payload: StatusUpdate,
    current_user: AnalystUser = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> Alert:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    old_status = alert.status
    if old_status == payload.status:
        return alert
    alert.status = payload.status
    write_audit(
        db,
        current_user.username,
        "alert_status_changed",
        "alert",
        str(alert.id),
        {"from": old_status, "to": payload.status},
    )
    db.commit()
    db.refresh(alert)
    return alert


@router.get("/audit-logs", response_model=list[AuditLogRead])
def list_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=100_000),
    _: AnalystUser = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> list[AuditLog]:
    return list(
        db.scalars(
            select(AuditLog).order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)
        )
    )


@router.post("/simulations/{scenario}")
def simulate(
    scenario: str,
    current_user: AnalystUser = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> dict:
    try:
        events = build_scenario(scenario)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    alert_count = 0
    for event_payload in events:
        _, alert, _ = ingest_event(event_payload, db)
        alert_count += int(alert is not None)
    write_audit(
        db,
        current_user.username,
        "simulation_executed",
        "scenario",
        scenario,
        {"events": len(events), "alerts": alert_count},
    )
    db.commit()
    return {"scenario": scenario, "events_created": len(events), "alerts_created": alert_count}
