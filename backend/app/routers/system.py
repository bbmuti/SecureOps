from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from ..auth import require_analyst
from ..config import get_settings
from ..database import get_db
from ..detection import ALERT_THRESHOLD, MINIMUM_PERSONAL_BASELINE, MODEL_VERSION, DetectionEngine
from ..models import Alert, AnalystUser, SecurityEvent
from ..schemas import DashboardSummary, DetectionHealth

router = APIRouter(tags=["system"])
settings = get_settings()
APP_VERSION = "0.3.0"


@router.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": settings.app_name, "version": APP_VERSION}


@router.get("/ready")
def readiness(db: Session = Depends(get_db)) -> dict:
    db.execute(text("SELECT 1"))
    return {"status": "ready", "database": "connected", "model": MODEL_VERSION}


@router.get("/api/v1/detection/health", response_model=DetectionHealth)
def detection_health(_: AnalystUser = Depends(require_analyst)) -> DetectionHealth:
    return DetectionHealth(
        model_version=MODEL_VERSION,
        alert_threshold=ALERT_THRESHOLD,
        minimum_personal_baseline=MINIMUM_PERSONAL_BASELINE,
        rules=DetectionEngine.RULES,
        integrations=["JSON/JSONL", "Linux OpenSSH auth.log", "Windows Security Event Log"],
    )


@router.get("/api/v1/dashboard/summary", response_model=DashboardSummary)
def dashboard_summary(
    _: AnalystUser = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> DashboardSummary:
    active_statuses = ("open", "investigating")
    total_events = db.scalar(select(func.count(SecurityEvent.id))) or 0
    open_alerts = db.scalar(select(func.count(Alert.id)).where(Alert.status.in_(active_statuses))) or 0
    critical_alerts = db.scalar(
        select(func.count(Alert.id)).where(
            Alert.severity == "critical", Alert.status.in_(active_statuses)
        )
    ) or 0
    average_risk = db.scalar(select(func.avg(SecurityEvent.risk_score))) or 0.0
    severity_rows = db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(Alert.status.in_(active_statuses))
        .group_by(Alert.severity)
    ).all()
    event_rows = db.execute(
        select(SecurityEvent.event_type, func.count(SecurityEvent.id)).group_by(SecurityEvent.event_type)
    ).all()
    return DashboardSummary(
        total_events=total_events,
        open_alerts=open_alerts,
        critical_alerts=critical_alerts,
        average_risk=round(float(average_risk), 1),
        severity_counts=dict(severity_rows),
        event_type_counts=dict(event_rows),
    )
