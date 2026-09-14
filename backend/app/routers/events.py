import hmac
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import require_analyst
from ..config import get_settings
from ..database import get_db
from ..event_service import ingest_event
from ..models import AnalystUser, SecurityEvent
from ..schemas import BatchIngestRequest, BatchIngestResponse, EventCreate, EventRead

router = APIRouter(prefix="/api/v1", tags=["events"])
settings = get_settings()


def require_ingestion_key(x_ingestion_key: str = Header(...)) -> None:
    if not hmac.compare_digest(x_ingestion_key, settings.ingestion_api_key):
        raise HTTPException(status_code=403, detail="Invalid ingestion API key")


@router.post(
    "/ingest/events",
    response_model=BatchIngestResponse,
    dependencies=[Depends(require_ingestion_key)],
)
def ingest_batch(payload: BatchIngestRequest, db: Session = Depends(get_db)) -> BatchIngestResponse:
    event_ids: list[int] = []
    alerts_created = 0
    duplicates = 0
    for event_payload in payload.events:
        event, alert, created = ingest_event(event_payload, db)
        event_ids.append(event.id)
        alerts_created += int(created and alert is not None)
        duplicates += int(not created)
    db.commit()
    return BatchIngestResponse(
        accepted=len(event_ids) - duplicates,
        duplicates=duplicates,
        alerts_created=alerts_created,
        event_ids=event_ids,
    )


@router.post("/events", response_model=EventRead)
def create_event(
    payload: EventCreate,
    _: AnalystUser = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> SecurityEvent:
    event, _, _ = ingest_event(payload, db)
    db.commit()
    db.refresh(event)
    return event


@router.get("/events", response_model=list[EventRead])
def list_events(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=100_000),
    event_type: Literal["login", "api_access", "authorization_failure", "role_change"] | None = None,
    outcome: Literal["success", "failure", "denied"] | None = None,
    user_id: str | None = None,
    _: AnalystUser = Depends(require_analyst),
    db: Session = Depends(get_db),
) -> list[SecurityEvent]:
    statement = select(SecurityEvent)
    if event_type:
        statement = statement.where(SecurityEvent.event_type == event_type)
    if outcome:
        statement = statement.where(SecurityEvent.outcome == outcome)
    if user_id:
        statement = statement.where(SecurityEvent.user_id == user_id)
    return list(
        db.scalars(statement.order_by(SecurityEvent.timestamp.desc()).offset(offset).limit(limit))
    )
