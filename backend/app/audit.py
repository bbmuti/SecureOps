from sqlalchemy.orm import Session

from .models import AuditLog


def write_audit(
    db: Session,
    actor: str,
    action: str,
    target_type: str,
    target_id: str,
    details: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=details or {},
        )
    )
