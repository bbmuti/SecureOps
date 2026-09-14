from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from .auth import hash_password
from .config import get_settings
from .database import SessionLocal
from .models import AnalystUser
from .routers import alerts, auth, events, system

settings = get_settings()


def seed_admin() -> None:
    with SessionLocal() as db:
        existing = db.scalar(select(AnalystUser).where(AnalystUser.username == settings.admin_username))
        if existing:
            return
        password_hash, salt = hash_password(settings.admin_password)
        db.add(
            AnalystUser(
                username=settings.admin_username,
                password_hash=password_hash,
                password_salt=salt,
                role="admin",
            )
        )
        db.commit()


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.validate_security()
    seed_admin()
    yield


app = FastAPI(
    title=settings.app_name,
    version=system.APP_VERSION,
    description="Explainable authentication and API security monitoring.",
    lifespan=lifespan,
    docs_url=None if settings.environment.lower() == "production" else "/docs",
    redoc_url=None if settings.environment.lower() == "production" else "/redoc",
    openapi_url=None if settings.environment.lower() == "production" else "/openapi.json",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-Ingestion-Key", "X-CSRF-Token"],
)

app.include_router(auth.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(system.router)
