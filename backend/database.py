"""Database setup via SQLAlchemy.

Default: a local SQLite file (zero config, local development).
Production: set DATABASE_URL to a permanent hosted Postgres (e.g. Neon) —
accounts, details, customers and orders then survive every redeploy and
restart. (Render's free tier wipes the local file on each deploy, which
is why same-account logins used to be asked for their details again.)
"""
import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cafeloop.db"
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DB_PATH}")
# Some providers hand out postgres:// — SQLAlchemy 2.x wants postgresql://.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql://" + DATABASE_URL[len("postgres://"):]

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,  # hosted Postgres sleeps when idle; drop stale connections
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
