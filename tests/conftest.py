import os
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add backend to sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from config import ADMIN_TOKEN, BLUE_TEAM_TOKEN, RED_TEAM_TOKEN
from database import get_db, seed_initial_data
from main import app
from models import Base

# Isolated SQLite in-memory test database
TEST_DB_URL = "sqlite:///:memory:"

engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    Base.metadata.create_all(bind=engine)
    with TestingSessionLocal() as db:
        from database import SessionLocal
        # temporarily hook SessionLocal for seed_initial_data
        import database
        database.SessionLocal = TestingSessionLocal
        database.ENGINE = engine
        seed_initial_data()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db():
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def red_headers():
    return {"Authorization": f"Bearer {RED_TEAM_TOKEN}"}


@pytest.fixture
def blue_headers():
    return {"Authorization": f"Bearer {BLUE_TEAM_TOKEN}"}


@pytest.fixture
def admin_headers():
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}
