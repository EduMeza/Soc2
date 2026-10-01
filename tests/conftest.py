import os
import sys
import secrets
import tempfile
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Before importing the application: never construct a runtime DB engine in tests.
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['JWT_SECRET'] = secrets.token_urlsafe(48)
os.environ['INITIAL_ADMIN_USERNAME'] = ''
os.environ['INITIAL_ADMIN_PASSWORD'] = ''
from app.main import app
from app.core.database import Base, get_db
from app.core.security import hash_password
from app.models.user import User
from fastapi.testclient import TestClient

@pytest.fixture
def context(tmp_path, monkeypatch):
    engine = create_engine('sqlite:///'+(tmp_path/'soc_test.db').as_posix(),connect_args={'check_same_thread':False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    def override():
        with factory() as db:
            yield db
    app.dependency_overrides[get_db] = override
    from app.services import report_store
    from app.services import geoip
    monkeypatch.setattr(geoip,'CACHE_FILE',tmp_path/'geoip_cache.json')
    monkeypatch.setattr(report_store,'OUTPUT_DIR',tmp_path/'output')
    username, password = 'test_'+secrets.token_hex(6), secrets.token_urlsafe(18)
    with factory() as db:
        db.add(User(username=username,password_hash=hash_password(password),force_password_change=False))
        db.commit()
    # No lifespan: bootstrap/scheduler belong to runtime and have separate tests.
    client = TestClient(app)
    yield client,factory,username,password
    client.close()
    app.dependency_overrides.clear()
    engine.dispose()

@pytest.fixture
def authenticated(context):
    client,factory,username,password = context
    response = client.post('/api/auth/login',json={'username':username,'password':password})
    assert response.status_code == 200
    client.headers['Authorization'] = 'Bearer '+response.json()['access_token']
    return client,factory
