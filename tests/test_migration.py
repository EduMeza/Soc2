import sqlite3
import json
from pathlib import Path
import migrate
from contextlib import closing

def test_recover_original_timestamp():
    row = migrate.recover_row({'timestamp':'2099-01-01','raw_event':"{'timestamp': 'Sep 14, 2026 @ 01:00:00.000', 'rule.description': 'Evidence', 'source_ip': nan}"})
    assert row['timestamp'] == 'Sep 14, 2026 @ 01:00:00.000'
    assert row['source_ip'] is None

def test_default_db_independent_of_cwd(tmp_path):
    import os
    import subprocess
    import sys
    root = Path(__file__).resolve().parents[1]
    env = {**os.environ,'PYTHONPATH':str(root/'backend'),'DATABASE_URL':''}
    result = subprocess.check_output([sys.executable,'-c','from app.core.config import settings; print(settings.DATABASE_URL)'],cwd=tmp_path,env=env,text=True).strip()
    assert result == 'sqlite:///'+(root/'data/soc.db').as_posix()

def test_migration_backups_and_idempotence(tmp_path,monkeypatch):
    root = tmp_path/'project'
    data = root/'data'
    data.mkdir(parents=True)
    monkeypatch.setattr(migrate,'PROJECT_ROOT',root)
    monkeypatch.setattr(migrate,'DATA_DIR',data)
    with closing(sqlite3.connect(root/'soc.db')) as conn:
        conn.execute('CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp TEXT, source_ip TEXT, severity TEXT)')
        conn.execute("INSERT INTO events VALUES (1,'2026-09-14T01:00:00Z','8.8.8.8','High')")
        conn.execute("INSERT INTO events VALUES (2,'invalid','8.8.8.8','High')")
        conn.commit()
    migrate.migrate()
    with closing(sqlite3.connect(data/'soc.db')) as conn:
        assert conn.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 1
        assert conn.execute('SELECT total_rows,inserted,rejected FROM import_batches').fetchone() == (2,1,1)
        assert conn.execute('PRAGMA foreign_key_check').fetchall() == []
    backups = list((root/'_backup').glob('*/soc.db'))
    assert len(backups) == 1
    with closing(sqlite3.connect(backups[0])) as conn:
        assert conn.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 2
    migrate.migrate()
    assert len(list((root/'_backup').glob('*/soc.db'))) == 1
    with closing(sqlite3.connect(data/'soc.db')) as conn:
        conn.execute("INSERT INTO reports (report_id,created_by) VALUES ('preserved','migration')")
        conn.commit()
    from repair_migration import repair
    repair(backups[0].parent)
    with closing(sqlite3.connect(data/'soc.db')) as conn:
        assert conn.execute('SELECT COUNT(*) FROM reports').fetchone()[0] == 1
        assert conn.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 1

def test_report_migration_duplicate_ids(tmp_path,monkeypatch):
    root = tmp_path/'project'
    data = root/'data'
    data.mkdir(parents=True)
    history = root/'backend/data'
    history.mkdir(parents=True)
    monkeypatch.setattr(migrate,'PROJECT_ROOT',root)
    monkeypatch.setattr(migrate,'DATA_DIR',data)
    migrate.migrate()
    (history/'report_history.json').write_text(json.dumps([
        {'id':'report','entity':'one','timestamp':'2026-09-14T00:00:00Z'},
        {'id':'report','entity':'two','timestamp':'2026-09-14T00:01:00Z'}]),encoding='utf-8')
    migrate.migrate_report_history()
    migrate.migrate_report_history()
    with closing(sqlite3.connect(data/'soc.db')) as conn:
        assert conn.execute('SELECT COUNT(*) FROM reports').fetchone()[0] == 2
