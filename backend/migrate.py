"""Explicit, backed-up migration of historical SQLite files into the canonical runtime."""
import json
import sqlite3
import shutil
import hashlib
import ast
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.core.config import PROJECT_ROOT, DATA_DIR
from app.core.database import Base
from app.models import event, user, persistence
from app.services.normalization import normalize_row, detect_columns
from app.services.risk import calculate_event_risk
from app.services.correlation import persist_correlations
from app.services.mitre import classify_with_evidence

def recover_row(record):
    """Recover source evidence from the old parser's JSON/Python-literal raw_event."""
    raw = record.get('raw_event')
    if not raw:
        return record
    try:
        recovered = json.loads(raw)
    except (ValueError,TypeError):
        try:
            tree = ast.parse(raw,mode='eval')
            class MissingValue(ast.NodeTransformer):
                def visit_Name(self,node):
                    return ast.copy_location(ast.Constant(None),node) if node.id == 'nan' else node
            recovered = ast.literal_eval(MissingValue().visit(tree))
        except (ValueError,SyntaxError,TypeError):
            return record
    return recovered if isinstance(recovered,dict) and any(k in recovered for k in ['timestamp','Timestamp','@timestamp']) else record

def migrate():
    target = DATA_DIR / 'soc.db'
    if target.exists():
        with closing(sqlite3.connect(target)) as conn:
            if conn.execute("SELECT 1 FROM sqlite_master WHERE name='import_batches'").fetchone():
                print('Esquema actual: migración ya aplicada.')
                return
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')
    backup = PROJECT_ROOT / '_backup' / stamp
    backup.mkdir(parents=True)
    sources = [PROJECT_ROOT/'soc.db', target, PROJECT_ROOT/'backend/data/soc.db']
    snapshots = []
    for source in sources:
        if source.exists():
            snapshot = backup / ('_'.join(source.relative_to(PROJECT_ROOT).parts))
            with closing(sqlite3.connect(f'file:{source.as_posix()}?mode=ro',uri=True)) as src, closing(sqlite3.connect(snapshot)) as dst:
                src.backup(dst)
            snapshots.append((source,snapshot))
    staging = DATA_DIR / ('soc_migration_'+stamp+'.db')
    engine = create_engine('sqlite:///'+staging.as_posix())
    Base.metadata.create_all(engine)
    report = {'backup':str(backup),'sources':[], 'rejected_rows_preserved_in_backup':0}
    with Session(engine) as db:
        known, users = set(), set()
        for source,snapshot in reversed(snapshots):
            conn = sqlite3.connect(snapshot)
            conn.row_factory = sqlite3.Row
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            batch = persistence.ImportBatch(filename=str(source.relative_to(PROJECT_ROOT)),file_size=source.stat().st_size,
                username='migration',inserted=0,duplicates=0,rejected=0,total_rows=0,status='completed')
            db.add(batch)
            db.flush()
            imported, warnings = [], []
            if 'events' in tables:
                for row in conn.execute('SELECT * FROM events'):
                    batch.total_rows += 1
                    raw = recover_row(dict(row))
                    try:
                        normalized, notes = normalize_row(raw,detect_columns(raw))
                    except ValueError:
                        batch.rejected += 1
                        warnings.append({'legacy_id':raw.get('id'),'message':'timestamp inválido, evidencia conservada en backup'})
                        continue
                    if normalized.event_fingerprint in known:
                        batch.duplicates += 1
                        continue
                    known.add(normalized.event_fingerprint)
                    values = normalized.model_dump()
                    evidence = classify_with_evidence(values)
                    values['mitre_evidence'] = evidence
                    risk,factors = calculate_event_risk(values)
                    record = event.Event(**values, risk_score=risk,risk_factors=factors,import_batch_id=batch.id,
                                         mitre_tactic='; '.join(dict.fromkeys(e['tactic'] for e in evidence)),
                                         mitre_technique='; '.join(dict.fromkeys(e['technique'] for e in evidence)),correlation_id='')
                    db.add(record)
                    imported.append(record)
                    batch.inserted += 1
            if 'users' in tables:
                for row in conn.execute('SELECT * FROM users'):
                    raw = dict(row)
                    name = raw.get('username') or raw.get('document_number')
                    hashed = raw.get('password_hash') or ''
                    if name and name not in users and hashed.startswith(('$2a$','$2b$','$2y$')):
                        db.add(user.User(username=name,password_hash=hashed,force_password_change=True))
                        users.add(name)
            db.flush()
            persist_correlations(db, imported)
            batch.warnings = warnings
            batch.completed_at = persistence.now()
            report['sources'].append({'source':str(source.relative_to(PROJECT_ROOT)), 'total':batch.total_rows,
                'inserted':batch.inserted,'duplicates':batch.duplicates,'rejected':batch.rejected})
            report['rejected_rows_preserved_in_backup'] += batch.rejected
            conn.close()
        db.commit()
    engine.dispose()
    # Never replace a live SQLite database with pending WAL data.
    if target.exists():
        with closing(sqlite3.connect(target,timeout=2)) as checkpoint:
            if checkpoint.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0]:
                raise RuntimeError('Base ocupada: detenga el runtime antes de migrar')
    for suffix in ['-wal','-shm']:
        if Path(str(target)+suffix).exists():
            raise RuntimeError('Detenga el runtime antes de completar la migración; backup y staging conservados.')
    staging.replace(target)
    (backup/'migration.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))

def migrate_report_history():
    target = DATA_DIR / 'soc.db'
    engine = create_engine('sqlite:///'+target.as_posix())
    sources = [PROJECT_ROOT/'backend/data/report_history.json']
    imported = 0
    with Session(engine) as db:
        for source in sources:
            if not source.exists():
                continue
            records = json.loads(source.read_text(encoding='utf-8'))
            unique = {}
            for raw in records:
                if not raw.get('id'):
                    continue
                row = dict(raw)
                if row['id'] in unique:
                    if row == unique[row['id']]:
                        continue
                    digest = hashlib.sha256(json.dumps(row,sort_keys=True).encode()).hexdigest()[:12]
                    row['id'] += '_'+digest
                unique[row['id']] = row
            pending = [r for r in unique.values() if not db.get(persistence.Report,r['id'])]
            if not pending:
                continue
            backup = PROJECT_ROOT/'_backup'/('reports_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f'))
            backup.mkdir(parents=True)
            shutil.copy2(source,backup/source.name)
            with closing(sqlite3.connect(target)) as src,closing(sqlite3.connect(backup/'data_soc.db')) as dst:
                src.backup(dst)
            output = PROJECT_ROOT/'output'
            output.mkdir(exist_ok=True)
            for row in pending:
                paths = {}
                for fmt in ['pdf','txt','json']:
                    name = Path(str(row.get('file_paths',{}).get(fmt,'')).replace('\\','/')).name
                    if not name:
                        continue
                    origin = PROJECT_ROOT/'backend/output'/name
                    if origin.is_file() and origin.resolve().is_relative_to((PROJECT_ROOT/'backend/output').resolve()):
                        destination = output/name
                        if destination.exists() and destination.read_bytes() != origin.read_bytes():
                            destination = output/(persistence.uid()+'_'+name)
                        if not destination.exists():
                            shutil.copy2(origin,destination)
                        paths[fmt+'_path'] = str(destination.resolve())
                raw_date = row.get('timestamp','')
                try:
                    created = datetime.fromisoformat(raw_date.replace('Z','+00:00')).astimezone(timezone.utc).replace(tzinfo=None)
                except ValueError:
                    created = None
                report = persistence.Report(report_id=row['id'],analyst=row.get('analyst',''),entity=row.get('entity',''),
                    period=row.get('period',''),total_events=row.get('total_events',0),critical=row.get('critical',0),
                    high=row.get('high',0),medium=row.get('medium',0),low=row.get('low',0),risk_score=row.get('risk_score',0),
                    status='legacy_imported',created_by='migration',**paths)
                if created:
                    report.created_at = created
                db.add(report)
                imported += 1
            db.commit()
    engine.dispose()
    print(f'Reportes históricos migrados: {imported}')

if __name__ == '__main__':
    migrate()
    migrate_report_history()
