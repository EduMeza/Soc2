"""Repair the initial migration from its preserved snapshots, before runtime use.

Requires a snapshot directory argument. Refuses to replace user-created runtime
records. The current canonical database is backed up before replacement.
"""
import argparse
import shutil
import sqlite3
import tempfile
import json
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import migrate

def repair(snapshot_dir):
    root, data = migrate.PROJECT_ROOT, migrate.DATA_DIR
    target = data/'soc.db'
    with closing(sqlite3.connect(target)) as conn:
        for table, column in [('import_batches','username'),('reports','created_by')]:
            if conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {column} != 'migration'").fetchone()[0]:
                raise RuntimeError('Runtime con registros nuevos: no se reemplazará automáticamente')
        if conn.execute('SELECT COUNT(*) FROM audit_logs').fetchone()[0] or conn.execute('SELECT COUNT(*) FROM scheduler_runs').fetchone()[0]:
            raise RuntimeError('Runtime ya utilizado: reparación automática cancelada')
        if conn.execute('SELECT COUNT(*) FROM users WHERE force_password_change = 0').fetchone()[0]:
            raise RuntimeError('Usuarios actualizados: reparación automática cancelada')
    backup = root/'_backup'/('repair_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f'))
    backup.mkdir(parents=True)
    current = backup/'data_soc.db'
    with closing(sqlite3.connect(target)) as src,closing(sqlite3.connect(current)) as dst:
        src.backup(dst)
    with tempfile.TemporaryDirectory(prefix='soc2-repair-') as temp:
        stage = Path(temp)
        (stage/'data').mkdir()
        (stage/'backend/data').mkdir(parents=True)
        for name, destination in [('soc.db','soc.db'),('data_soc.db','data/soc.db'),('backend_data_soc.db','backend/data/soc.db')]:
            source = snapshot_dir/name
            if source.exists():
                shutil.copy2(source,stage/destination)
        migrate.PROJECT_ROOT, migrate.DATA_DIR = stage,stage/'data'
        try:
            migrate.migrate()
        finally:
            migrate.PROJECT_ROOT, migrate.DATA_DIR = root,data
        with closing(sqlite3.connect(stage/'data/soc.db')) as conn:
            conn.execute('ATTACH DATABASE ? AS previous',(str(current),))
            conn.execute('INSERT INTO reports SELECT * FROM previous.reports')
            conn.execute('INSERT INTO app_settings SELECT * FROM previous.app_settings')
            assert conn.execute('PRAGMA foreign_key_check').fetchall() == []
            conn.commit()
        staging = data/'soc_repaired.db'
        shutil.copy2(stage/'data/soc.db',staging)
        for suffix in ['-wal','-shm']:
            if Path(str(target)+suffix).exists():
                raise RuntimeError('Runtime abierto: no se reemplazará la base')
        staging.replace(target)
        manifests = list((stage/'_backup').glob('*/migration.json'))
        manifest = json.loads(manifests[0].read_text(encoding='utf-8'))
        manifest['backup'] = str(backup)
        manifest['source_snapshots'] = str(snapshot_dir)
        (backup/'migration.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print('Reparación completada; backup:',backup)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('snapshot_dir',type=Path)
    repair(parser.parse_args().snapshot_dir.resolve())
