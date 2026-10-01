from app.models.persistence import AuditLog

def audit(db, username, action, status='success', **details):
    # Callers supply only explicit non-secret metadata, never request bodies.
    allowed = {'filename', 'batch_id', 'report_id', 'execution_id', 'format', 'reason'}
    db.add(AuditLog(username=username, action=action, status=status,
                    details={k: v for k, v in details.items() if k in allowed}))
