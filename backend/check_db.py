"""Read-only database inspection using the canonical configuration."""
from sqlalchemy import inspect, text
from app.core.database import engine
if __name__ == '__main__':
    print(inspect(engine).get_table_names())
    with engine.connect() as conn:
        print(conn.execute(text('SELECT severity, COUNT(*) FROM events GROUP BY severity')).all())
