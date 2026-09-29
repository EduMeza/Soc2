import sqlite3
conn = sqlite3.connect('data/soc.db')
c = conn.cursor()
c.execute('SELECT name FROM sqlite_master WHERE type="table"')
print(c.fetchall())
c.execute('SELECT severity, COUNT(*) FROM events GROUP BY severity')
print(c.fetchall())