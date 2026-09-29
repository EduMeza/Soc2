import requests

# Test import with detailed error
import sqlite3

# Login first
r = requests.post('http://127.0.0.1:8000/api/auth/login', json={'username': '5205342', 'password': '5205342'})
token = r.json()['access_token']
headers = {'Authorization': f'Bearer {token}'}

# Import CSV
with open(r'C:\Users\emeza.LEGACY\Documents\Proyectos\Soc2\data\sample_events_1.csv', 'rb') as f:
    files = {'file': f}
    r = requests.post('http://127.0.0.1:8000/api/events/import', files=files, headers=headers)
print(f"Import: {r.status_code} - {r.json()}")

# Check DB
conn = sqlite3.connect('data/soc.db')
c = conn.cursor()
c.execute('SELECT COUNT(*) FROM events')
print(f"Events in DB: {c.fetchone()}")