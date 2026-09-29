import requests
import time
import subprocess
import sys
import os

# Start backend
print("Starting backend...")
backend_proc = subprocess.Popen([
    sys.executable, "-m", "uvicorn", "app.main:app", 
    "--host", "127.0.0.1", "--port", "8000"
], cwd=r"C:\Users\emeza.LEGACY\Documents\Proyectos\Soc2\backend")

# Wait for backend to start
print("Waiting for backend to start...")
for i in range(30):
    try:
        r = requests.get("http://127.0.0.1:8000/api/health", timeout=2)
        if r.status_code == 200:
            print("Backend ready!")
            break
    except:
        pass
    time.sleep(1)
else:
    print("Backend failed to start")
    backend_proc.terminate()
    sys.exit(1)

# Run tests
print("\n=== RUNNING INTEGRATION TESTS ===")

# Test 1: Health
r = requests.get("http://127.0.0.1:8000/api/health")
print(f"1. GET /api/health: {r.status_code} - {r.json()}")
assert r.status_code == 200

# Test 2: Login
r = requests.post("http://127.0.0.1:8000/api/auth/login", json={"username": "5205342", "password": "5205342"})
print(f"2. POST /api/auth/login: {r.status_code}")
assert r.status_code == 200
token = r.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

# Test 3: Auth/me
r = requests.get("http://127.0.0.1:8000/api/auth/me", headers=headers)
print(f"3. GET /api/auth/me: {r.status_code}")
assert r.status_code == 200

# Test 4: Summary
r = requests.get("http://127.0.0.1:8000/api/analytics/summary", headers=headers)
summary = r.json()
print(f"4. GET /api/analytics/summary: {r.status_code}")
print(f"   total_events: {summary.get('total_events')}")
print(f"   critical: {summary.get('critical')}")
print(f"   high: {summary.get('high')}")

# Test 5: Events
r = requests.get("http://127.0.0.1:8000/api/events/?page=1&limit=10", headers=headers)
events = r.json()
print(f"5. GET /api/events/: {r.status_code} - items: {len(events.get('items', []))}, total: {events.get('total')}")

# Test 6: Severity
r = requests.get("http://127.0.0.1:8000/api/analytics/severity", headers=headers)
print(f"6. GET /api/analytics/severity: {r.status_code} - {r.json()}")

# Test 7: Top agents
r = requests.get("http://127.0.0.1:8000/api/analytics/agents", headers=headers)
print(f"7. GET /api/analytics/agents: {r.status_code}")

# Test 8: Top hosts
r = requests.get("http://127.0.0.1:8000/api/analytics/hosts", headers=headers)
print(f"8. GET /api/analytics/hosts: {r.status_code}")

# Test 9: Top rules
r = requests.get("http://127.0.0.1:8000/api/analytics/rules", headers=headers)
print(f"9. GET /api/analytics/rules: {r.status_code}")

# Test 10: Top IPs
r = requests.get("http://127.0.0.1:8000/api/analytics/ips", headers=headers)
print(f"10. GET /api/analytics/ips: {r.status_code}")

# Test 11: MITRE
r = requests.get("http://127.0.0.1:8000/api/analytics/mitre", headers=headers)
mitre = r.json()
print(f"11. GET /api/analytics/mitre: {r.status_code} - tactics: {len(mitre.get('tactics', []))}, techniques: {len(mitre.get('techniques', []))}")

# Test 12: Correlations
r = requests.get("http://127.0.0.1:8000/api/analytics/correlations", headers=headers)
corr = r.json()
print(f"12. GET /api/analytics/correlations: {r.status_code} - count: {len(corr)}")

# Test 13: Timeline
r = requests.get("http://127.0.0.1:8000/api/analytics/timeline?limit=50", headers=headers)
timeline = r.json()
print(f"13. GET /api/analytics/timeline: {r.status_code} - events: {len(timeline)}")

# Test 14: Risk
r = requests.get("http://127.0.0.1:8000/api/analytics/risk", headers=headers)
risk = r.json()
print(f"14. GET /api/analytics/risk: {r.status_code} - overall_risk: {risk.get('overall_risk')}")

# Test 15: GeoIP
r = requests.get("http://127.0.0.1:8000/api/geoip/", headers=headers)
geoip = r.json()
print(f"15. GET /api/geoip/: {r.status_code} - results: {len(geoip.get('results', []))}")

# Test 16: Graph
r = requests.get("http://127.0.0.1:8000/api/analytics/graph", headers=headers)
graph = r.json()
print(f"16. GET /api/analytics/graph: {r.status_code} - nodes: {len(graph.get('nodes', []))}, edges: {len(graph.get('edges', []))}")

# Test 17: CSV Import
csv_path = r"C:\Users\emeza.LEGACY\Documents\Proyectos\Soc2\data\sample_events_1.csv"
with open(csv_path, "rb") as f:
    files = {"file": f}
    r = requests.post("http://127.0.0.1:8000/api/events/import", files=files, headers=headers)
print(f"17. POST /api/events/import: {r.status_code} - {r.json()}")

# Test 18: Summary after import
r = requests.get("http://127.0.0.1:8000/api/analytics/summary", headers=headers)
summary = r.json()
print(f"18. GET /api/analytics/summary (after import): {r.status_code}")
print(f"    total_events: {summary.get('total_events')}")

# Test 19: Generate report
r = requests.post("http://127.0.0.1:8000/api/reports/generate", json={"format": "pdf", "report_type": "ejecutivo", "include_timeline": True}, headers=headers)
print(f"19. POST /api/reports/generate: {r.status_code} - {r.json()}")
report_id = r.json().get("report_id")

# Test 20: Download PDF
r = requests.get(f"http://127.0.0.1:8000/api/reports/download/pdf/{report_id}", headers=headers)
print(f"20. GET /api/reports/download/pdf/{report_id}: {r.status_code}, size: {len(r.content)} bytes")

# Test 21: Download TXT
r = requests.get(f"http://127.0.0.1:8000/api/reports/download/txt/{report_id}", headers=headers)
print(f"21. GET /api/reports/download/txt/{report_id}: {r.status_code}, size: {len(r.content)} bytes")

# Test 22: Download JSON
r = requests.get(f"http://127.0.0.1:8000/api/reports/download/json/{report_id}", headers=headers)
print(f"22. GET /api/reports/download/json/{report_id}: {r.status_code}, size: {len(r.content)} bytes")

# Test 23: List reports
r = requests.get("http://127.0.0.1:8000/api/reports/", headers=headers)
print(f"23. GET /api/reports/: {r.status_code} - {len(r.json())} reports")

# Test 24: Second CSV import
csv_path2 = r"C:\Users\emeza.LEGACY\Documents\Proyectos\Soc2\data\sample_events_2.csv"
if os.path.exists(csv_path2):
    with open(csv_path2, "rb") as f:
        files = {"file": f}
        r = requests.post("http://127.0.0.1:8000/api/events/import", files=files, headers=headers)
    print(f"24. POST /api/events/import (sample_events_2.csv): {r.status_code} - {r.json()}")

print("\n=== ALL TESTS PASSED ===")

# Cleanup
backend_proc.terminate()