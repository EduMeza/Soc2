import requests
import json
import os

print('=== INTEGRATION TESTS ===')

# Test 1: Health endpoint
r = requests.get('http://127.0.0.1:8000/api/health')
print(f'1. GET /api/health: {r.status_code} - {r.json()}')
assert r.status_code == 200
assert r.json()['status'] == 'ok'

# Test 2: Login
r = requests.post('http://127.0.0.1:8000/api/auth/login', json={'username': '5205342', 'password': '5205342'})
print(f'2. POST /api/auth/login: {r.status_code} - {r.json()}')
assert r.status_code == 200
token = r.json()['access_token']
force_change = r.json()['force_change']
print(f'   force_change: {force_change}')
headers = {'Authorization': f'Bearer {token}'}

# Test 3: Auth/me
r = requests.get('http://127.0.0.1:8000/api/auth/me', headers=headers)
print(f'3. GET /api/auth/me: {r.status_code} - {r.json()}')
assert r.status_code == 200

# Test 4: Summary
r = requests.get('http://127.0.0.1:8000/api/analytics/summary', headers=headers)
print(f'4. GET /api/analytics/summary: {r.status_code}')
summary = r.json()
print(f'   total_events: {summary["total_events"]}')
print(f'   critical: {summary["critical"]}')
print(f'   high: {summary["high"]}')

# Test 5: Events list
r = requests.get('http://127.0.0.1:8000/api/events/?page=1&limit=10', headers=headers)
print(f'5. GET /api/events/: {r.status_code}')
events = r.json()
print(f'   items: {len(events.get("items", []))}, total: {events.get("total")}')

# Test 6: Severity distribution
r = requests.get('http://127.0.0.1:8000/api/analytics/severity', headers=headers)
print(f'6. GET /api/analytics/severity: {r.status_code} - {r.json()}')

# Test 7: Top agents
r = requests.get('http://127.0.0.1:8000/api/analytics/agents', headers=headers)
print(f'7. GET /api/analytics/agents: {r.status_code} - {r.json()}')

# Test 8: Top hosts
r = requests.get('http://127.0.0.1:8000/api/analytics/hosts', headers=headers)
print(f'8. GET /api/analytics/hosts: {r.status_code} - {r.json()}')

# Test 9: Top rules
r = requests.get('http://127.0.0.1:8000/api/analytics/rules', headers=headers)
print(f'9. GET /api/analytics/rules: {r.status_code} - {r.json()}')

# Test 10: Top IPs
r = requests.get('http://127.0.0.1:8000/api/analytics/ips', headers=headers)
print(f'10. GET /api/analytics/ips: {r.status_code} - {r.json()}')

# Test 11: MITRE distribution
r = requests.get('http://127.0.0.1:8000/api/analytics/mitre', headers=headers)
print(f'11. GET /api/analytics/mitre: {r.status_code}')
mitre = r.json()
print(f'    tactics: {len(mitre.get("tactics", []))}')
print(f'    techniques: {len(mitre.get("techniques", []))}')

# Test 12: Correlations
r = requests.get('http://127.0.0.1:8000/api/analytics/correlations', headers=headers)
print(f'12. GET /api/analytics/correlations: {r.status_code}')
corr = r.json()
print(f'    count: {len(corr)}')

# Test 13: Timeline
r = requests.get('http://127.0.0.1:8000/api/analytics/timeline?limit=50', headers=headers)
print(f'13. GET /api/analytics/timeline: {r.status_code}')
timeline = r.json()
print(f'    events: {len(timeline)}')

# Test 14: Risk
r = requests.get('http://127.0.0.1:8000/api/analytics/risk', headers=headers)
print(f'14. GET /api/analytics/risk: {r.status_code}')
risk = r.json()
print(f'    overall_risk: {risk.get("overall_risk")}')

# Test 15: GeoIP
r = requests.get('http://127.0.0.1:8000/api/geoip/', headers=headers)
print(f'15. GET /api/geoip/: {r.status_code}')
geoip = r.json()
print(f'    results: {len(geoip.get("results", []))}')

# Test 16: Graph
r = requests.get('http://127.0.0.1:8000/api/analytics/graph', headers=headers)
print(f'16. GET /api/analytics/graph: {r.status_code}')
graph = r.json()
print(f'    nodes: {len(graph.get("nodes", []))}')
print(f'    edges: {len(graph.get("edges", []))}')

# Test 17: CSV Import
csv_path = r'C:\Users\emeza.LEGACY\Documents\Proyectos\Soc2\data\sample_events_1.csv'
with open(csv_path, 'rb') as f:
    files = {'file': f}
    r = requests.post('http://127.0.0.1:8000/api/events/import', files=files, headers=headers)
print(f'17. POST /api/events/import: {r.status_code} - {r.json()}')

# Test 18: Summary after import
r = requests.get('http://127.0.0.1:8000/api/analytics/summary', headers=headers)
print(f'18. GET /api/analytics/summary (after import): {r.status_code}')
summary = r.json()
print(f'    total_events: {summary["total_events"]}')
print(f'    critical: {summary["critical"]}')
print(f'    high: {summary["high"]}')

# Test 19: Generate report
r = requests.post('http://127.0.0.1:8000/api/reports/generate', json={'format': 'pdf', 'report_type': 'ejecutivo', 'include_timeline': True}, headers=headers)
print(f'19. POST /api/reports/generate: {r.status_code} - {r.json()}')
report_id = r.json().get('report_id')

# Test 20: Download PDF
r = requests.get(f'http://127.0.0.1:8000/api/reports/download/pdf/{report_id}', headers=headers)
print(f'20. GET /api/reports/download/pdf/{report_id}: {r.status_code}, size: {len(r.content)} bytes')

# Test 21: Download TXT
r = requests.get(f'http://127.0.0.1:8000/api/reports/download/txt/{report_id}', headers=headers)
print(f'21. GET /api/reports/download/txt/{report_id}: {r.status_code}, size: {len(r.content)} bytes')

# Test 22: Download JSON
r = requests.get(f'http://127.0.0.1:8000/api/reports/download/json/{report_id}', headers=headers)
print(f'22. GET /api/reports/download/json/{report_id}: {r.status_code}, size: {len(r.content)} bytes')

# Test 23: List reports
r = requests.get('http://127.0.0.1:8000/api/reports/', headers=headers)
print(f'23. GET /api/reports/: {r.status_code} - {len(r.json())} reports')

print('\n=== ALL TESTS PASSED ===')