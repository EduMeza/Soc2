import urllib.request

url = 'http://localhost:8000/api/events/import'
file_path = r'C:\Users\emeza.LEGACY\soc-dashboard\sample_events_1.csv'
boundary = 'WebKitFormBoundary7MA4YWxkTrZu0gW'

with open(file_path, 'rb') as f:
    file_content = f.read()

body_parts = [
    '--' + boundary,
    'Content-Disposition: form-data; name="file"; filename="sample_events_2.csv"',
    'Content-Type: text/csv',
    '',
]
body_text = '\r\n'.join(body_parts)
body = body_text.encode('utf-8') + file_content + ('\r\n--' + boundary + '--\r\n').encode('utf-8')

req = urllib.request.Request(url, data=body, method='POST')
req.add_header('Content-Type', 'multipart/form-data; boundary=' + boundary)

try:
    with urllib.request.urlopen(req, timeout=90) as resp:
        data = resp.read()
        print('Status:', resp.status)
        print('Response:', data[:600].decode('utf-8', 'ignore'))
except Exception as e:
    print('Error:', type(e).__name__, str(e)[:300])
