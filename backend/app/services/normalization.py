"""Single canonical CSV normalization boundary. Naive source times use configured timezone."""
import hashlib
import json
import ipaddress
import unicodedata
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pydantic import BaseModel
from app.core.config import settings

ALIASES = {
 'timestamp': ['timestamp', '@timestamp', 'fecha', 'datetime', 'time', 'date'],
 'agent': ['agent.name', 'agent', 'agente', 'host', 'hostname'],
 'hostname': ['hostname', 'host', 'computername', 'data.win.system.computer', 'agent.name'],
 'severity': ['rule.level', 'severity', 'severidad', 'level', 'prioridad'],
 'rule_id': ['rule.id', 'rule_id', 'regla', 'rule', 'eventcode'],
 'rule_description': ['rule.description', 'rule_description', 'description', 'descripcion', 'message', 'data.win.system.message', 'full_log'],
 'source_ip': ['data.srcip', 'data.win.eventdata.ipAddress', 'source_ip', 'src_ip', 'srcip', 'origen', 'source'],
 'destination_ip': ['data.dstip', 'destination_ip', 'dst_ip', 'destino', 'destination'],
 'process': ['data.win.eventdata.image', 'data.win.eventdata.processName', 'process', 'proceso', 'image', 'executable'],
 'command': ['data.win.eventdata.commandLine', 'command', 'commandline'],
 'username': ['data.win.eventdata.targetUserName', 'username', 'user', 'usuario'],
 'cve': ['cve', 'cve_id', 'data.vulnerability.cve'],
 'file_path': ['file_path', 'file', 'data.win.eventdata.targetFilename'],
 'source_port': ['source_port', 'data.srcport'], 'destination_port': ['destination_port', 'data.dstport'],
 'protocol': ['protocol', 'data.protocol'], 'status': ['status', 'estado'],
 'event_type': ['event_type', 'data.id'], 'source': ['source_type'],
}

def fold(value):
    return re.sub('[^a-z0-9]', '', ''.join(c for c in unicodedata.normalize('NFKD', str(value).lower()) if not unicodedata.combining(c)))

def detect_columns(columns):
    lookup = {fold(c): c for c in columns}
    return {key: next(lookup[fold(a)] for a in aliases if fold(a) in lookup)
            for key, aliases in ALIASES.items() if any(fold(a) in lookup for a in aliases)}

def normalize_severity(value, numeric_level=False):
    text = fold(value)
    if text.isdigit():
        n = int(text)
        if numeric_level:
            return 'Critical' if n >= 15 else 'High' if n >= 12 else 'Medium' if n >= 7 else 'Low' if n >= 1 else 'Info'
        return {5:'Critical',4:'Critical',3:'High',2:'Medium',1:'Low',0:'Info'}.get(n, 'Unknown')
    for name, aliases in {'Critical':['critical','critico','critica'], 'High':['high','alta','alto'],
                          'Medium':['medium','media','medio','warning'], 'Low':['low','bajo','baja'],
                          'Info':['info','informational']}.items():
        if text in aliases:
            return name
    return 'Unknown'

class NormalizedEvent(BaseModel):
    timestamp: datetime
    agent: str = ''
    hostname: str = ''
    severity: str = 'Unknown'
    original_severity: str = ''
    rule_id: str = ''
    rule_description: str = ''
    source_ip: str = ''
    destination_ip: str = ''
    source_port: int = 0
    destination_port: int = 0
    process: str = ''
    command: str = ''
    username: str = ''
    cve: str = ''
    file_path: str = ''
    protocol: str = ''
    status: str = ''
    source: str = ''
    event_type: str = ''
    raw_event: str
    event_fingerprint: str

def normalize_row(row, detected):
    values = {key: str(row.get(col) or '').strip() for key, col in detected.items()}
    raw_time = values.get('timestamp', '')
    try:
        stamp = datetime.fromisoformat(raw_time.replace('Z', '+00:00'))
    except ValueError:
        try:
            stamp = datetime.strptime(raw_time, '%b %d, %Y @ %H:%M:%S.%f')
        except ValueError:
            raise ValueError('timestamp inválido: fila rechazada')
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=ZoneInfo(settings.TIMEZONE))
    values['timestamp'] = stamp.astimezone(timezone.utc).replace(tzinfo=None)
    values['hostname'] = values.get('hostname') or values.get('agent', '')
    values['original_severity'] = values.get('severity', '')
    values['severity'] = normalize_severity(values.get('severity', ''), fold(detected.get('severity', '')) == 'rulelevel')
    warnings = []
    for key in ['source_ip', 'destination_ip']:
        text = values.get(key, '')
        if text:
            try:
                values[key] = str(ipaddress.ip_address(text))
            except ValueError:
                values[key] = ''
                warnings.append(key + ' inválida; conservada en raw_event')
    for key in ['source_port', 'destination_port']:
        text = values.get(key, '')
        values[key] = int(text) if text.isdigit() and 0 <= int(text) <= 65535 else 0
    values['raw_event'] = json.dumps(row, ensure_ascii=False, sort_keys=True)
    fields = ['timestamp', 'agent', 'hostname', 'rule_id', 'source_ip', 'destination_ip', 'rule_description', 'process', 'command', 'cve', 'username', 'source_port', 'destination_port', 'protocol', 'file_path']
    extra = {key: value for key,value in row.items() if key not in detected.values() and ('.' in key or key in ['full_log','_id']) and value not in (None,'')}
    fingerprint = json.dumps([[str(values.get(k, '')) for k in fields],extra], ensure_ascii=False, sort_keys=True)
    values['event_fingerprint'] = hashlib.sha256(fingerprint.encode()).hexdigest()
    return NormalizedEvent(**values), warnings
