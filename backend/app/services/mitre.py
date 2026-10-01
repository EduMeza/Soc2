"""Mapeo MITRE ATT&CK migrado del motor original."""
from __future__ import annotations
import re
from typing import Any


MITRE_TECHNIQUES = {
    "Reconocimiento": {
        "tactic_id": "TA0043",
        "description": "Intento de reconocimiento o recopilación de información sobre los sistemas de la red.",
        "report_line": "Escaneos de puertos/directorios o fingerprinting detectados",
        "techniques": ["T1595 Active Scanning", "T1046 Network Service Discovery"],
        "patterns": [
            re.compile(r"\b(?:recon|reconnaiss|information gathering|osint|enrichment|scanning|port.?scan|vulnerability scan|whois|traceroute|credential access|harvest|phishing|dns.?recon)\b", re.IGNORECASE),
        ],
        "rule_ids": [31151],
    },
    "Ejecución": {
        "tactic_id": "TA0002",
        "description": "Ejecución de código, comandos o scripts sospechosos en los hosts.",
        "report_line": "Ejecución de código, comandos o scripts sospechosos detectada",
        "techniques": ["T1059 Command and Scripting Interpreter", "T1203 Client Execution"],
        "patterns": [
            re.compile(r"(?:powershell[^\r\n]{0,160}?(?:-enc\b|encodedcommand\b)|cmd\.exe[^\r\n]{0,120}?/c\b|rundll32[^\r\n]{0,120}?\.dll\b|\bmimikatz\b|\blsass\b|\bprocdump\b|\bmshta\b|\bwscript\b|\bcscript\b|\bregsvr32\b|\bcertutil\b|\bwmic\b|\bbitsadmin\b|\binvoke-command\b|\bwmiexec\b|\bpsexec\b|schtasks[ \t]+/create|-enc[ \t]+[a-z0-9+/=]{20,}|frombase64string|downloadstring|obfuscat|encoded command|\bwmi\b[^\r\n]{0,120}?process call create)", re.IGNORECASE),
        ],
        "rule_ids": [23506],
    },
    "Persistencia": {
        "tactic_id": "TA0003",
        "description": "Mecanismos de persistencia: tareas programadas, servicios o claves de registro.",
        "report_line": "Mecanismos de persistencia detectados",
        "techniques": ["T1546.011", "T1547", "T1053"],
        "patterns": [
            re.compile(r"(?:persistence|registry.*run|run.?key|startup folder|schtasks /create|scheduled task created|new service|services\.exe load|wmi event subscription|autorun)", re.IGNORECASE),
            re.compile(r"(?:service created|service install|installed as a service|create service|sc create|7045|new service|started service)", re.IGNORECASE),
        ],
        "rule_ids": [92058, 92213],
    },
    "Evasión de defensas": {
        "tactic_id": "TA0005",
        "description": "Técnicas para evadir/deshabilitar controles de seguridad.",
        "report_line": "Técnicas de evasión o deshabilitación de defensas detectadas",
        "techniques": ["T1562 Impair Defenses", "T1027 Obfuscated Files or Information"],
        "patterns": [re.compile(r"(?:disable.*(?:defender|firewall|av|antivirus|security)|stop.*(?:defender|firewall)|bypass|evasiv|clear.*(?:log|event)|timestomp|masquerad|whitelist|exclusion|mimikatz.*sekurlsa|amsi.?bypass|ppl.?dump|remove.*definitions)", re.IGNORECASE)],
        "rule_ids": [],
    },
    "Exfiltración": {
        "tactic_id": "TA0010",
        "description": "Posible transferencia o exfiltración de datos fuera de la red.",
        "report_line": "Posibles intentos de exfiltración de datos",
        "techniques": ["T1048", "T1041"],
        "patterns": [re.compile(r"(?:exfiltrat|data exfil|upload to (?:external|remote|unknown)|dns tunnel|base64 data|large outbound|sensitive data|download of (?:database|credentials|backup)|theft)", re.IGNORECASE)],
        "rule_ids": [],
    },
    "Comando y Control": {
        "tactic_id": "TA0011",
        "description": "Indicadores de comunicación con infraestructura de comando y control (C2).",
        "report_line": "Indicadores de comunicación con infraestructura de comando y control (C2) detectados",
        "techniques": ["T1071", "T1573"],
        "patterns": [re.compile(r"(?:c2|command & control|command and control|beacon|cobalt strike|metasploit|reverse shell|meterpreter|dga|domain generation|call.?back|tunneling|proxy pool|tor exit)", re.IGNORECASE)],
        "rule_ids": [],
    },
}


TACTIC_SLUGS = {
    "Reconocimiento": "reconocimiento",
    "Ejecución": "ejecuci_n",
    "Persistencia": "persistencia",
    "Evasión de defensas": "evasi_n_de_defensas",
    "Exfiltración": "exfiltraci_n",
    "Comando y Control": "comando_y_control",
}

# Evidence-bearing mappings used by the runtime. Broad legacy keyword matches
# above remain reference metadata, not sufficient evidence for a persisted mapping.
EVIDENCE_RULES = [
    ('Persistencia','TA0003','T1546.011',r'\bApplication Compatibility Database launched\b'),
    ('Acceso a credenciales','TA0006','T1003.001',r'\bmimikatz\b|\blsass(?:\.exe)?[^\r\n]{0,40}\bdump\b'),
    ('Ejecución','TA0002','T1059.001',r'powershell[^\r\n]{0,160}(?:-enc\b|encodedcommand\b|downloadstring)'),
    ('Persistencia','TA0003','T1053.005',r'schtasks\s+/create|scheduled task created'),
    ('Persistencia','TA0003','T1547.001',r'\\currentversion\\run(?:once)?\b'),
    ('Evasión de defensas','TA0005','T1562.001',r'(?:disable|stop)[^\r\n]{0,60}(?:defender|antivirus)'),
    ('Comando y Control','TA0011','T1071.001',r'cobalt strike[^\r\n]{0,80}beacon|beacon[^\r\n]{0,80}cobalt strike'),
]

def classify_with_evidence(event):
    text = ' '.join(str(event.get(k) or '') for k in ['rule_description','process','command'])
    evidence = []
    for tactic,tactic_id,technique,pattern in EVIDENCE_RULES:
        match = re.search(pattern,text,re.I)
        if match:
            evidence.append({'tactic':tactic,'tactic_id':tactic_id,'technique':technique,'pattern':pattern,'evidence':match.group()})
    return evidence


TACTIC_SLUG_TO_NAME = {
    "reconocimiento": "Reconocimiento",
    "ejecuci_n": "Ejecución",
    "persistencia": "Persistencia",
    "evasi_n_de_defensas": "Evasión de defensas",
    "exfiltraci_n": "Exfiltración",
    "comando_y_control": "Comando y Control",
}


def classify_mitre(df) -> dict:
    """Clasifica eventos MITRE y devuelve conteos por táctica."""
    if df is None or isinstance(df, list):
        import pandas as pd
        df = pd.DataFrame(df) if df else pd.DataFrame()
    empty = not hasattr(df, "empty") or df.empty
    if empty:
        return {t: {"count": 0, "technique": info["techniques"], "tactic_id": info["tactic_id"]} for t, info in MITRE_TECHNIQUES.items()}

    counts = {tactic: 0 for tactic in MITRE_TECHNIQUES}
    has_rule_col = "rule_id" in df.columns or "rule.id" in df.columns
    for _, row in df.iterrows():
        text = " ".join(str(row.get(f, "")) for f in ("description", "rule", "cve", "process", "status", "rule_description"))
        row_rule_id = None
        if has_rule_col:
            raw = row.get("rule_id", row.get("rule.id"))
            if raw not in (None, "", "nan"):
                try:
                    row_rule_id = int(float(str(raw)))
                except (ValueError, TypeError):
                    row_rule_id = None
        for tactic, info in MITRE_TECHNIQUES.items():
            matched = any(pattern.search(text) for pattern in info.get("patterns", []))
            if matched or (row_rule_id is not None and row_rule_id in info.get("rule_ids", [])):
                counts[tactic] += 1
    return {
        t: {"count": counts[t], "technique": info["techniques"], "tactic_id": info["tactic_id"]}
        for t, info in MITRE_TECHNIQUES.items()
    }


def classify_event_mitre(text: str) -> dict[str, int]:
    """Clasifica un evento individual y devuelve conteos por táctica."""
    counts = {tactic: 0 for tactic in MITRE_TECHNIQUES}
    for tactic, info in MITRE_TECHNIQUES.items():
        for pattern in info.get("patterns", []):
            if pattern.search(text):
                counts[tactic] += 1
                break
    return counts


def slug_to_tactic(slug: str) -> str:
    return {
        "reconocimiento": "Reconocimiento",
        "ejecuci_n": "Ejecución",
        "persistencia": "Persistencia",
        "evasi_n_de_defensas": "Evasión de defensas",
        "exfiltraci_n": "Exfiltración",
        "comando_y_control": "Comando y Control",
    }.get(slug, slug.replace("_", " ").title())
