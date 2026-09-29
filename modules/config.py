"""Configuración global y constantes del dashboard SOC 24x7.

Centraliza: analistas por defecto, mapeo de alias de columnas,
mapas de severidad, patrones regex y definiciones MITRE ATT&CK.
"""
from __future__ import annotations

import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Rutas del proyecto
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
ANALYSTS_FILE = DATA_DIR / "analysts.json"
HISTORY_FILE = DATA_DIR / "report_history.json"

# Retención del historial de reportes (trazabilidad mínima en días).
HISTORY_RETENTION_DAYS = 3

# ---------------------------------------------------------------------------
# Analistas predefinidos (persistidos en analysts.json al primer arranque)
# ---------------------------------------------------------------------------
DEFAULT_ANALYSTS = ["Eduardo Meza", "Ana", "Carlos"]

# ---------------------------------------------------------------------------
# Turnos / periodos disponibles
# ---------------------------------------------------------------------------
SHIFTS = {
    "Mañana (07:00)": "Mañana (07:00)",
    "Tarde (16:00)": "Tarde (16:00)",
    "Noche (23:00)": "Noche (23:00)",
}

# ---------------------------------------------------------------------------
# Aliases de columnas.
# La clave es el nombre canónico normalizado; el valor es el conjunto de
# posibles nombres de columna que acepta el detector (normalizados: minúsculas,
# sin acentos, sin espacios ni símbolos no alfanuméricos).
# ---------------------------------------------------------------------------
COLUMN_ALIASES: dict[str, set[str]] = {
    "severity": {
        "rulelevel",  # columna 'rule.level' / 'rule_level' (prioridad)
        "severity", "severidad", "prioridad", "priority", "level", "nivel",
        "criticality", "criticidad", "gravedad", "risk", "riesgo", "sevrity",
    },
    "agent": {
        "agent", "agente", "hostname", "host", "computername", "computer",
        "equipo", "workstation", "machine", "maquina", "wazuhagent",
        "agentname", "agentid", "host_name", "computer_name",
    },
    "timestamp": {
        "timestamp", "time", "fecha", "datetime", "date", "hora",
        "event_time", "created", "created_at", "time_created", "when",
    },
    "rule": {
        "rule", "rule_id", "rule_name", "regla", "signature", "signature_id",
        "azure", "detections", "eventcode", "event_id", "id",
    },
    "description": {
        "description", "descripcion", "message", "mensaje", "details",
        "detalle", "summary", "resumen", "log", "event", "text", "full_log",
        "alert", "event_title", "log_notes", "data",
    },
    "src_ip": {
        "src_ip", "source_ip", "srcip", "sourceip", "ip_origen",
        "source", "src", "origen", "sourceaddress", "srcaddress",
        "srcaddr", "direccion_ip_origen", "sip",
    },
    "dst_ip": {
        "dst_ip", "dest_ip", "destination_ip", "dstip", "destip",
        "ip_destino", "destino", "destination", "dst", "dest",
        "destinationaddress", "dstaddress", "dip",
    },
    "cve": {"cve", "cve_id", "vulnerability", "vuln_id"},
    "process": {
        "process", "proceso", "process_name", "processname", "module",
        "executable", "program", "image", "file",
    },
    "user": {
        "user", "usuario", "username", "principal", "account", "cuenta",
        "actor", "actoruser", "targetusername", "user.name",
    },
    "status": {
        "status", "estado", "action", "accion", "result", "outcome",
        "success", "eventaction", "event_type",
    },
}

# ---------------------------------------------------------------------------
# Normalización de severidades.
# ---------------------------------------------------------------------------
SEVERITY_MAP: dict[str, str] = {
    # Crítico
    "critical": "Critical",
    "critico": "Critical",
    "critica": "Critical",
    "emergency": "Critical",
    "nivelcritico": "Critical",
    "4": "Critical",
    "5": "Critical",
    # Alta
    "high": "High",
    "alta": "High",
    "alto": "High",
    "elevated": "High",
    "3": "High",
    # Media
    "medium": "Medium",
    "media": "Medium",
    "moderate": "Medium",
    "warning": "Medium",
    "2": "Medium",
    # Baja
    "low": "Low",
    "baja": "Low",
    "bajo": "Low",
    "info": "Low",
    "informational": "Low",
    "informative": "Low",
    "notification": "Low",
    "1": "Low",
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

# Rangos de nivel numérico -> severidad canónica (en orden de prioridad).
# Regla de la organización (columna 'rule.level'):
#   12, 13, 14 -> Alta severidad
#   15         -> Crítico
# Además se conserva la escala genérica 1-5 para compatibilidad.
SEVERITY_LEVEL_RANGES: list[tuple[int, int, str]] = [
    (15, 15, "Critical"),
    (12, 14, "High"),
    (4, 5, "Critical"),
    (3, 3, "High"),
    (2, 2, "Medium"),
    (1, 1, "Low"),
]

# ---------------------------------------------------------------------------
# Patrones de detección de hallazgos relevantes.
# ---------------------------------------------------------------------------
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# IP interna (RFC1918 + rangos especiales de red local).
PRIVATE_IP_PATTERN = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Indicadores de escaneo / enumeración (inglés y español).
SCAN_PATTERN = re.compile(
    r"\b(?:port scan|scanner|nmap|masscan|probe|network scan|sweep|"
    r"enumerat|brute.?force|authentication failure|multiple 404|"
    r"dir.?scan|directory.?scan|traversal|403 forbidden|"
    r"admin login|wordpress|phpmyadmin|/\.git|fuzzing|"
    r"escaneo|escaneos|escanear|directorios?|evadiendo|agresivo)\b",
    re.IGNORECASE,
)

# Creación/instalación de servicios o herramientas de administración remota.
SERVICE_CREATION_PATTERN = re.compile(
    r"\b(?:service created|service install|installed as a service|"
    r"create service|sc create|7045|new service|started service)\b",
    re.IGNORECASE,
)

# Comandos y procesos sospechosos.
#
# Registro de detección por patrón -> etiqueta legible. El orden importa: la
# primera etiqueta que coincida se usa como fragmento representativo de la fila.
# Los patrones toleran espacios y mayúsculas/minúsculas.
SUSPICIOUS_PROCESS_REGISTRY: list[tuple[str, str]] = [
    (r"powershell[^\r\n]{0,160}?(?:-enc\b|encodedcommand\b)", "powershell -enc"),
    (r"\bpowershell\b[^\r\n]{0,120}?-w hidden\b", "PowerShell -w hidden"),
    (r"cmd\.exe[^\r\n]{0,120}?/c\b", "cmd.exe /c"),
    (r"rundll32[^\r\n]{0,120}?\.dll\b", "rundll32 .dll"),
    (r"\bwmics?[^\r\n]{0,120}?process\b", "wmic process"),
    (r"\breg[ \t]+add[^\r\n]{0,120}?(?:run|runonce)\b", "reg add Run/RunOnce"),
    (r"certutil[^\r\n]{0,120}?urlcache", "certutil -urlcache"),
    (r"certutil[^\r\n]{0,120}?-decode\b", "certutil -decode"),
    (r"bitsadmin[^\r\n]{0,120}?/transfer\b", "bitsadmin /transfer"),
    (r"\binvoke-command\b", "invoke-command"),
    (r"\bwmiexec\b", "wmiexec"),
    (r"\bpsexec\b", "psexec"),
    (r"schtasks[ \t]+/create", "schtasks /create"),
    (r"-enc[ \t]+[a-z0-9+/=]{20,}", "comando codificado (-enc)"),
    (r"frombase64string", "Base64String"),
    (r"downloadstring", "PowerShell downloadstring"),
    (r"obfuscat", "obfuscation"),
    (r"encoded command", "encoded command"),
    (r"\bwmi\b[^\r\n]{0,120}?process call create", "WMI Process Create"),
    (r"\bmimikatz\b", "Mimikatz"),
    (r"\blsass\b", "lsass"),
    (r"\bprocdump\b", "procdump"),
    (r"\bmshta\b", "mshta"),
    (r"\bwscript\b", "wscript"),
    (r"\bcscript\b", "cscript"),
    (r"\bregsvr32\b", "regsvr32"),
    (r"iis command line", "IIS command line"),
]

# Patrón combinado (para el flag booleano rápido y la clasificación MITRE).
SUSPICIOUS_PROCESS_PATTERN = re.compile(
    "(?:" + "|".join(pat for pat, _ in SUSPICIOUS_PROCESS_REGISTRY) + ")",
    re.IGNORECASE,
)

# Columnas adicionales (normalizadas) que pueden contener procesos/comandos.
# Se suman al texto de la fila además de description/rule/cve/process/status.
EXTRA_PROCESS_FIELDS: set[str] = {
    "datawineventdataimage",
    "wineventdataimage",
    "eventdataimage",
    "processname",
    "datawineventdataprocessname",
    "wineventdataprocessname",
    "datawineventdatacommandline",
    "wineventdatacommandline",
    "commandline",
    "datawineventdataparentprocessname",
    "wineventdataparentprocessname",
    "parentprocessname",
    "datawineventdataparentimage",
    "wineventdataparentimage",
    "parentimage",
    "datawinsystemmessage",
    "winsystemmessage",
    "fulllog",
}

# IDs de reglas Wazuh que ya indican procesos sospechosos por sí solos.
# La etiqueta es el fragmento legible que se muestra en el reporte.
SUSPICIOUS_RULE_IDS: dict[int, str] = {
    92058: "sdbinst.exe (regla Wazuh 92058)",
}

# Nivel de regla mínimo como indicador adicional de sospecha (combinado con
# la presencia de contenido de proceso en la fila).
SUSPICIOUS_RULE_LEVEL_BOOST = 12

# Rutas/patrones de ubicaciones inusuales para ejecutables.
SUSPICIOUS_PATH_PATTERN = re.compile(
    r"(?i)(?:appdata[\\/]local[\\/]temp|appdata[\\/]roaming|"
    r"\\temp[\\/]{1,2}|\bwindows[\\/]temp\b|"
    r"programdata[\\/].*temp|recycle|\.\.\\)"
)

# Heurística de parent elevando shell (p. ej. svchost.exe -> cmd.exe).
SUSPICIOUS_PARENT_PATTERN = re.compile(r"(?i)svchost\.exe|winlogon\.exe")
SUSPICIOUS_CHILD_PATTERN = re.compile(
    r"(?i)\bcmd\.exe\b|\bpowershell(?:\.exe)?\b|\bwscript\.exe\b|"
    r"\bcscript\.exe\b|\brundll32\b|\bmshta\b|\bregsvr32\b|"
    r"\bcertutil\b|\bwmic\b|\bbitsadmin\b"
)

# Credenciales / autenticación (fuerza bruta / cred stuffing).
CREDENTIALS_PATTERN = re.compile(
    r"(?:brute.?force|credential stuffing|password spraying|invalid password|"
    r"login failed|authentication failed|account locked|many login failures|"
    r"successful login|privileged login)",
    re.IGNORECASE,
)

# Exfiltración / transferencia de datos.
EXFILTRATION_PATTERN = re.compile(
    r"(?:exfiltrat|data exfil|upload to (?:external|remote|unknown)|"
    r"dns tunnel|base64 data|large outbound|sensitive data|"
    r"download of (?:database|credentials|backup)|theft)",
    re.IGNORECASE,
)

# Comando y control.
C2_PATTERN = re.compile(
    r"(?:c2|command & control|command and control|beacon|cobalt strike|"
    r"metasploit|reverse shell|meterpreter|dga|domain generation|"
    r"call.?back|tunneling|proxy pool|tor exit)",
    re.IGNORECASE,
)

# Persistencia.
PERSISTENCE_PATTERN = re.compile(
    r"(?:persistence|registry.*run|run.?key|startup folder|"
    r"schtasks /create|scheduled task created|new service|"
    r"services\.exe|explorer\.exe load|wmi event subscription|autorun)",
    re.IGNORECASE,
)

# Evasión de defensas.
EVASION_PATTERN = re.compile(
    r"(?:disable.*(?:defender|firewall|av|antivirus|security)|"
    r"stop.*(?:defender|firewall)|bypass|evasiv|clear.*(?:log|event)|"
    r"timestomp|masquerad|whitelist|exclusion|mimikatz.*sekurlsa|"
    r"amsi.?bypass|ppl.?dump|remove.*definitions)",
    re.IGNORECASE,
)

# Reconocimiento.
RECON_PATTERN = re.compile(
    r"(?:recon|reconnaiss|information gathering|osint|enrichment|"
    r"scanning|port.?scan|vulnerability scan|whois|traceroute|"
    r"credential access|harvest|phishing|dns.?recon)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Definiciones MITRE ATT&CK: técnica -> lista de palabras clave / patrones y
# reglas de Wazuh (rule.id) que activan la táctica (mapeo según documento
# oficial MITRE ATT&CK y los IDs observados en los CSVs de casos reales).
# ---------------------------------------------------------------------------
MITRE_TECHNIQUES: dict[str, dict] = {
    "Reconocimiento": {
        "tactic_id": "TA0043",
        "description": "Intento de reconocimiento o recopilación de información sobre los sistemas de la red.",
        "report_line": "Escaneos de puertos/directorios o fingerprinting detectados",
        "techniques": ["T1595 Active Scanning", "T1046 Network Service Discovery"],
        "patterns": [RECON_PATTERN],
        "rule_ids": [31151],
    },
    "Ejecución": {
        "tactic_id": "TA0002",
        "description": "Ejecución de código, comandos o scripts sospechosos en los hosts.",
        "report_line": "Ejecución de código, comandos o scripts sospechosos detectada",
        "techniques": ["T1059 Command and Scripting Interpreter",
                       "T1203 Client Execution (exploits/vulns aplicaciones)"],
        "patterns": [SUSPICIOUS_PROCESS_PATTERN, SCAN_PATTERN],
        "rule_ids": [23506],
    },
    "Persistencia": {
        "tactic_id": "TA0003",
        "description": "Mecanismos de persistencia: tareas programadas, servicios o claves de registro.",
        "report_line": "Mecanismos de persistencia detectados",
        "techniques": ["T1546.011 Event Triggered Execution: Application Shimming",
                       "T1547 Boot/Logon Autostart Execution",
                       "T1053 Scheduled Task/Job"],
        "patterns": [PERSISTENCE_PATTERN, SERVICE_CREATION_PATTERN],
        "rule_ids": [92058, 92213],
    },
    "Evasión de defensas": {
        "tactic_id": "TA0005",
        "description": "Técnicas para evadir/deshabilitar controles de seguridad.",
        "report_line": "Técnicas de evasión o deshabilitación de defensas detectadas",
        "techniques": ["T1562 Impair Defenses", "T1027 Obfuscated Files or Information"],
        "patterns": [EVASION_PATTERN],
        "rule_ids": [],
    },
    "Exfiltración": {
        "tactic_id": "TA0010",
        "description": "Posible transferencia o exfiltración de datos fuera de la red.",
        "report_line": "Posibles intentos de exfiltración de datos",
        "techniques": ["T1048 Exfiltration Over Alternative Protocol", "T1041 Exfiltration Over C2 Channel"],
        "patterns": [EXFILTRATION_PATTERN],
        "rule_ids": [],
    },
    "Comando y Control": {
        "tactic_id": "TA0011",
        "description": "Indicadores de comunicación con infraestructura de comando y control (C2).",
        "report_line": "Indicadores de comunicación con infraestructura de comando y control (C2) detectados",
        "techniques": ["T1071 Application Layer Protocol", "T1573 Encrypted Channel"],
        "patterns": [C2_PATTERN],
        "rule_ids": [],
    },
}

# ---------------------------------------------------------------------------
# Puertos relevantes para alinear IPs sospechosas (referencia para futuros usos).
# ---------------------------------------------------------------------------
SUSPICIOUS_PORTS = {22, 445, 3389, 1433, 3306, 5985, 5986}