"""Motor de análisis SOC migrado del motor original."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from collections import Counter

import pandas as pd
import numpy as np

# Patrones de detección (migrados de modules/config.py)
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

PRIVATE_IP_PATTERN = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SCAN_PATTERN = re.compile(
    r"\b(?:port scan|scanner|nmap|masscan|probe|network scan|sweep|"
    r"enumerat|brute.?force|authentication failure|multiple 404|"
    r"dir.?scan|directory.?scan|traversal|403 forbidden|"
    r"admin login|wordpress|phpmyadmin|/\.git|fuzzing|"
    r"escaneo|escaneos|escanear|directorios?|evadiendo|agresivo)\b",
    re.IGNORECASE,
)

SERVICE_CREATION_PATTERN = re.compile(
    r"\b(?:service created|service install|installed as a service|"
    r"create service|sc create|7045|new service|started service)\b",
    re.IGNORECASE,
)

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

SUSPICIOUS_PROCESS_PATTERN = re.compile(
    "(?:" + "|".join(pat for pat, _ in SUSPICIOUS_PROCESS_REGISTRY) + ")",
    re.IGNORECASE,
)

CREDENTIALS_PATTERN = re.compile(
    r"(?:brute.?force|credential stuffing|password spraying|invalid password|"
    r"login failed|authentication failed|account locked|many login failures|"
    r"successful login|privileged login)",
    re.IGNORECASE,
)

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def detect_suspicious_processes(df: pd.DataFrame) -> tuple:
    """Stub implementation - returns empty results."""
    import pandas as pd
    flags = pd.Series([False] * len(df), index=df.index)
    fragments = pd.Series([""] * len(df), index=df.index)
    df["proc_sospechoso"] = flags
    df["hallazgo_proceso"] = fragments
    return flags, fragments, []


TEXT_FIELDS = ("description", "rule", "cve", "process", "status")
IP_FIELDS = TEXT_FIELDS + ("src_ip", "dst_ip")


@dataclass
class AnalysisResult:
    total_events: int = 0
    critical_count: int = 0
    high_count: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)
    agents: list[str] = field(default_factory=list)
    top_agents: list[tuple[str, int]] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    internal_ips: list[str] = field(default_factory=list)
    external_ips: list[str] = field(default_factory=list)
    suspicious_processes: list[str] = field(default_factory=list)
    suspicious_events: int = 0
    scan_events: int = 0
    service_events: int = 0
    auth_events: int = 0
    scan_ips: list[dict[str, str]] = field(default_factory=list)
    ip_counts: dict[str, int] = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)
    df: pd.DataFrame | None = None
    risk_score_per_agent: dict[str, float] = field(default_factory=dict)
    overall_risk_score: float = 0.0
    trend_data: dict = field(default_factory=dict)
    iocs: dict = field(default_factory=dict)
    attack_sequences: dict = field(default_factory=dict)

    @property
    def agents_count(self) -> int:
        return len(self.agents)

    def calculate_agent_risk_scores(self):
        if self.total_events == 0 or not self.agents:
            self.risk_score_per_agent = {}
            return {}

        weights = {
            'critical': 10.0, 'high': 6.0, 'suspicious_process': 8.0,
            'service_event': 7.0, 'auth_event': 5.0, 'scan_event': 4.0, 'cve': 9.0
        }

        def asset_criticality(agent_name: str) -> float:
            name = agent_name.lower()
            if any(k in name for k in ['dc', 'domain', 'adfs', 'certsrv']): return 1.0
            if any(k in name for k in ['srv', 'sql', 'db', 'exchange', 'mail']): return 0.85
            if any(k in name for k in ['ws', 'workstation', 'work']): return 0.6
            return 0.7

        total_weighted = (
            self.critical_count * weights['critical'] + self.high_count * weights['high'] +
            self.suspicious_events * weights['suspicious_process'] +
            self.service_events * weights['service_event'] +
            self.auth_events * weights['auth_event'] +
            self.scan_events * weights['scan_event'] +
            len(self.cves) * weights['cve']
        )

        scores = {agent: 0.0 for agent in self.agents}
        if self.top_agents:
            total_top = sum(cnt for _, cnt in self.top_agents)
            if total_top > 0:
                for agent, count in self.top_agents:
                    if agent in scores:
                        proportion = count / total_top
                        criticidad = asset_criticality(agent)
                        agent_score = (total_weighted * proportion) * criticidad
                        scores[agent] = min(100.0, agent_score)
        else:
            base = min(100.0, total_weighted / max(len(self.agents), 1))
            for agent in self.agents:
                criticidad = asset_criticality(agent)
                scores[agent] = min(100.0, base * criticidad)

        self.risk_score_per_agent = {k: round(v, 1) for k, v in scores.items()}
        return self.risk_score_per_agent

    def calculate_overall_risk_score(self):
        if not self.risk_score_per_agent:
            self.calculate_agent_risk_scores()
        if self.risk_score_per_agent:
            avg = sum(self.risk_score_per_agent.values()) / len(self.risk_score_per_agent)
            self.overall_risk_score = round(min(100.0, max(0.0, avg)), 1)
        else:
            self.overall_risk_score = 0.0
        return self.overall_risk_score

    def update_trend_data(self, historical_baseline: list[dict]):
        if not historical_baseline:
            self.trend_data = {}
            return
        recent_days = historical_baseline[-3:]
        days_count = len(recent_days)
        if days_count == 0:
            self.trend_data = {}
            return
        avg_critical = sum(d.get('critical', 0) for d in recent_days) / days_count
        avg_high = sum(d.get('high', 0) for d in recent_days) / days_count
        avg_total = sum(d.get('total', 0) for d in recent_days) / days_count
        avg_agents = sum(d.get('agents', 0) for d in recent_days) / days_count

        def pct_change(current, average):
            if average == 0:
                return 0.0 if current == 0 else 100.0
            return ((current - average) / average) * 100

        self.trend_data = {
            'critical_avg': round(avg_critical, 1), 'high_avg': round(avg_high, 1),
            'total_avg': round(avg_total, 1), 'agents_avg': round(avg_agents, 1),
            'critical_change': round(((self.critical_count - avg_critical) / avg_critical * 100) if avg_critical else 0.0, 1),
            'high_change': round(((self.high_count - avg_high) / avg_high * 100) if avg_high else 0.0, 1),
            'total_change': round(((self.total_events - avg_total) / avg_total * 100) if avg_total else 0.0, 1),
            'agents_change': round(((len(self.agents) - avg_agents) / avg_agents * 100) if avg_agents else 0.0, 1),
        }

    def extract_iocs(self) -> dict:
        iocs = {'file_hashes': set(), 'domains': set(), 'urls': set()}
        if self.df is None or self.df.empty:
            return {k: [] for k in iocs}
        sha256_pat = re.compile(r'\b[a-fA-F0-9]{64}\b')
        md5_pat = re.compile(r'\b[a-fA-F0-9]{32}\b')
        domain_pat = re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+\b')
        url_pat = re.compile(r'https?://[^\s/$.?#].[^\s]*', re.IGNORECASE)
        ioc_fields = ['full_log', 'description', 'data.win.eventdata.data', 'data.win.eventdata.commandLine', 'data.url']
        for field in ioc_fields:
            if field in self.df.columns:
                for value in self.df[field].dropna().astype(str):
                    iocs['file_hashes'].update(sha256_pat.findall(value))
                    iocs['file_hashes'].update(md5_pat.findall(value))
                    for match in re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+\b').findall(value):
                        iocs['domains'].add(match[0] if isinstance(match, tuple) else match)
                    iocs['urls'].update(url_pat.findall(value))
        return {k: sorted(list(v)) for k, v in iocs.items()}

    def detect_attack_sequences(self, enriched_df=None) -> dict:
        df = enriched_df if enriched_df is not None else self.df
        if df is None or df.empty:
            return {}
        mitre_cols = [c for c in df.columns if c.startswith('mitre_')]
        if not mitre_cols:
            return {}
        phase_order = ["Reconocimiento", "Ejecución", "Persistencia", "Evasión de defensas", "Exfiltración", "Comando y Control"]
        slug_to_tactic = {
            'reconocimiento': 'Reconocimiento', 'ejecuci_n': 'Ejecución',
            'persistencia': 'Persistencia', 'evasi_n_de_defensas': 'Evasión de defensas',
            'exfiltraci_n': 'Exfiltración', 'comando_y_control': 'Comando y Control'
        }
        tactics_with_events = {}
        for col in mitre_cols:
            slug = col.replace('mitre_', '')
            tactic_name = slug_to_tactic.get(slug, slug.replace('_', ' ').title())
            count = int(df[col].sum())
            if count > 0:
                tactics_with_events[tactic_name] = count
        if not tactics_with_events:
            return {}
        detected_sequence = [t for t in phase_order if t in tactics_with_events]
        kill_chain_patterns = []
        if all(t in tactics_with_events for t in ['Reconocimiento', 'Persistencia', 'Exfiltración']):
            kill_chain_patterns.append({'name': 'Kill Chain Completa', 'sequence': ['Reconocimiento', 'Persistencia', 'Exfiltración'], 'counts': {t: tactics_with_events[t] for t in ['Reconocimiento', 'Persistencia', 'Exfiltración']}})
        if all(t in tactics_with_events for t in ['Reconocimiento', 'Ejecución', 'Persistencia']):
            kill_chain_patterns.append({'name': 'Recon → Ejecución → Persistencia', 'sequence': ['Reconocimiento', 'Ejecución', 'Persistencia'], 'counts': {t: tactics_with_events[t] for t in ['Reconocimiento', 'Ejecución', 'Persistencia']}})
        if all(t in tactics_with_events for t in ['Ejecución', 'Evasión de defensas', 'Comando y Control']):
            kill_chain_patterns.append({'name': 'Ejecución → Evasión → C2', 'sequence': ['Ejecución', 'Evasión de defensas', 'Comando y Control'], 'counts': {t: tactics_with_events[t] for t in ['Ejecución', 'Evasión de defensas', 'Comando y Control']}})
        if 'Reconocimiento' in tactics_with_events and 'Exfiltración' in tactics_with_events:
            kill_chain_patterns.append({'name': 'Reconocimiento → Exfiltración', 'sequence': ['Reconocimiento', 'Exfiltración'], 'counts': {t: tactics_with_events[t] for t in ['Reconocimiento', 'Exfiltración']}})
        return {'tactics_with_events': tactics_with_events, 'detected_sequence': detected_sequence, 'kill_chain_patterns': kill_chain_patterns, 'total_tactics': len(tactics_with_events)}


def _combine_text(row: pd.Series) -> str:
    parts = []
    for field in ("description", "rule", "cve", "process", "status"):
        value = row.get(field)
        if pd.notna(value):
            parts.append(str(value))
    return " ".join(parts)


def _combine_all_text(row: pd.Series) -> str:
    parts = []
    for field in ("description", "rule", "cve", "process", "status", "src_ip", "dst_ip"):
        value = row.get(field)
        if pd.notna(value):
            parts.append(str(value))
    return " ".join(parts)


def _extract_unique_matches(text_blobs: list[str], pattern: re.Pattern) -> list[str]:
    found, seen = [], set()
    for blob in text_blobs:
        for match in pattern.findall(blob):
            value = match[0] if isinstance(match, tuple) else match
            key = value.casefold()
            if key not in seen:
                seen.add(key)
                found.append(value)
    return found


_RELEVANT_PATTERNS = (
    re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE),
    re.compile(r"(?:powershell[^\r\n]{0,160}?(?:-enc\b|encodedcommand\b)|cmd\.exe[^\r\n]{0,120}?/c\b|rundll32[^\r\n]{0,120}?\.dll\b)", re.IGNORECASE),
    re.compile(r"(?:port scan|scanner|nmap|masscan|probe|network scan|sweep|enumerat|brute.?force|authentication failure|multiple 404|dir.?scan|directory.?scan|traversal|403 forbidden|admin login|wordpress|phpmyadmin|/\.git|fuzzing|escaneo|escaneos|escanear|directorios?|evadiendo|agresivo)", re.IGNORECASE),
    re.compile(r"(?:service created|service install|installed as a service|create service|sc create|7045|new service|started service)", re.IGNORECASE),
    re.compile(r"(?:brute.?force|credential stuffing|password spraying|invalid password|login failed|authentication failed|account locked|many login failures|successful login|privileged login)", re.IGNORECASE),
)


def _classify_ip_type(ip: str) -> str:
    if re.search(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", ip) or ip.split(".")[0] in {"0", "127", "169", "255"}:
        return "privada"
    return "publica"


def _extract_scan_ips(scan_rows: pd.DataFrame) -> list[dict[str, str]]:
    if scan_rows.empty:
        return []
    texts = scan_rows.apply(lambda r: " ".join(str(r.get(f, "")) for f in ("description", "rule", "cve", "process", "status", "src_ip", "dst_ip")), axis=1).tolist()
    IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    return [{"ip": ip, "tipo": "privada" if re.search(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", ip) or ip.split(".")[0] in {"0", "127", "169", "255"} else "publica"} for ip in set(sum([re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", t) for t in texts], []))]


def analyze(df: pd.DataFrame):
    result = AnalysisResult(df=df)
    if df.empty:
        return result

    result.total_events = len(df)
    severity = df["severity"]
    result.severity_counts = {level: int((severity == level).sum()) for level in ["Critical", "High", "Medium", "Low", "Unknown"]}
    result.critical_count = result.severity_counts.get("Critical", 0)
    result.high_count = result.severity_counts.get("High", 0)

    agents = df["agent"].replace("", pd.NA).dropna()
    if agents.empty and "src_ip" in df.columns:
        agents = df["src_ip"].replace("", pd.NA).dropna()
    result.agents = agents.drop_duplicates().astype(str).tolist()
    result.top_agents = list(agents.value_counts().head(10).items()) if not agents.empty else []

    texts = df.apply(lambda r: " ".join(str(r.get(f, "")) for f in ("description", "rule", "cve", "process", "status")), axis=1).tolist()
    full_text = "\n".join(t for t in texts if t)

    cve_pat = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
    result.cves = sorted(set().union(*[cve_pat.findall(t) for t in texts]))

    scan_pat = re.compile(r"(?:port scan|scanner|nmap|masscan|probe|network scan|sweep|enumerat|brute.?force|authentication failure|multiple 404|dir.?scan|directory.?scan|traversal|403 forbidden|admin login|wordpress|phpmyadmin|/\.git|fuzzing|escaneo|escaneos|escanear|directorios?|evadiendo|agresivo)", re.IGNORECASE)
    scan_rows = df[df.apply(lambda r: bool(re.search(r"(?:port scan|scanner|nmap|masscan|probe|network scan|sweep|enumerat|brute.?force|authentication failure|multiple 404|dir.?scan|directory.?scan|traversal|403 forbidden|admin login|wordpress|phpmyadmin|/\.git|fuzzing|escaneo|escaneos|escanear|directorios?|evadiendo|agresivo)", " ".join(str(r.get(f, "")) for f in ("description", "rule", "cve", "process", "status")), re.IGNORECASE)), axis=1)]
    result.scan_events = len(scan_rows)

    service_pat = re.compile(r"(?:service created|service install|installed as a service|create service|sc create|7045|new service|started service)", re.IGNORECASE)
    service_rows = df[df.apply(lambda r: bool(re.search(r"(?:service created|service install|installed as a service|create service|sc create|7045|new service|started service)", " ".join(str(r.get(f, "")) for f in ("description", "rule", "cve", "process", "status")), re.IGNORECASE)), axis=1)]
    result.service_events = len(service_rows)

    proc_flag, proc_fragment, proc_unique = detect_suspicious_processes(df)
    proc_rows = df.loc[proc_flag]
    result.suspicious_events = int(proc_flag.sum())
    result.suspicious_processes = proc_unique

    auth_pat = re.compile(r"(?:brute.?force|credential stuffing|password spraying|invalid password|login failed|authentication failed|account locked|many login failures|successful login|privileged login)", re.IGNORECASE)
    auth_rows = df[df.apply(lambda r: bool(re.search(r"(?:brute.?force|credential stuffing|password spraying|invalid password|login failed|authentication failed|account locked|many login failures|successful login|privileged login)", " ".join(str(r.get(f, "")) for f in ("description", "rule", "cve", "process", "status")), re.IGNORECASE)), axis=1)]
    result.auth_events = len(auth_rows)

    ip_texts = df.apply(lambda r: " ".join(str(r.get(f, "")) for f in ("description", "rule", "cve", "process", "status", "src_ip", "dst_ip")), axis=1).tolist()
    IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    PRIVATE_IP_PATTERN = re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    all_ips = sorted(set(sum([re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", t) for t in ip_texts], [])))
    internal, external = [], []
    active = proc_rows if not proc_rows.empty else df
    risky_text = "\n".join(active.apply(lambda r: " ".join(str(r.get(f, "")) for f in ("description", "rule", "cve", "process", "status", "src_ip", "dst_ip")), axis=1).tolist())
    for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", risky_text):
        if re.search(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", ip) or ip.split(".")[0] in {"0", "127", "169", "255"}:
            if ip not in internal: internal.append(ip)
        else:
            if ip not in external: external.append(ip)
    result.internal_ips = internal
    result.external_ips = external

    ip_counts = {}
    src_col = "src_ip" if "src_ip" in df.columns else None
    dst_col = "dst_ip" if "dst_ip" in df.columns else None
    for ip in internal + external:
        mask = pd.Series(False, index=df.index)
        if src_col is not None: mask |= df[src_col] == ip
        if dst_col is not None: mask |= df[dst_col] == ip
        ip_counts[ip] = int(mask.sum())
    result.ip_counts = ip_counts

    cve_pat = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
    result.cves = sorted(set().union(*[cve_pat.findall(t) for t in texts]))

    result.scan_ips = []

    suspicious_pat = re.compile(r"(?:powershell[^\r\n]{0,160}?(?:-enc\b|encodedcommand\b)|cmd\.exe[^\r\n]{0,120}?/c\b|rundll32[^\r\n]{0,120}?\.dll\b|\bmimikatz\b|\blsass\b|\bprocdump\b|\bmshta\b|\bwscript\b|\bcscript\b|\bregsvr32\b|\bcertutil\b|\bwmic\b|\bbitsadmin\b|\binvoke-command\b|\bwmiexec\b|\bpsexec\b|schtasks[ \t]+/create|-enc[ \t]+[a-z0-9+/=]{20,}|frombase64string|downloadstring|obfuscat|encoded command|\bwmi\b[^\r\n]{0,120}?process call create)", re.IGNORECASE)
    proc_flag = df.apply(lambda r: bool(suspicious_pat.search(" ".join(str(r.get(f, "")) for f in ("description", "rule", "cve", "process", "status")))), axis=1)
    result.suspicious_events = int(proc_flag.sum())
    result.suspicious_processes = sorted(set(sum([re.findall(r"(?:powershell|cmd\.exe|rundll32|mimikatz|lsass|procdump|mshta|wscript|cscript|regsvr32|certutil|wmic|bitsadmin|invoke-command|wmiexec|psexec|schtasks|certutil|mimikatz|lsass|procdump|mshta|wscript|cscript|regsvr32|wmic|bitsadmin|wmiexec|psexec|schtasks)", t, re.IGNORECASE) for t in df.apply(lambda r: " ".join(str(r.get(f, "")) for f in ("description", "rule", "cve", "process", "status")), axis=1).tolist()], [])))

    auth_pat = re.compile(r"(?:brute.?force|credential stuffing|password spraying|invalid password|login failed|authentication failed|account locked|many login failures|successful login|privileged login)", re.IGNORECASE)
    auth_rows = df[df.apply(lambda r: bool(auth_pat.search(" ".join(str(r.get(f, "")) for f in ("description", "rule", "cve", "process", "status")))), axis=1)]
    result.auth_events = len(auth_rows)

    severity = df["severity"]
    severity_order = ["Critical", "High", "Medium", "Low", "Unknown"]
    severity_counts = {level: int((severity == level).sum()) for level in ["Critical", "High", "Medium", "Low", "Unknown"]}

    agents = df["agent"].replace("", pd.NA).dropna()
    if agents.empty and "src_ip" in df.columns:
        agents = df["src_ip"].replace("", pd.NA).dropna()
    agents_list = agents.drop_duplicates().astype(str).tolist()
    top_agents = list(agents.value_counts().head(10).items()) if not agents.empty else []

    # Use the module-level AnalysisResult class
    result.cves = sorted(set().union(*[cve_pat.findall(t) for t in texts]))
    result.internal_ips = internal
    result.external_ips = external
    result.suspicious_processes = sorted(set(sum([re.findall(r"(?:powershell|cmd\.exe|rundll32|mimikatz|lsass|procdump|mshta|wscript|cscript|regsvr32|certutil|wmic|bitsadmin|invoke-command|wmiexec|psexec|schtasks|certutil|mimikatz|lsass|procdump|mshta|wscript|cscript|regsvr32|wmic|bitsadmin|wmiexec|psexec|schtasks)", t, re.IGNORECASE) for t in texts], [])))
    result.suspicious_events = int(proc_flag.sum())
    result.scan_events = len(scan_rows)
    result.service_events = len(service_rows)
    result.auth_events = len(auth_rows)
    result.scan_ips = []
    result.ip_counts = ip_counts
    result.findings = []
    result.df = df
    result.risk_score_per_agent = {}
    result.overall_risk_score = 0.0
    result.trend_data = {}
    result.iocs = {}
    result.attack_sequences = {}
    return result