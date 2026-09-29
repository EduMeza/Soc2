"""Análisis automático del CSV de eventos de seguridad.

Calcula los conteos de severidad, agentes afectados, hallazgos relevantes
(CVEs, escaneos, creación de servicios, IPs sospechosas, procesos) y deja el
DataFrame enriquecido con marcas para la clasificación MITRE ATT&CK.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import pandas as pd

from modules.config import (
    CVE_PATTERN,
    IP_PATTERN,
    PRIVATE_IP_PATTERN,
    SCAN_PATTERN,
    SERVICE_CREATION_PATTERN,
    SEVERITY_ORDER,
    SUSPICIOUS_PROCESS_PATTERN,
    CREDENTIALS_PATTERN,
)
from modules.process_analysis import detect_suspicious_processes

# Columnas de interés usadas como texto para el análisis.
TEXT_FIELDS = ("description", "rule", "cve", "process", "status")

# Columnas adicionales que pueden contener direcciones IP.
IP_FIELDS = TEXT_FIELDS + ("src_ip", "dst_ip")


@dataclass
class AnalysisResult:
    """Resultado del análisis de eventos."""

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
        """Calcula un score de riesgo 0-100 para cada agente/activo.
        Pondera severidad de eventos, tipo de amenaza y criticidad del activo.
        """
        if self.total_events == 0 or not self.agents:
            self.risk_score_per_agent = {}
            return {}

        # Pesos por tipo de evento (ajustables por fase)
        weights = {
            'critical': 10.0,
            'high': 6.0,
            'suspicious_process': 8.0,
            'service_event': 7.0,
            'auth_event': 5.0,
            'scan_event': 4.0,
            'cve': 9.0
        }

        # Criticidad del activo basada en el nombre del agente
        def asset_criticality(agent_name: str) -> float:
            name = agent_name.lower()
            if any(k in name for k in ['dc', 'domain', 'adfs', 'certsrv']):
                return 1.0
            if any(k in name for k in ['srv', 'sql', 'db', 'exchange', 'mail']):
                return 0.85
            if any(k in name for k in ['ws', 'workstation', 'work']):
                return 0.6
            return 0.7  # Default neutral

        # Cálculo base por agente (simplificado: se reparte el score según eventos)
        total_weighted = (
            self.critical_count * weights['critical'] +
            self.high_count * weights['high'] +
            self.suspicious_events * weights['suspicious_process'] +
            self.service_events * weights['service_event'] +
            self.auth_events * weights['auth_event'] +
            self.scan_events * weights['scan_event'] +
            len(self.cves) * weights['cve']
        )

        # Distribuir score según actividad del agente (usar top_agents)
        scores = {agent: 0.0 for agent in self.agents}

        if self.top_agents:
            total_top = sum(cnt for _, cnt in self.top_agents)
            if total_top > 0:
                for agent, count in self.top_agents:
                    if agent in scores:
                        proportion = count / total_top
                        criticidad = asset_criticality(agent)
                        # Score base proporcional + bonus por criticidad
                        agent_score = (total_weighted * proportion) * criticidad
                        scores[agent] = min(100.0, agent_score)
        else:
            # Sin top_agents, repartir uniformemente
            base = min(100.0, total_weighted / max(len(self.agents), 1))
            for agent in self.agents:
                criticidad = asset_criticality(agent)
                scores[agent] = min(100.0, base * criticidad)

        self.risk_score_per_agent = {k: round(v, 1) for k, v in scores.items()}
        return self.risk_score_per_agent

    def calculate_overall_risk_score(self):
        """Calcula el score de riesgo general como promedio ponderado de agentes."""
        if not self.risk_score_per_agent:
            self.calculate_agent_risk_scores()

        if self.risk_score_per_agent:
            avg = sum(self.risk_score_per_agent.values()) / len(self.risk_score_per_agent)
            self.overall_risk_score = round(min(100.0, max(0.0, avg)), 1)
        else:
            self.overall_risk_score = 0.0

        return self.overall_risk_score

    def update_trend_data(self, historical_baseline: list[dict]):
        """Actualiza los datos de tendencia comparando con promedio de ultimos 3 dias.

        Args:
            historical_baseline: lista de dicts con metricas diarias
                [{'date': str, 'critical': int, ...}, ...]
        """
        if not historical_baseline or len(historical_baseline) == 0:
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
            'critical_avg': round(avg_critical, 1),
            'high_avg': round(avg_high, 1),
            'total_avg': round(avg_total, 1),
            'agents_avg': round(avg_agents, 1),
            'critical_change': round(pct_change(self.critical_count, avg_critical), 1),
            'high_change': round(pct_change(self.high_count, avg_high), 1),
            'total_change': round(pct_change(self.total_events, avg_total), 1),
            'agents_change': round(pct_change(len(self.agents), avg_agents), 1)
        }

    def extract_iocs(self) -> dict:
        """Extrae Indicadores de Compromiso (IOCs) del lote analizado.

        Returns:
            dict con listas de hashes, dominios y URLs unicas
        """
        iocs = {'file_hashes': set(), 'domains': set(), 'urls': set()}

        if self.df is None or self.df.empty:
            return {k: [] for k in iocs}

        sha256_pat = re.compile(r'\b[a-fA-F0-9]{64}\b')
        md5_pat = re.compile(r'\b[a-fA-F0-9]{32}\b')
        domain_pat = re.compile(
            r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
            r'(\.[a-zA-Z]{2,})+\b'
        )
        url_pat = re.compile(
            r'https?://[^\s/$.?#].[^\s]*',
            re.IGNORECASE
        )

        ioc_fields = ['full_log', 'description', 'data.win.eventdata.data',
                      'data.win.eventdata.commandLine', 'data.url']

        for field in ioc_fields:
            if field in self.df.columns:
                for value in self.df[field].dropna().astype(str):
                    iocs['file_hashes'].update(sha256_pat.findall(value))
                    iocs['file_hashes'].update(md5_pat.findall(value))
                    # handle domain matches which may be tuples due to capturing groups
                    for match in domain_pat.findall(value):
                        if isinstance(match, tuple):
                            iocs['domains'].add(match[0])  # take the first group
                        else:
                            iocs['domains'].add(match)
                    iocs['urls'].update(url_pat.findall(value))

        return {
            'file_hashes': sorted(list(iocs['file_hashes'])),
            'domains': sorted(list(iocs['domains'])),
            'urls': sorted(list(iocs['urls']))
        }

    def detect_attack_sequences(self, enriched_df=None) -> dict:
        """Detecta secuencias de ataque multi-fase basadas en tácticas MITRE.
        
        Args:
            enriched_df: DataFrame enriquecido con columnas mitre_* (opcional, usa self.df si no se proporciona)
        
        Returns:
            dict con fases detectadas y su secuencia (ej. Reconocimiento -> Persistencia -> Exfiltración)
        """
        df = enriched_df if enriched_df is not None else self.df
        if df is None or df.empty:
            return {}
        
        # Mapear eventos a tácticas MITRE usando las columnas mitre_*
        # Las columnas mitre_* se añaden durante la clasificación
        mitre_cols = [c for c in df.columns if c.startswith('mitre_')]
        if not mitre_cols:
            return {}
        
        # Definir orden de fases del ataque (kill chain simplificado)
        phase_order = [
            "Reconocimiento",
            "Ejecución", 
            "Persistencia",
            "Evasión de defensas",
            "Exfiltración",
            "Comando y Control"
        ]
        
        # Mapeo de slug a nombre canónico (basado en la función _slug de mitre.py)
        slug_to_tactic = {
            'reconocimiento': 'Reconocimiento',
            'ejecuci_n': 'Ejecución', 
            'persistencia': 'Persistencia',
            'evasi_n_de_defensas': 'Evasión de defensas',
            'exfiltraci_n': 'Exfiltración',
            'comando_y_control': 'Comando y Control'
        }
        
        # Detectar qué tácticas tienen eventos
        tactics_with_events = {}
        for col in mitre_cols:
            slug = col.replace('mitre_', '')
            tactic_name = slug_to_tactic.get(slug, slug.replace('_', ' ').title())
            
            count = int(df[col].sum())
            if count > 0:
                tactics_with_events[tactic_name] = count
        
        if not tactics_with_events:
            return {}
        
        # Construir secuencia detectada
        detected_sequence = [t for t in phase_order if t in tactics_with_events]
        
        # Identificar patrones de kill chain comunes
        kill_chain_patterns = []
        
        # Patrón 1: Reconocimiento -> Persistencia -> Exfiltración
        if all(t in tactics_with_events for t in ['Reconocimiento', 'Persistencia', 'Exfiltración']):
            kill_chain_patterns.append({
                'name': 'Kill Chain Completa (Recon → Persistencia → Exfiltración)',
                'sequence': ['Reconocimiento', 'Persistencia', 'Exfiltración'],
                'counts': {t: tactics_with_events[t] for t in ['Reconocimiento', 'Persistencia', 'Exfiltración']}
            })
        
        # Patrón 2: Reconocimiento -> Ejecución -> Persistencia
        if all(t in tactics_with_events for t in ['Reconocimiento', 'Ejecución', 'Persistencia']):
            kill_chain_patterns.append({
                'name': 'Recon → Ejecución → Persistencia',
                'sequence': ['Reconocimiento', 'Ejecución', 'Persistencia'],
                'counts': {t: tactics_with_events[t] for t in ['Reconocimiento', 'Ejecución', 'Persistencia']}
            })
        
        # Patrón 3: Ejecución -> Evasión -> C2
        if all(t in tactics_with_events for t in ['Ejecución', 'Evasión de defensas', 'Comando y Control']):
            kill_chain_patterns.append({
                'name': 'Ejecución → Evasión → C2',
                'sequence': ['Ejecución', 'Evasión de defensas', 'Comando y Control'],
                'counts': {t: tactics_with_events[t] for t in ['Ejecución', 'Evasión de defensas', 'Comando y Control']}
            })
        
        # Patrón 4: Reconocimiento -> Exfiltración (exfiltración rápida)
        if 'Reconocimiento' in tactics_with_events and 'Exfiltración' in tactics_with_events:
            kill_chain_patterns.append({
                'name': 'Reconocimiento → Exfiltración (exfiltración rápida)',
                'sequence': ['Reconocimiento', 'Exfiltración'],
                'counts': {t: tactics_with_events[t] for t in ['Reconocimiento', 'Exfiltración']}
            })
        
        return {
            'tactics_with_events': tactics_with_events,
            'detected_sequence': detected_sequence,
            'kill_chain_patterns': kill_chain_patterns,
            'total_tactics': len(tactics_with_events)
        }


def _combine_text(row: pd.Series) -> str:
    """Une el texto de las columnas relevantes de una fila."""
    parts = []
    for field in TEXT_FIELDS:
        value = row.get(field)
        if pd.notna(value):
            parts.append(str(value))
    return " ".join(parts)


def _combine_all_text(row: pd.Series) -> str:
    """Une todas las columnas de la fila (para detección de IPs)."""
    parts = []
    for field in IP_FIELDS:
        value = row.get(field)
        if pd.notna(value):
            parts.append(str(value))
    return " ".join(parts)


def _extract_unique_matches(text_blobs: list[str], pattern: re.Pattern) -> list[str]:
    """Extrae coincidencias únicas (orden de aparición) de una lista de textos."""
    found: list[str] = []
    seen: set[str] = set()
    for blob in text_blobs:
        for match in pattern.findall(blob):
            value = match[0] if isinstance(match, tuple) else match
            key = value.casefold()
            if key not in seen:
                seen.add(key)
                found.append(value)
    return found


# Patrones que marcan un evento como "relevante" (para la tabla de hallazgos).
_RELEVANT_PATTERNS = (
    CVE_PATTERN,
    SUSPICIOUS_PROCESS_PATTERN,
    SCAN_PATTERN,
    SERVICE_CREATION_PATTERN,
    CREDENTIALS_PATTERN,
)


def _classify_ip_type(ip: str) -> str:
    """Clasifica una IP como 'privada' o 'publica'."""
    if PRIVATE_IP_PATTERN.search(ip) or ip.split(".")[0] in {"0", "127", "169", "255"}:
        return "privada"
    return "publica"


def _extract_scan_ips(scan_rows: pd.DataFrame) -> list[dict[str, str]]:
    """Devuelve las IPs de los eventos de escaneo con su clasificación."""
    if scan_rows.empty:
        return []
    texts = scan_rows.apply(_combine_all_text, axis=1).tolist()
    return [
        {"ip": ip, "tipo": _classify_ip_type(ip)}
        for ip in _extract_unique_matches(texts, IP_PATTERN)
    ]


def relevant_events(df: pd.DataFrame) -> pd.DataFrame:
    """Devuelve las filas con hallazgos relevantes (CVE, escaneo, servicios,
    credenciales o procesos sospechosos)."""
    text = df.apply(_combine_text, axis=1)
    mask = pd.Series(False, index=df.index)
    for pattern in _RELEVANT_PATTERNS:
        mask |= text.str.contains(pattern.pattern, regex=True, na=False)
    if "proc_sospechoso" in df.columns:
        mask |= df["proc_sospechoso"].fillna(False).astype(bool)
    return df[mask]


def analyze(df: pd.DataFrame) -> AnalysisResult:
    """Realiza el análisis completo sobre un DataFrame normalizado."""
    result = AnalysisResult(df=df)
    if df.empty:
        return result

    result.total_events = len(df)
    severity = df["severity"]
    result.severity_counts = {
        level: int((severity == level).sum()) for level in SEVERITY_ORDER
    }
    result.severity_counts["Unknown"] = int((severity == "Unknown").sum())
    result.critical_count = result.severity_counts.get("Critical", 0)
    result.high_count = result.severity_counts.get("High", 0)

    # Agentes / hosts afectados únicos. Si no existe columna de nombre, se usan
    # las IPs como identificador de host (p. ej. CSVs con 'agent.ip').
    agents = df["agent"].replace("", pd.NA).dropna()
    if agents.empty and "src_ip" in df.columns:
        agents = df["src_ip"].replace("", pd.NA).dropna()
    result.agents = agents.drop_duplicates().astype(str).tolist()
    result.top_agents = (
        list(agents.value_counts().head(10).items())
        if not agents.empty
        else []
    )

    # Textos consolidados por fila para minimizar la sobrecarga de regex.
    texts = df.apply(_combine_text, axis=1).tolist()
    full_text = "\n".join(t for t in texts if t)

    # CVEs.
    result.cves = _extract_unique_matches(texts, CVE_PATTERN)

    # Escaneo / enumeración.
    scan_rows = df[df.apply(lambda r: bool(SCAN_PATTERN.search(_combine_text(r))), axis=1)]
    result.scan_events = len(scan_rows)
    result.scan_ips = _extract_scan_ips(scan_rows)

    # Creación de servicios.
    service_rows = df[df.apply(lambda r: bool(SERVICE_CREATION_PATTERN.search(_combine_text(r))), axis=1)]
    result.service_events = len(service_rows)

    # Procesos sospechosos (motor multicanal: regex + rule.id + rule.level +
    # heurísticas). Añade 'proc_sospechoso' y 'hallazgo_proceso' a df.
    proc_flag, proc_fragment, proc_unique = detect_suspicious_processes(df)
    proc_rows = df.loc[proc_flag]
    result.suspicious_events = int(proc_flag.sum())
    result.suspicious_processes = proc_unique

    # Intento de autenticación / credenciales.
    auth_rows = df[df.apply(lambda r: bool(CREDENTIALS_PATTERN.search(_combine_text(r))), axis=1)]
    result.auth_events = len(auth_rows)

    # IPs: internas y externas sospechosas (las que aparecen en eventos de alto interés).
    ip_texts = df.apply(_combine_all_text, axis=1).tolist()
    all_ips = _extract_unique_matches(ip_texts, IP_PATTERN)
    internal, external = [], []
    active = proc_rows if not proc_rows.empty else df
    risky_text = "\n".join(active.apply(_combine_all_text, axis=1).tolist())
    for ip in _extract_unique_matches([risky_text], IP_PATTERN):
        if PRIVATE_IP_PATTERN.search(ip) or ip.split(".")[0] in {"0", "127", "169", "255"}:
            if ip not in internal:
                internal.append(ip)
        else:
            if ip not in external:
                external.append(ip)
    result.internal_ips = internal
    result.external_ips = external

    # Conteo de eventos por IP relevante (filas con la IP en src/dst).
    ip_counts: dict[str, int] = {}
    src_col = "src_ip" if "src_ip" in df.columns else None
    dst_col = "dst_ip" if "dst_ip" in df.columns else None
    for ip in internal + external:
        mask = pd.Series(False, index=df.index)
        if src_col is not None:
            mask |= df[src_col] == ip
        if dst_col is not None:
            mask |= df[dst_col] == ip
        ip_counts[ip] = int(mask.sum())
    result.ip_counts = ip_counts

    # Hallazgos legibles para el reporte.
    findings = build_findings(result, cves=result.cves)
    result.findings = findings

    # CALCULAR MÉTRICAS DE RIESGO Y TENDENCIAS
    result.calculate_agent_risk_scores()
    result.calculate_overall_risk_score()

    # EXTRAER IOCs
    result.iocs = result.extract_iocs()

    return result


def build_findings(result: AnalysisResult, cves: list[str], limit: int = 6) -> list[str]:
    """Construye las líneas legibles de hallazgos relevantes para el reporte.

    Prioriza: CVEs, procesos sospechosos, escaneos, creación de servicios,
    intentos de autenticación e IPs sospechosas.
    """
    lines: list[str] = []

    if cves:
        rendered = ", ".join(cves[:6])
        lines.append(f"CVEs identificados: {rendered}")

    if result.suspicious_processes:
        rendered = ", ".join(result.suspicious_processes[:5])
        lines.append(f"Procesos/comandos sospechosos: {rendered}")

    if result.scan_events:
        subj = "eventos" if result.scan_events != 1 else "evento"
        verb = "detectados" if result.scan_events != 1 else "detectado"
        lines.append(f"{result.scan_events} {subj} de escaneo/enumeración {verb}")

    if result.service_events:
        subj = "eventos" if result.service_events != 1 else "evento"
        verb = "detectados" if result.service_events != 1 else "detectado"
        lines.append(f"{result.service_events} {subj} de creación/instalación de servicios {verb}")

    if result.auth_events:
        subj = "eventos" if result.auth_events != 1 else "evento"
        verb = "detectados" if result.auth_events != 1 else "detectado"
        lines.append(f"{result.auth_events} {subj} de autenticación/credenciales sospechosas {verb}")

    if result.internal_ips:
        lines.append("IPs internas relevantes: " + ", ".join(result.internal_ips[:5]))

    if result.external_ips:
        lines.append("IPs externas sospechosas: " + ", ".join(result.external_ips[:5]))

    return lines[:limit] if not cves else lines