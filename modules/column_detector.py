"""Detección flexible de columnas en el CSV cargado.

Soporta dos formatos:

1. Nombres punteados de exportaciones Wazuh/Kibana/OpenSearch:
   'rule.level', 'agent.name', 'rule.description', 'data.srcip',
   'data.win.eventdata.image', 'data.win.eventdata.targetUserName', etc.
2. Alias genéricos en inglés/español:
   Severity/Severidad, Host/Agente, Description/Mensaje, Origen/Destino,
   CVE, Proceso, Estado, Timestamp/Fecha.

La prioridad garantiza que 'rule.level' sea SIEMPRE la fuente de severidad,
aunque el archivo también traiga una columna 'severity'.
"""
from __future__ import annotations

import unicodedata

from modules.config import COLUMN_ALIASES

# Reglas de prioridad para nombres punteados/sufijos (exportaciones Wazuh).
# (campo_canónico, clave_normalizada_que_lo_identifica)
DOTTED_RULES: list[tuple[str, str]] = [
    ("severity", "rulelevel"),          # rule.level
    ("agent", "agentname"),             # agent.name
    ("agent", "agenthostname"),         # agent.hostname
    ("agent", "agentid"),               # agent.id (solo como respaldo)
    ("user", "datawineventdatatargetusername"),  # data.win.eventdata.targetUserName
    ("user", "wineventdatatargetusername"),
    ("user", "targetusername"),
    ("user", "username"),
    ("user", "actoruser"),
    ("user", "principal"),
    ("description", "ruledescription"), # rule.description
    ("description", "rulemessage"),     # rule.message
    ("description", "datawinsystemmessage"),  # data.win.system.message
    ("description", "winsystemmessage"),
    ("description", "fulllog"),         # full_log
    ("src_ip", "datasrcip"),            # data.srcip
    ("src_ip", "agentip"),              # agent.ip
    ("src_ip", "iporigen"),             # ip_origen
    ("src_ip", "sourceip"),
    ("dst_ip", "datadstip"),            # data.dstip
    ("dst_ip", "ipdestino"),
    ("dst_ip", "destinationip"),
    ("process", "datawineventdataimage"),      # data.win.eventdata.image
    ("process", "wineventdataimage"),
    ("process", "eventdataimage"),
    ("process", "processname"),
    ("timestamp", "marcatiempo"),
    ("timestamp", "fechahora"),
]


def normalize(name: str) -> str:
    """Normaliza un nombre de columna para comparaciones.

    - Convierte a minúsculas.
    - Elimina acentos y diacríticos.
    - Elimina espacios, guiones, puntos y cualquier símbolo no alfanumérico.
    """
    text = unicodedata.normalize("NFKD", str(name))
    text = "".join(c for c in text if not unicodedata.combining(c))
    return "".join(c for c in text.lower() if c.isalnum())


def detect_columns(columns: list[str]) -> dict[str, str]:
    """Detecta las columnas relevantes del CSV.

    Parámetro
    ---------
    columns : lista de nombres de columna del CSV.

    Devuelve
    --------
    dict : mapeo {campo_canonico: nombre_real_de_columna}. Solo se incluyen los
           campos que pudieron ser detectados.
    """
    detected: dict[str, str] = {}
    norm = {normalize(c): c for c in columns}

    def take(canonical: str, key: str) -> None:
        if key in norm and canonical not in detected:
            detected[canonical] = norm[key]

    # 1) Nombres punteados/sufijos de exportaciones Wazuh (prioridad explícita).
    for canonical, key in DOTTED_RULES:
        take(canonical, key)

    # 2) Alias genéricos exactos (inglés/español) para lo no resuelto.
    for canonical, aliases in COLUMN_ALIASES.items():
        if canonical in detected:
            continue
        for alias in aliases:
            if alias in norm:
                detected[canonical] = norm[alias]
                break

    return detected