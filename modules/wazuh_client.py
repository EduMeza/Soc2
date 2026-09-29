"""Cliente básico para consultas al Indexer Wazuh / OpenSearch.

Este módulo actúa como stub funcional: si no hay servidor Wazuh disponible,
retorna datos vacíos o de demo sin interrumpir el flujo del dashboard.
"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Campos mínimos esperados desde el Indexer
INDEX_FIELDS = [
    "rule.id", "rule.level", "rule.description", "agent.name",
    "agent.id", "rule.mitre.id", "rule.mitre.tactic",
    "data.srcip", "data.dstip", "data.url", "data.win.eventdata.commandLine"
]


class WazuhIndexerClient:
    """Cliente simplificado para consultar eventos en ventana de turno."""

    def __init__(self, host: str = "localhost", port: int = 9200, auth: tuple | None = None):
        self.host = host
        self.port = port
        self.auth = auth or ("admin", "admin")
        self._available = False

    def test_connection(self) -> bool:
        try:
            import urllib.request
            req = urllib.request.Request(
                f"http://{self.host}:{self.port}/_cluster/health",
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                self._available = resp.status == 200
        except Exception:
            self._available = False
        return self._available

    def fetch_window(
        self,
        start_dt: str,
        end_dt: str,
        index_pattern: str = "wazuh-alerts-*",
        size: int = 500,
    ) -> list[dict]:
        """Devuelve lista de eventos en la ventana (demo si no hay conexión)."""
        if not self._available:
            self.test_connection()
        if not self._available:
            logger.info("Wazuh indexer no disponible; devolviendo ventana vacía.")
            return []

        try:
            import requests
            url = f"http://{self.host}:{self.port}/{index_pattern}/_search"
            body = {
                "size": size,
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": start_dt,
                            "lte": end_dt,
                        }
                    }
                },
                "_source": INDEX_FIELDS,
            }
            resp = requests.get(url, json=body, auth=self.auth, timeout=15, verify=False)
            hits = resp.json().get("hits", {}).get("hits", [])
            return [h.get("_source", {}) for h in hits]
        except Exception as exc:
            logger.warning("Error consultando Wazuh: %s", exc)
            return []
