"""Servicio GeoIP offline-first con caché local."""
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Any
from functools import lru_cache
from collections import Counter


CACHE_FILE = Path("data/geoip_cache.json")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PRIVATE_IP_PATTERN = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)

OFFLINE_GEO_DB = {
    "8.8.8.8": {"country": "United States", "country_code": "US", "region": "California", "city": "Mountain View", "latitude": 37.4056, "longitude": -122.0775, "asn": "15169", "isp": "Google LLC"},
    "1.1.1.1": {"country": "United States", "country_code": "US", "region": "California", "city": "San Francisco", "latitude": 37.751, "longitude": -122.4, "asn": "13335", "isp": "Cloudflare"},
    "8.8.4.4": {"country": "United States", "country_code": "US", "region": "California", "city": "Mountain View", "latitude": 37.4056, "longitude": -122.0775, "asn": "15169", "isp": "Google LLC"},
    "1.0.0.1": {"country": "United States", "country_code": "US", "region": "California", "city": "San Francisco", "latitude": 37.751, "longitude": -122.4, "asn": "13335", "isp": "Cloudflare"},
    "208.67.222.222": {"country": "United States", "country_code": "US", "region": "California", "city": "San Francisco", "latitude": 37.751, "longitude": -122.4, "asn": "6724", "isp": "OpenDNS"},
    "208.67.220.220": {"country": "United States", "country_code": "US", "region": "California", "city": "San Francisco", "latitude": 37.751, "longitude": -122.4, "asn": "6724", "isp": "OpenDNS"},
    "9.9.9.9": {"country": "United States", "country_code": "US", "region": "California", "city": "San Francisco", "latitude": 37.751, "longitude": -122.4, "asn": "13335", "isp": "Quad9"},
}


def load_cache() -> dict[str, dict]:
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_cache(cache: dict):
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


def is_private_ip(ip: str) -> bool:
    if not ip:
        return True
    return bool(PRIVATE_IP_PATTERN.match(ip))


def is_reserved_ip(ip: str) -> bool:
    """Check if IP is in reserved/documentation ranges."""
    reserved_prefixes = ["203.0.113.", "198.51.100.", "192.0.2."]
    return any(ip.startswith(p) for p in reserved_prefixes)


@lru_cache(maxsize=1024)
def resolve_geoip(ip: str) -> dict:
    """Resuelve geolocalización de una IP. Offline-first con caché."""
    if not ip or is_private_ip(ip):
        return {
            "ip": ip,
            "country": "Local/Private",
            "country_code": "XX",
            "region": "Private Network",
            "city": "Private",
            "latitude": None,
            "longitude": None,
            "asn": None,
            "isp": "Private Network",
            "source": "offline",
        }

    if is_reserved_ip(ip):
        return {
            "ip": ip,
            "country": "Reserved (TEST-NET)",
            "country_code": "XX",
            "region": "Documentation",
            "city": "Documentation",
            "latitude": None,
            "longitude": None,
            "asn": None,
            "isp": "IANA Reserved",
            "source": "offline_db",
        }

    # Check cache first
    cache = load_cache()
    if ip in cache:
        cached = cache[ip].copy()
        cached["source"] = "cache"
        return cached

    # Check offline database (exact matches)
    if ip in OFFLINE_GEO_DB:
        result = {"ip": ip, **OFFLINE_GEO_DB[ip], "source": "offline_db"}
        cache[ip] = result
        save_cache(cache)
        return result

    # Fallback: no coordinates invented
    result = {
        "ip": ip,
        "country": "Unknown",
        "country_code": "XX",
        "region": "Unknown",
        "city": "Unknown",
        "latitude": None,
        "longitude": None,
        "asn": None,
        "isp": "Unknown",
        "source": "unknown",
    }
    # Cache the result
    cache = load_cache()
    cache[ip] = result
    save_cache(cache)
    return result


def get_geoip_for_events(events: list[dict]) -> list[dict]:
    """Resuelve GeoIP para lista de eventos con IPs.
    
    Returns only IPs with valid coordinates (latitude != None, longitude != None).
    """
    ip_counter: Counter = Counter()
    
    # Extract all IPs from events
    for e in events:
        for field in ("src_ip", "dst_ip", "source_ip", "destination_ip"):
            ip = e.get(field)
            if ip and ip.strip() and not is_private_ip(ip) and not is_reserved_ip(ip):
                ip_counter[ip.strip()] += 1
    
    results = []
    for ip, count in ip_counter.most_common():
        geo = resolve_geoip(ip)
        if geo.get("latitude") is not None and geo.get("longitude") is not None:
            # Determine severity based on events with this IP
            severity = "Low"
            ip_events = [e for e in events if e.get("src_ip") == ip or e.get("dst_ip") == ip]
            for e in ip_events:
                sev = (e.get("severity") or "").lower()
                if sev == "critical":
                    severity = "Critical"
                    break
                elif sev == "high" and severity != "Critical":
                    severity = "High"
                elif sev == "medium" and severity not in ("Critical", "High"):
                    severity = "Medium"
            
            results.append({
                "ip": ip,
                "country": geo.get("country", "Unknown"),
                "country_code": geo.get("country_code", "XX"),
                "region": geo.get("region", "Unknown"),
                "city": geo.get("city", "Unknown"),
                "latitude": geo.get("latitude"),
                "longitude": geo.get("longitude"),
                "asn": geo.get("asn"),
                "isp": geo.get("isp"),
                "event_count": count,
                "severity": severity,
            })
    
    return results