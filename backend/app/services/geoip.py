"""Only validated cached coordinates; unknown addresses remain unlocated."""
import json
import ipaddress
from collections import Counter
from app.core.config import DATA_DIR

CACHE_FILE = DATA_DIR / 'geoip_cache.json'

def is_public(ip):
    try:
        address = ipaddress.ip_address(ip)
        return address.is_global and not any([address.is_multicast,address.is_reserved,address.is_loopback,address.is_link_local])
    except ValueError:
        return False

def resolve_geoip(ip):
    result = {'ip':ip,'latitude':None,'longitude':None,'country':'Unknown','source':'unknown'}
    if not is_public(ip):
        return result
    try:
        cache = json.loads(CACHE_FILE.read_text(encoding='utf-8'))
        record = cache.get(ip)
        if isinstance(record,dict):
            lat,lon = record.get('latitude'),record.get('longitude')
            if isinstance(lat,(float,int)) and isinstance(lon,(float,int)) and -90 <= lat <= 90 and -180 <= lon <= 180:
                result.update(record,ip=ip,source='cache')
    except (OSError,ValueError,AttributeError):
        pass
    return result

def get_geoip_for_events(events):
    counter = Counter(ip for e in events for ip in [e.get('source_ip') or e.get('src_ip'),e.get('destination_ip') or e.get('dst_ip')] if ip and is_public(ip))
    results = []
    for ip,count in counter.items():
        geo = resolve_geoip(ip)
        if geo['latitude'] is not None and geo['longitude'] is not None:
            results.append({**geo,'event_count':count,'severity':'Unknown'})
    return results
