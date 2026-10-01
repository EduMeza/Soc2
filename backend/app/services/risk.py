"""Priority index, not probability of compromise. Aggregates use persisted scores."""
import ipaddress
import re

def calculate_event_risk(event):
    factors = {'severity': {'Critical':70,'High':50,'Medium':25,'Low':5}.get(event.get('severity'),0)}
    if event.get('cve'):
        factors['CVE'] = 15
    text = ' '.join(str(event.get(k) or '') for k in ['process','command','rule_description'])
    if re.search(r'mimikatz| -enc\b|rundll32.*javascript|credential.?dump',text,re.I):
        factors['suspicious_process'] = 15
    for key in ['source_ip','destination_ip']:
        try:
            address = ipaddress.ip_address(event.get(key,''))
            if address.is_global and not address.is_multicast:
                factors['external_ip'] = 5
        except ValueError:
            pass
    if event.get('mitre_evidence'):
        factors['MITRE evidence'] = 5
    return min(100,sum(factors.values())),factors
