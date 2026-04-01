import csv
import io
import datetime

from .constants import COMPOUND_TLDS


def _extract_base_domain(domain):
    """
    Extract the registerable base domain from a full domain name.
    Uses last 3 segments for compound TLDs (.co.uk, .com.au, etc),
    otherwise last 2 segments.
    """
    parts = domain.rstrip('.').split('.')
    if len(parts) <= 2:
        return domain
    if len(parts) >= 3:
        compound = '.' + '.'.join(parts[-2:])
        if compound.lower() in COMPOUND_TLDS:
            return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def build_ioc_bundle(results, source_file=''):
    """
    Extract actionable IOCs from analysis results into a structured bundle.

    Only indicators an analyst would feed into a SIEM / threat-intel platform:
    domains, IPs, file hashes, suspicious user agents, and MITRE technique IDs.
    """
    triggered_mitre = {t['id'] for t in results.get('mitre', [])}

    domains = []
    ips = []
    hashes = []
    user_agents = []
    mitre_techniques = []

    # ── Domains: group flagged subdomains by their base/registerable domain ──
    # For DNS tunnelling, the base domain (e.g. "steasteel.net") is the IOC,
    # not the 99 individual encoded subdomains.  Group all flagged subdomains
    # under their base domain and emit one IOC row per base domain.
    base_groups = {}  # base_domain -> {count, flag_types, resolved_ips, subdomains}
    for q in results.get('dns', {}).get('queries', []):
        if not q.get('flags'):
            continue
        base = _extract_base_domain(q['domain'])
        if base not in base_groups:
            base_groups[base] = {
                'count': 0,
                'flag_types': set(),
                'resolved_ips': [],
                'subdomains': [],
            }
        g = base_groups[base]
        g['count'] += 1
        g['subdomains'].append(q['domain'])
        for f in q['flags']:
            g['flag_types'].add(f['label'].split('(')[0].strip())
        for ip in q.get('resolved_ips', []):
            if ip not in g['resolved_ips']:
                g['resolved_ips'].append(ip)

    mt_dns = 'T1071.004' if 'T1071.004' in triggered_mitre else ''
    for base, g in sorted(base_groups.items()):
        types_str = ', '.join(sorted(g['flag_types']))
        if g['count'] == 1 and base == g['subdomains'][0]:
            ctx = types_str
        else:
            ctx = f"{g['count']} flagged subdomains ({types_str})"
        domains.append({
            'value': base,
            'count': g['count'],
            'flag_types': sorted(g['flag_types']),
            'resolved_ips': g['resolved_ips'],
            'context': ctx,
            'severity': 'malicious' if mt_dns else 'suspicious',
            'mitre_technique': mt_dns,
        })

    # ── IPs: bare-IP HTTP hosts ──
    bare_ip_hosts = {}
    for req in results.get('http', {}).get('requests', []):
        if req.get('bare_ip'):
            bare_ip_hosts.setdefault(req['host'], []).append(req['uri'])
    mt_bare = 'T1071.001' if 'T1071.001' in triggered_mitre else ''
    for host, uris in bare_ip_hosts.items():
        ips.append({
            'value': host,
            'context': 'Bare IP HTTP; URIs: ' + ', '.join(uris[:3]),
            'severity': 'malicious' if mt_bare else 'suspicious',
            'mitre_technique': mt_bare,
        })

    # ── IPs: resolved from flagged base domains (deduplicated vs bare IPs) ──
    seen_ips = set(bare_ip_hosts.keys())
    for d in domains:
        for ip in d.get('resolved_ips', []):
            if ip not in seen_ips:
                seen_ips.add(ip)
                ips.append({
                    'value': ip,
                    'context': f"Resolved from flagged domain {d['value']}",
                    'severity': d['severity'],
                    'mitre_technique': d['mitre_technique'],
                })

    # ── Hashes: extracted files that pass the analytical-context filter ──
    # Exclude orphaned TCP fragments with no recognised type, no declared type,
    # and no source host — they have zero analytical value as IOCs.
    for f in results.get('files', []):
        has_mismatch = f.get('type_mismatch')
        has_actual = f.get('actual_type', 'unknown') != 'unknown'
        has_declared = f.get('declared_type', 'unknown') != 'unknown'
        has_source = bool(f.get('source') and f['source'] not in ('', '—'))
        if not (has_mismatch or has_actual or has_declared or has_source):
            continue

        mt_file = 'T1036' if (has_mismatch and 'T1036' in triggered_mitre) else ''
        sev = 'malicious' if mt_file else 'suspicious'
        ctx = f['filename']
        if has_mismatch:
            ctx += f" — declared {f['declared_type']}, actual {f['actual_type']}"
        hashes.append({
            'sha256': f['sha256'],
            'sha1': f['sha1'],
            'md5': f['md5'],
            'filename': f['filename'],
            'size': f['size'],
            'type_mismatch': f['type_mismatch'],
            'declared_type': f['declared_type'],
            'actual_type': f['actual_type'],
            'severity': sev,
            'mitre_technique': mt_file,
            'context': ctx,
        })

    # ── User agents: flagged UA strings ──
    for ua in results.get('http', {}).get('user_agents', []):
        if ua.get('suspicious'):
            flag = ua.get('flag', '')
            mt_ua = 'T1059.001' if ('powershell' in flag.lower() and 'T1059.001' in triggered_mitre) else ''
            user_agents.append({
                'value': ua['ua'],
                'flag': flag,
                'count': ua['count'],
                'severity': 'malicious' if mt_ua else 'suspicious',
                'mitre_technique': mt_ua,
            })

    # ── MITRE techniques triggered ──
    for t in results.get('mitre', []):
        mitre_techniques.append({
            'id': t['id'],
            'name': t['name'],
            'url': t['url'],
            'indicator_count': len(t.get('evidence', [])),
        })

    total_iocs = (
        len(domains) + len(ips) +
        len(hashes) * 3 +        # sha256 + sha1 + md5 per file
        len(user_agents) +
        len(mitre_techniques)
    )

    return {
        'export_metadata': {
            'source_file': source_file,
            'export_time': datetime.datetime.utcnow().isoformat() + 'Z',
            'pcaplens_version': '1.0',
        },
        'iocs': {
            'domains': domains,
            'ips': ips,
            'hashes': hashes,
            'user_agents': user_agents,
            'mitre_techniques': mitre_techniques,
        },
        'summary': {
            'total_iocs': total_iocs,
            'by_type': {
                'domains': len(domains),
                'ips': len(ips),
                'hashes': len(hashes),
                'user_agents': len(user_agents),
                'mitre_techniques': len(mitre_techniques),
            },
        },
    }


def to_csv_string(bundle):
    """Render IOCs from the bundle as a CSV string."""
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=['ioc_type', 'ioc_value', 'context', 'severity', 'mitre_technique'],
        lineterminator='\n',
    )
    writer.writeheader()

    iocs = bundle['iocs']

    for d in iocs['domains']:
        writer.writerow({
            'ioc_type': 'domain',
            'ioc_value': d['value'],
            'context': d['context'],
            'severity': d['severity'],
            'mitre_technique': d['mitre_technique'],
        })

    for ip in iocs['ips']:
        writer.writerow({
            'ioc_type': 'ip',
            'ioc_value': ip['value'],
            'context': ip['context'],
            'severity': ip['severity'],
            'mitre_technique': ip['mitre_technique'],
        })

    for h in iocs['hashes']:
        for hash_type in ('sha256', 'sha1', 'md5'):
            writer.writerow({
                'ioc_type': f'hash_{hash_type}',
                'ioc_value': h[hash_type],
                'context': h['context'],
                'severity': h['severity'],
                'mitre_technique': h['mitre_technique'],
            })

    for ua in iocs['user_agents']:
        writer.writerow({
            'ioc_type': 'user_agent',
            'ioc_value': ua['value'],
            'context': f"Pattern: {ua['flag']}, seen {ua['count']} time{'s' if ua['count'] != 1 else ''}",
            'severity': ua['severity'],
            'mitre_technique': ua['mitre_technique'],
        })

    for t in iocs['mitre_techniques']:
        writer.writerow({
            'ioc_type': 'mitre_technique',
            'ioc_value': t['id'],
            'context': f"{t['name']} ({t['indicator_count']} indicator{'s' if t['indicator_count'] != 1 else ''})",
            'severity': 'malicious',
            'mitre_technique': t['id'],
        })

    return output.getvalue()
