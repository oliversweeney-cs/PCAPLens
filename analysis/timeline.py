from .constants import MITRE_TECHNIQUES


def build_timeline(results):
    """
    Build a chronological list of security-relevant events from all analysis modules.
    Each event: {timestamp, category, summary, severity}
    timestamp is relative to capture start (seconds).
    """
    events = []

    # DNS query events
    for q in results.get('dns', {}).get('queries', []):
        ts = q.get('first_seen', 0.0)
        is_flagged = bool(q.get('flags'))
        summary = f"DNS query: {q['domain']}"
        if q.get('resolved_ips'):
            summary += ' \u2192 ' + ', '.join(q['resolved_ips'][:3])
            if len(q['resolved_ips']) > 3:
                summary += f' +{len(q["resolved_ips"]) - 3} more'
        events.append({
            'timestamp': ts,
            'category': 'suspicious' if is_flagged else 'dns',
            'summary': summary,
            'severity': 'suspicious' if is_flagged else 'normal',
        })

    # HTTP request events
    for req in results.get('http', {}).get('requests', []):
        ts = req.get('timestamp', 0.0)
        is_suspicious = req.get('bare_ip') or req.get('ct_mismatch')
        host = req['host'] or ''
        summary = f"HTTP {req['method']} {host}{req['uri']}"
        if req.get('status'):
            summary += f" [{req['status']}]"
        if req.get('bare_ip'):
            summary += ' (bare IP)'
        if req.get('ct_mismatch'):
            summary += ' (content-type mismatch)'
        events.append({
            'timestamp': ts,
            'category': 'suspicious' if is_suspicious else 'http',
            'summary': summary,
            'severity': 'suspicious' if is_suspicious else 'normal',
        })

    # File extraction events
    for f in results.get('files', []):
        is_suspicious = f.get('type_mismatch')
        size_str = _format_bytes(f.get('size', 0))
        proto = f.get('protocol', 'HTTP')
        summary = f"File extracted ({proto}): {f['filename']} ({f['actual_type']}, {size_str})"
        if is_suspicious:
            summary += f" — declared {f['declared_type']}"
        events.append({
            'timestamp': 0.0,  # no packet timestamp available for extracted files
            'category': 'suspicious' if is_suspicious else 'files',
            'summary': summary,
            'severity': 'suspicious' if is_suspicious else 'normal',
        })

    # Suspicious port events
    for p in results.get('ports', {}).get('ports', []):
        if p.get('suspicious'):
            ts = p.get('first_seen', 0.0)
            service = p.get('service') or 'unknown'
            summary = f"Suspicious port {p['port']} ({service}) — {p['count']} packets"
            events.append({
                'timestamp': ts,
                'category': 'suspicious',
                'summary': summary,
                'severity': 'suspicious',
            })

    # Cleartext protocol events (one per protocol)
    for cp in results.get('ports', {}).get('cleartext_ports', []):
        # Use first_seen of the matching well-known port entry
        ts = 0.0
        for p in results.get('ports', {}).get('ports', []):
            if p['port'] == cp['port']:
                ts = p.get('first_seen', 0.0)
                break
        summary = f"Cleartext protocol detected: {cp['protocol']} on port {cp['port']}"
        events.append({
            'timestamp': ts,
            'category': 'suspicious',
            'summary': summary,
            'severity': 'normal',
        })

    # Flagged user agent events (first seen)
    for ua in results.get('http', {}).get('user_agents', []):
        if ua.get('suspicious'):
            ts = ua.get('first_seen', 0.0)
            flag = ua.get('flag', '')
            summary = f"Suspicious UA [{flag}]: {ua['ua'][:80]}"
            events.append({
                'timestamp': ts,
                'category': 'suspicious',
                'summary': summary,
                'severity': 'suspicious',
            })

    # Cleartext credential events
    for cred in results.get('http', {}).get('cleartext_creds', []):
        ts = cred.get('timestamp', 0.0)
        summary = f"Cleartext credentials on {cred['host']}"
        events.append({
            'timestamp': ts,
            'category': 'suspicious',
            'summary': summary,
            'severity': 'suspicious',
        })

    # Flagged TLS session events
    for s in results.get('tls', {}).get('flagged_sessions', []):
        ts = s.get('timestamp', 0.0)
        dest = s.get('sni') or s['dst_ip']
        port = s.get('dst_port', 0)
        flag_descs = ', '.join(s['flags'])
        summary = f"TLS session to {dest}:{port} \u2014 {flag_descs}"
        # Red for malicious/no-sni, amber for tool/rare/port/legacy
        is_red = any(f.startswith('Malicious JA3') or f == 'No SNI' for f in s['flags'])
        events.append({
            'timestamp': ts,
            'category': 'tls',
            'summary': summary,
            'severity': 'suspicious' if is_red else 'normal',
        })

    # MITRE technique events — timestamp derived from earliest evidence
    for t in results.get('mitre', []):
        ts = _mitre_earliest_timestamp(t['id'], results)
        n = len(t.get('evidence', []))
        summary = f"MITRE {t['id']}: {t['name']} ({n} indicator{'s' if n != 1 else ''})"
        events.append({
            'timestamp': ts,
            'category': 'mitre',
            'summary': summary,
            'severity': 'suspicious',
        })

    events.sort(key=lambda e: e['timestamp'])
    return events


def _mitre_earliest_timestamp(tech_id, results):
    """Derive the earliest relevant timestamp for a given MITRE technique ID."""
    if tech_id == 'T1571':
        times = [p.get('first_seen', 0.0) for p in results.get('ports', {}).get('ports', [])
                 if p.get('suspicious')]
        return min(times) if times else 0.0

    if tech_id == 'T1071.004':
        flagged = [q for q in results.get('dns', {}).get('queries', [])
                   if any(f.get('type') in ('entropy', 'subdomain') for f in q.get('flags', []))]
        times = [q.get('first_seen', 0.0) for q in flagged]
        return min(times) if times else 0.0

    if tech_id == 'T1071.003':
        irc = next((p for p in results.get('ports', {}).get('ports', []) if p['port'] == 6667), None)
        return irc.get('first_seen', 0.0) if irc else 0.0

    if tech_id == 'T1552.001':
        times = [c.get('timestamp', 0.0) for c in results.get('http', {}).get('cleartext_creds', [])]
        return min(times) if times else 0.0

    if tech_id == 'T1059.001':
        flagged = [ua for ua in results.get('http', {}).get('user_agents', [])
                   if ua.get('suspicious') and 'powershell' in (ua.get('flag') or '').lower()]
        times = [ua.get('first_seen', 0.0) for ua in flagged]
        return min(times) if times else 0.0

    if tech_id == 'T1071.001':
        times = [r.get('timestamp', 0.0) for r in results.get('http', {}).get('requests', [])
                 if r.get('bare_ip')]
        return min(times) if times else 0.0

    if tech_id == 'T1036':
        times = [r.get('timestamp', 0.0) for r in results.get('http', {}).get('requests', [])
                 if r.get('ct_mismatch')]
        return min(times) if times else 0.0

    if tech_id == 'T1573.001':
        malicious = [s for s in results.get('tls', {}).get('sessions', [])
                     if any('Malicious JA3' in f for f in s.get('flags', []))]
        times = [s.get('timestamp', 0.0) for s in malicious]
        return min(times) if times else 0.0

    if tech_id == 'T1040':
        cleartext = results.get('ports', {}).get('cleartext_ports', [])
        times = []
        for cp in cleartext:
            for p in results.get('ports', {}).get('ports', []):
                if p['port'] == cp['port']:
                    times.append(p.get('first_seen', 0.0))
                    break
        return min(times) if times else 0.0

    return 0.0


def _format_bytes(value):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if value < 1024:
            return f'{value:.1f} {unit}'
        value /= 1024
    return f'{value:.1f} TB'
