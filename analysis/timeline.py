import subprocess
from datetime import datetime, timedelta, timezone

from .constants import MITRE_TECHNIQUES, TSHARK_PATH


def build_timeline(results, pcap_path=None):
    """
    Build a chronological list of security-relevant events from all analysis modules.
    Each event: {timestamp, timestamp_utc, timestamp_relative, category, summary, severity, frame_number}
    timestamp is relative to capture start (seconds).
    timestamp_utc is the absolute ISO 8601 UTC string.
    timestamp_relative is the formatted relative string (e.g. "0.001s").
    frame_number is the packet number where available, otherwise None.
    """
    capture_start = _get_capture_start_utc(pcap_path)
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
            'frame_number': None,
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
            'frame_number': req.get('frame_number'),
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
            'frame_number': None,
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
                'frame_number': None,
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
            'frame_number': None,
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
                'frame_number': None,
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
            'frame_number': None,
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
            'frame_number': None,
        })

    # Connection events (first SYN, SYN/ACKs, scanner detection)
    conn_data = results.get('connections', {})
    conn_stats = conn_data.get('stats', {})
    if conn_stats.get('first_syn_time'):
        events.append({
            'timestamp': 0.0,
            'category': 'connections',
            'summary': f"First SYN packet (frame #{conn_stats['first_syn_frame']}): {conn_stats['first_syn_time']}",
            'severity': 'info',
            'frame_number': conn_stats.get('first_syn_frame'),
        })
    for op in conn_data.get('open_ports', []):
        service = f" ({op['service']})" if op.get('service') else ''
        events.append({
            'timestamp': 0.0,
            'category': 'connections',
            'summary': f"SYN/ACK: {op['dst_ip']}:{op['port']}{service} open (frame #{op['frame_number']})",
            'severity': 'info',
            'frame_number': op.get('frame_number'),
        })
    scan = conn_data.get('scan_summary', {})
    if scan.get('scanner_ip'):
        n_ports = len(scan.get('ports_scanned', []))
        n_targets = len(scan.get('targets', []))
        duration = scan.get('scan_duration_seconds', 0)
        events.append({
            'timestamp': 0.0,
            'category': 'suspicious',
            'summary': f"Port scan detected: {scan['scanner_ip']} scanned {n_ports} ports across {n_targets} targets in {duration}s",
            'severity': 'high',
            'frame_number': None,
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
            'frame_number': None,
        })

    events.sort(key=lambda e: e['timestamp'])

    # Compute absolute UTC timestamps and formatted relative strings
    for ev in events:
        rel = ev['timestamp']
        ev['timestamp_relative'] = f"{rel:.3f}s"
        if capture_start:
            abs_dt = capture_start + timedelta(seconds=rel)
            ev['timestamp_utc'] = abs_dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        else:
            ev['timestamp_utc'] = ''

    return events


def _get_capture_start_utc(pcap_path):
    """Extract the absolute UTC timestamp of the first packet using tshark."""
    if not pcap_path:
        return None
    try:
        result = subprocess.run(
            [TSHARK_PATH, '-r', pcap_path, '-T', 'fields', '-e', 'frame.time_utc', '-c', '1'],
            capture_output=True,
            text=True,
            timeout=10,
        )
        raw = result.stdout.strip()
        if not raw:
            return None
        return _parse_tshark_time(raw)
    except Exception:
        return None


def _parse_tshark_time(raw):
    """Parse tshark frame.time into a Python datetime (UTC)."""
    cleaned = raw.strip()
    # Truncate nanoseconds to microseconds — find '.' and keep up to 6 decimal digits
    dot_idx = cleaned.find('.')
    if dot_idx != -1:
        space_after = cleaned.find(' ', dot_idx)
        if space_after != -1:
            frac = cleaned[dot_idx + 1:space_after]
            frac_trimmed = frac[:6].ljust(6, '0')
            cleaned = cleaned[:dot_idx + 1] + frac_trimmed + cleaned[space_after:]
        else:
            frac = cleaned[dot_idx + 1:]
            frac_trimmed = frac[:6].ljust(6, '0')
            cleaned = cleaned[:dot_idx + 1] + frac_trimmed

    for fmt in (
        '%b %d, %Y %H:%M:%S.%f %Z',
        '%b  %d, %Y %H:%M:%S.%f %Z',
        '%b %d, %Y %H:%M:%S.%f',
        '%b  %d, %Y %H:%M:%S.%f',
    ):
        try:
            dt = datetime.strptime(cleaned, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


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

    if tech_id == 'T1046':
        return 0.0  # Connection timestamps are absolute, not relative

    return 0.0


def _format_bytes(value):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if value < 1024:
            return f'{value:.1f} {unit}'
        value /= 1024
    return f'{value:.1f} TB'
