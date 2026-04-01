from .constants import MITRE_TECHNIQUES, EXECUTABLE_MIMES


def analyse_mitre(results):
    """Map observed behaviours to MITRE ATT&CK techniques using rule-based triggers."""
    triggered = {}
    _check_suspicious_ports(results, triggered)
    _check_dns_tunnelling(results, triggered)
    _check_irc_traffic(results, triggered)
    _check_cleartext_auth(results, triggered)
    _check_powershell_ua(results, triggered)
    _check_bare_ip_http(results, triggered)
    _check_file_type_mismatch(results, triggered)
    _check_smb_executables(results, triggered)
    _check_ftp_files(results, triggered)
    return list(triggered.values())


def _check_suspicious_ports(results, triggered):
    flagged = [p for p in results.get('ports', {}).get('ports', []) if p.get('suspicious')]
    if flagged:
        t = _technique('T1571')
        t['evidence'] = [
            {
                'indicator': str(p['port']),
                'flag_type': 'Suspicious Port',
                'value': f"{p['count']} packets ({p['service'] or 'unknown'})",
            }
            for p in flagged
        ]
        triggered['T1571'] = t


def _check_dns_tunnelling(results, triggered):
    flagged = [
        q for q in results.get('dns', {}).get('queries', [])
        if any(f.get('type') in ('entropy', 'subdomain') for f in q.get('flags', []))
    ]
    if flagged:
        t = _technique('T1071.004')
        rows = []
        for q in flagged[:10]:
            for f in q['flags']:
                if f.get('type') in ('entropy', 'subdomain'):
                    rows.append({
                        'indicator': q['domain'],
                        'flag_type': f['label'].split('(')[0].strip(),
                        'value': f['label'],
                    })
        t['evidence'] = rows
        triggered['T1071.004'] = t


def _check_irc_traffic(results, triggered):
    irc = next((p for p in results.get('ports', {}).get('ports', []) if p['port'] == 6667), None)
    if irc:
        t = _technique('T1071.003')
        t['evidence'] = [
            {'indicator': '6667', 'flag_type': 'IRC Port', 'value': f"{irc['count']} packets"}
        ]
        triggered['T1071.003'] = t


def _check_cleartext_auth(results, triggered):
    creds = results.get('http', {}).get('cleartext_creds', [])
    if creds:
        t = _technique('T1552.001')
        t['evidence'] = [
            {'indicator': c['host'], 'flag_type': 'Basic Auth', 'value': c['decoded']}
            for c in creds
        ]
        triggered['T1552.001'] = t


def _check_powershell_ua(results, triggered):
    flagged = [
        ua for ua in results.get('http', {}).get('user_agents', [])
        if ua.get('suspicious') and (ua.get('flag') or '').lower() == 'powershell'
    ]
    if flagged:
        t = _technique('T1059.001')
        t['evidence'] = [
            {
                'indicator': ua['ua'][:80],
                'flag_type': 'PowerShell UA',
                'value': f"{ua['count']} requests",
            }
            for ua in flagged
        ]
        triggered['T1059.001'] = t


def _check_bare_ip_http(results, triggered):
    if not results.get('http', {}).get('bare_ip_count', 0):
        return
    bare_hosts = {}
    for req in results.get('http', {}).get('requests', []):
        if req.get('bare_ip'):
            bare_hosts[req['host']] = bare_hosts.get(req['host'], 0) + 1
    if bare_hosts:
        t = _technique('T1071.001')
        t['evidence'] = [
            {'indicator': host, 'flag_type': 'Bare IP Host', 'value': f'{count} requests'}
            for host, count in sorted(bare_hosts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        triggered['T1071.001'] = t


def _check_file_type_mismatch(results, triggered):
    # Collect mismatches from extracted files
    file_mismatches = [
        f for f in results.get('files', []) if f.get('type_mismatch')
    ]
    # Collect mismatches from HTTP response Content-Type headers
    http_mismatches = [
        r for r in results.get('http', {}).get('requests', []) if r.get('ct_mismatch')
    ]

    evidence = []
    for f in file_mismatches[:8]:
        evidence.append({
            'indicator': f['filename'],
            'flag_type': 'Magic vs Extension',
            'value': f"{f['actual_type']} declared as {f['declared_type']}",
        })
    for r in http_mismatches[:5]:
        evidence.append({
            'indicator': f"{r['host']}{r['uri']}",
            'flag_type': 'Content-Type Mismatch',
            'value': r['content_type'] or 'unknown',
        })

    if evidence:
        t = _technique('T1036')
        t['evidence'] = evidence
        triggered['T1036'] = t


def _check_smb_executables(results, triggered):
    smb_execs = [
        f for f in results.get('files', [])
        if f.get('protocol') == 'SMB' and f.get('actual_mime') in EXECUTABLE_MIMES
    ]
    if smb_execs:
        t = _technique('T1021.002')
        t['evidence'] = [
            {
                'indicator': f['filename'],
                'flag_type': 'SMB Executable',
                'value': f"{f['actual_type']} ({f['size']} bytes)",
            }
            for f in smb_execs[:10]
        ]
        triggered['T1021.002'] = t


def _check_ftp_files(results, triggered):
    ftp_files = [f for f in results.get('files', []) if f.get('protocol') == 'FTP']
    if ftp_files:
        t = _technique('T1071.002')
        t['evidence'] = [
            {
                'indicator': f['filename'],
                'flag_type': 'FTP Transfer',
                'value': f"{f['actual_type']} ({f['size']} bytes)",
            }
            for f in ftp_files[:10]
        ]
        triggered['T1071.002'] = t


def _technique(technique_id):
    for t in MITRE_TECHNIQUES:
        if t['id'] == technique_id:
            return {'id': t['id'], 'name': t['name'], 'url': t['url'], 'evidence': []}
    return {'id': technique_id, 'name': technique_id, 'url': '#', 'evidence': []}
