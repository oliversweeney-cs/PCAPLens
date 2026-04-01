import subprocess
from collections import Counter

from .constants import TSHARK_PATH, MALICIOUS_JA3, TOOL_JA3, TLS_VERSION_MAP
from .top_talkers import _is_internal


def analyse_tls(pcap_path):
    """Extract and analyse TLS handshake data from the PCAP using tshark."""
    client_hellos = _extract_client_hellos(pcap_path)
    server_hellos = _extract_server_hellos(pcap_path)

    # Correlate Client Hello → Server Hello by tcp.stream index
    sessions = []
    for stream_id, ch in client_hellos.items():
        sh = server_hellos.get(stream_id, {})
        sessions.append({
            'tcp_stream': stream_id,
            'src_ip': ch.get('src_ip', ''),
            'dst_ip': ch.get('dst_ip', ''),
            'dst_port': ch.get('dst_port', 0),
            'sni': ch.get('sni') or None,
            'ja3_hash': ch.get('ja3_hash', ''),
            'ja3_full': ch.get('ja3_full', ''),
            'ja3s_hash': sh.get('ja3s_hash', ''),
            'ja3s_full': sh.get('ja3s_full', ''),
            'tls_version': _resolve_tls_version(ch.get('tls_version', '')),
            'timestamp': ch.get('timestamp', 0.0),
            'src_internal': _is_internal(ch.get('src_ip', '')),
            'dst_internal': _is_internal(ch.get('dst_ip', '')),
            'label': None,
            'flags': [],
        })

    # Apply flagging logic
    total = len(sessions)
    ja3_counts = Counter(s['ja3_hash'] for s in sessions if s['ja3_hash'])

    for s in sessions:
        _flag_session(s, ja3_counts, total)

    unique_ja3 = len(set(s['ja3_hash'] for s in sessions if s['ja3_hash']))
    unique_ja3s = len(set(s['ja3s_hash'] for s in sessions if s['ja3s_hash']))
    flagged = [s for s in sessions if s['flags']]

    return {
        'sessions': sessions,
        'stats': {
            'total_sessions': total,
            'unique_ja3': unique_ja3,
            'unique_ja3s': unique_ja3s,
            'flagged_count': len(flagged),
        },
        'flagged_sessions': flagged,
    }


def _extract_client_hellos(pcap_path):
    """Extract Client Hello fields using tshark."""
    try:
        result = subprocess.run(
            [
                TSHARK_PATH, '-r', pcap_path,
                '-Y', 'tls.handshake.type == 1',
                '-T', 'fields',
                '-e', 'tcp.stream',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'tcp.dstport',
                '-e', 'tls.handshake.ja3',
                '-e', 'tls.handshake.ja3_full',
                '-e', 'tls.handshake.extensions_server_name',
                '-e', 'tls.handshake.version',
                '-e', 'frame.time_relative',
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        hellos = {}
        for line in result.stdout.splitlines():
            parts = line.split('\t')
            if not parts or not parts[0].strip():
                continue
            # Pad to 9 columns — tshark omits trailing tabs for empty fields
            while len(parts) < 9:
                parts.append('')
            stream = parts[0].strip()
            if stream in hellos:
                continue  # first Client Hello per stream only
            hellos[stream] = {
                'src_ip': parts[1].strip(),
                'dst_ip': parts[2].strip(),
                'dst_port': _safe_int(parts[3].strip()),
                'ja3_hash': parts[4].strip(),
                'ja3_full': parts[5].strip(),
                'sni': parts[6].strip() or None,
                'tls_version': parts[7].strip(),
                'timestamp': _safe_float(parts[8].strip()),
            }
        return hellos
    except Exception:
        return {}


def _extract_server_hellos(pcap_path):
    """Extract Server Hello fields using tshark."""
    try:
        result = subprocess.run(
            [
                TSHARK_PATH, '-r', pcap_path,
                '-Y', 'tls.handshake.type == 2',
                '-T', 'fields',
                '-e', 'tcp.stream',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'tls.handshake.ja3s',
                '-e', 'tls.handshake.ja3s_full',
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        hellos = {}
        for line in result.stdout.splitlines():
            parts = line.split('\t')
            if not parts or not parts[0].strip():
                continue
            while len(parts) < 5:
                parts.append('')
            stream = parts[0].strip()
            if stream in hellos:
                continue
            hellos[stream] = {
                'ja3s_hash': parts[3].strip(),
                'ja3s_full': parts[4].strip(),
            }
        return hellos
    except Exception:
        return {}


def _flag_session(session, ja3_counts, total_sessions):
    """Apply flagging rules to a single TLS session."""
    ja3 = session['ja3_hash']
    flags = session['flags']

    # 1. No SNI
    if not session['sni']:
        flags.append('No SNI')

    # 2. Known Malicious JA3 (checked before Tool — malicious takes precedence)
    if ja3 in MALICIOUS_JA3:
        label = MALICIOUS_JA3[ja3]
        session['label'] = label
        flags.append(f'Malicious JA3: {label}')

    # 3. Known Tool JA3
    elif ja3 in TOOL_JA3:
        label = TOOL_JA3[ja3]
        session['label'] = label
        flags.append(f'Known Tool: {label}')

    # 4. Rare JA3 — only if >= 5 TLS sessions in capture
    if ja3 and total_sessions >= 5 and ja3_counts.get(ja3, 0) == 1:
        flags.append('Rare JA3')

    # 5. Non-Standard Port
    port = session['dst_port']
    if port and port not in (443, 8443):
        flags.append(f'Non-Standard Port ({port})')

    # 6. Legacy TLS
    version = session['tls_version']
    if version in ('TLS 1.0', 'TLS 1.1'):
        flags.append(f'Legacy TLS ({version})')


def _resolve_tls_version(raw):
    """Map tshark version output to human-readable label."""
    if not raw:
        return ''
    # tshark may output comma-separated values if multiple version fields exist
    first = raw.split(',')[0].strip()
    return TLS_VERSION_MAP.get(first, first)


def _safe_int(s):
    try:
        return int(s)
    except (ValueError, TypeError):
        return 0


def _safe_float(s):
    try:
        return float(s)
    except (ValueError, TypeError):
        return 0.0
