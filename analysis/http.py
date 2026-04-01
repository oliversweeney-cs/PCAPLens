import os
import re
import base64
from collections import Counter, defaultdict
from .constants import SUSPICIOUS_UA_PATTERNS, EXTENSION_CONTENT_TYPES

_IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}(:\d+)?$')


def _is_bare_ip(host):
    return bool(_IP_RE.match(host)) if host else False


def _flag_ua(ua):
    if not ua:
        return None
    ua_lower = ua.lower()
    for pattern in SUSPICIOUS_UA_PATTERNS:
        if pattern in ua_lower:
            return pattern
    return None


def _check_content_type_mismatch(uri, content_type):
    if not uri or not content_type:
        return False
    path = uri.split('?')[0]
    ext = os.path.splitext(path)[1].lower()
    acceptable = EXTENSION_CONTENT_TYPES.get(ext)
    if not acceptable:
        return False
    ct_base = content_type.split(';')[0].strip().lower()
    return ct_base not in acceptable


def analyse_http(packets):
    timestamps = [p['timestamp'] for p in packets if p.get('timestamp')]
    capture_start = min(timestamps) if timestamps else 0.0

    hosts = Counter()
    user_agents = Counter()
    ua_flag_map = {}
    ua_first_seen = {}   # ua string → min relative timestamp
    methods = Counter()
    cleartext_creds = []

    req_packets = []
    resp_packets = []

    for p in packets:
        if p.get('http_method'):
            req_packets.append(p)
            if p['http_host']:
                hosts[p['http_host']] += 1
            if p['http_method']:
                methods[p['http_method']] += 1
            if p['http_user_agent']:
                ua = p['http_user_agent']
                user_agents[ua] += 1
                flag = _flag_ua(ua)
                if flag and ua not in ua_flag_map:
                    ua_flag_map[ua] = flag
                rel = p['timestamp'] - capture_start
                if ua not in ua_first_seen or rel < ua_first_seen[ua]:
                    ua_first_seen[ua] = rel
            if p['http_auth']:
                decoded = _decode_basic_auth(p['http_auth'])
                if decoded:
                    cleartext_creds.append({
                        'header': p['http_auth'],
                        'decoded': decoded,
                        'host': p['http_host'] or 'unknown',
                        'timestamp': p['timestamp'] - capture_start,
                    })
        elif p.get('http_response_code'):
            resp_packets.append(p)

    # Build response map keyed by (server_ip, server_port, client_ip, client_port)
    resp_map = {}
    for p in resp_packets:
        key = (p['src_ip'], p['src_port'], p['dst_ip'], p['dst_port'])
        resp_map[key] = p

    requests = []
    bare_ip_count = 0
    ct_mismatch_count = 0

    for p in req_packets[:200]:
        resp_key = (p['dst_ip'], p['dst_port'], p['src_ip'], p['src_port'])
        resp = resp_map.get(resp_key)

        status = resp['http_response_code'] if resp else None
        content_type = resp['http_content_type'] if resp else None
        content_length = resp['http_content_length'] if resp else None
        server = resp['http_server'] if resp else None

        bare_ip = _is_bare_ip(p['http_host'])
        ct_mismatch = _check_content_type_mismatch(p['http_uri'], content_type)

        if bare_ip:
            bare_ip_count += 1
        if ct_mismatch:
            ct_mismatch_count += 1

        requests.append({
            'method': p['http_method'],
            'host': p['http_host'] or '',
            'uri': p['http_uri'] or '',
            'bare_ip': bare_ip,
            'status': status,
            'content_type': content_type,
            'content_length': content_length,
            'server': server,
            'ct_mismatch': ct_mismatch,
            'timestamp': p['timestamp'] - capture_start,
        })

    ua_list = [
        {
            'ua': ua,
            'count': c,
            'suspicious': ua in ua_flag_map,
            'flag': ua_flag_map.get(ua),
            'first_seen': ua_first_seen.get(ua, 0.0),
        }
        for ua, c in user_agents.most_common(20)
    ]

    return {
        'hosts': [{'host': h, 'count': c} for h, c in hosts.most_common(50)],
        'requests': requests,
        'user_agents': ua_list,
        'methods': dict(methods),
        'cleartext_creds': cleartext_creds,
        'flagged_ua_count': sum(1 for ua in ua_list if ua['suspicious']),
        'bare_ip_count': bare_ip_count,
        'ct_mismatch_count': ct_mismatch_count,
    }


def _decode_basic_auth(header):
    try:
        if header.lower().startswith('basic '):
            encoded = header[6:].strip()
            return base64.b64decode(encoded).decode('utf-8', errors='replace')
    except Exception:
        pass
    return None
