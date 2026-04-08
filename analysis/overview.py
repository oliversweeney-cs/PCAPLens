import ipaddress
from collections import Counter, defaultdict
from .constants import RFC1918_CIDRS

_RFC1918_NETWORKS = [ipaddress.ip_network(c) for c in RFC1918_CIDRS]


def _is_internal(ip_str):
    if not ip_str:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _RFC1918_NETWORKS)
    except ValueError:
        return True


def analyse_overview(packets):
    total_packets = len(packets)
    total_bytes = sum(p['length'] for p in packets)

    timestamps = [p['timestamp'] for p in packets if p['timestamp'] > 0]
    duration = round(max(timestamps) - min(timestamps), 2) if len(timestamps) >= 2 else 0.0

    src_ips = {p['src_ip'] for p in packets if p['src_ip']}
    dst_ips = {p['dst_ip'] for p in packets if p['dst_ip']}

    proto_counts = Counter(p['protocol'] for p in packets if p['protocol'])
    protocol_breakdown = [
        {'protocol': proto, 'count': count}
        for proto, count in proto_counts.most_common(20)
    ]

    return {
        'total_packets': total_packets,
        'total_bytes': total_bytes,
        'duration_seconds': duration,
        'unique_src_ips': len(src_ips),
        'unique_dst_ips': len(dst_ips),
        'protocol_breakdown': protocol_breakdown,
    }


def compute_top_external_destinations(packets, results):
    """Aggregate external destination IPs with packet/byte counts and ports used."""
    dst_agg = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'ports': set()})

    for p in packets:
        dst = p.get('dst_ip')
        if not dst or _is_internal(dst):
            continue
        dst_agg[dst]['packets'] += 1
        dst_agg[dst]['bytes'] += p.get('length', 0)
        port = p.get('dst_port')
        if port is not None:
            dst_agg[dst]['ports'].add(port)

    # Collect IPs flagged in HTTP (bare IP) or TLS (No SNI)
    flagged_ips = set()
    for req in results.get('http', {}).get('requests', []):
        if req.get('bare_ip'):
            flagged_ips.add(req.get('host', ''))
    for s in results.get('tls', {}).get('sessions', []):
        if any(f == 'No SNI' for f in s.get('flags', [])):
            flagged_ips.add(s.get('dst_ip', ''))

    sorted_dsts = sorted(dst_agg.items(), key=lambda x: x[1]['packets'], reverse=True)[:5]

    return [
        {
            'ip': ip,
            'packets': data['packets'],
            'bytes': data['bytes'],
            'ports': sorted(data['ports']),
            'flagged': ip in flagged_ips,
        }
        for ip, data in sorted_dsts
    ]
