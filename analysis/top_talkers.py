import ipaddress
from collections import defaultdict
from .constants import RFC1918_CIDRS

_RFC1918_NETWORKS = [ipaddress.ip_network(c) for c in RFC1918_CIDRS]


def _is_internal(ip_str):
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _RFC1918_NETWORKS)
    except ValueError:
        return False


def analyse_top_talkers(packets):
    pairs = defaultdict(lambda: {'packets': 0, 'bytes': 0})

    for p in packets:
        if p['src_ip'] and p['dst_ip']:
            key = (p['src_ip'], p['dst_ip'])
            pairs[key]['packets'] += 1
            pairs[key]['bytes'] += p['length']

    sorted_pairs = sorted(pairs.items(), key=lambda x: x[1]['packets'], reverse=True)

    result = []
    for i, ((src, dst), stats) in enumerate(sorted_pairs[:50]):
        src_internal = _is_internal(src)
        dst_internal = _is_internal(dst)
        result.append({
            'src_ip': src,
            'dst_ip': dst,
            'packets': stats['packets'],
            'bytes': stats['bytes'],
            'src_internal': src_internal,
            'dst_internal': dst_internal,
            'is_egress': src_internal and not dst_internal,
            'is_top5': i < 5,
        })

    return result
