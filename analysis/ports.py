from collections import Counter, defaultdict
from .constants import SUSPICIOUS_PORTS, PORT_LABELS, EPHEMERAL_PORT_THRESHOLD, CLEARTEXT_PROTOCOLS


def analyse_ports(packets):
    port_counts = Counter(
        p['dst_port'] for p in packets if p['dst_port'] is not None
    )

    # Track first-seen timestamp per destination port (relative to capture start)
    timestamps = [p['timestamp'] for p in packets if p.get('timestamp')]
    capture_start = min(timestamps) if timestamps else 0.0

    port_first_seen = defaultdict(lambda: float('inf'))
    for p in packets:
        port = p.get('dst_port')
        if port is not None and p.get('timestamp'):
            rel = p['timestamp'] - capture_start
            if rel < port_first_seen[port]:
                port_first_seen[port] = rel

    well_known = []
    ephemeral_ports = []
    ephemeral_total = 0

    for port, count in sorted(port_counts.items(), key=lambda x: x[1], reverse=True):
        first_seen = port_first_seen[port]
        if first_seen == float('inf'):
            first_seen = 0.0

        if port >= EPHEMERAL_PORT_THRESHOLD:
            ephemeral_total += count
            ephemeral_ports.append({
                'port': port,
                'count': count,
                'service': '',
                'suspicious': False,
                'first_seen': first_seen,
            })
        else:
            well_known.append({
                'port': port,
                'count': count,
                'service': PORT_LABELS.get(port, ''),
                'suspicious': port in SUSPICIOUS_PORTS,
                'cleartext': CLEARTEXT_PROTOCOLS.get(port),
                'first_seen': first_seen,
            })

    cleartext_ports = [
        {'port': p['port'], 'protocol': p['cleartext'], 'count': p['count']}
        for p in well_known if p['cleartext']
    ]

    return {
        'ports': well_known,
        'ephemeral_ports': ephemeral_ports,
        'ephemeral_total': ephemeral_total,
        'cleartext_ports': cleartext_ports,
    }
