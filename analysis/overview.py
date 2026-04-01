from collections import Counter


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
