import math
import subprocess
from collections import Counter
from .constants import DGA_ENTROPY_THRESHOLD, LONG_SUBDOMAIN_THRESHOLD, BAD_TLDS, TSHARK_PATH


def shannon_entropy(s):
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _flag_domain(domain):
    """Return a list of flag dicts, each with 'type' and 'label' keys."""
    flags = []
    labels = domain.rstrip('.').split('.')

    subdomain_labels = labels[:-2] if len(labels) > 2 else []
    for label in subdomain_labels:
        if len(label) >= 6:
            entropy = shannon_entropy(label)
            if entropy > DGA_ENTROPY_THRESHOLD:
                flags.append({
                    'type': 'entropy',
                    'label': f'High Entropy ({entropy:.2f})',
                    'detail': f'Label "{label}" entropy {entropy:.2f} > {DGA_ENTROPY_THRESHOLD}',
                })

    subdomain = '.'.join(labels[:-2]) if len(labels) > 2 else ''
    if len(subdomain) > LONG_SUBDOMAIN_THRESHOLD:
        flags.append({
            'type': 'subdomain',
            'label': f'Long Subdomain ({len(subdomain)} chars)',
            'detail': f'{len(subdomain)} char subdomain exceeds {LONG_SUBDOMAIN_THRESHOLD} char threshold',
        })

    tld = f'.{labels[-1]}' if labels else ''
    if tld in BAD_TLDS:
        flags.append({
            'type': 'tld',
            'label': f'Bad TLD ({tld})',
            'detail': f'TLD {tld} is in the flagged list',
        })

    return flags


def _get_tshark_dns_answers(pcap_path):
    """
    Use tshark to reliably extract DNS A/AAAA answer records from response packets.
    Returns dict mapping domain (normalised) → list of resolved IP strings.
    """
    try:
        result = subprocess.run(
            [
                TSHARK_PATH, '-r', pcap_path,
                '-Y', 'dns.flags.response == 1',
                '-T', 'fields',
                '-e', 'dns.qry.name',
                '-e', 'dns.a',
                '-e', 'dns.aaaa',
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        domain_ips = {}
        for line in result.stdout.splitlines():
            parts = line.split('\t')
            if not parts or not parts[0].strip():
                continue
            domain = parts[0].strip().lower().rstrip('.')
            ips = []
            # tshark separates multiple values for the same field with ','
            if len(parts) > 1 and parts[1].strip():
                ips.extend(ip.strip() for ip in parts[1].split(',') if ip.strip())
            if len(parts) > 2 and parts[2].strip():
                ips.extend(ip.strip() for ip in parts[2].split(',') if ip.strip())
            if domain and ips:
                existing = domain_ips.setdefault(domain, [])
                for ip in ips:
                    if ip not in existing:
                        existing.append(ip)
        return domain_ips
    except Exception:
        return {}


def analyse_dns(packets, pcap_path=None):
    timestamps = [p['timestamp'] for p in packets if p.get('timestamp')]
    capture_start = min(timestamps) if timestamps else 0.0

    queries = {}

    for p in packets:
        name = p.get('dns_query')
        if not name:
            continue
        key = name.lower().rstrip('.')
        is_response = p.get('dns_is_response', False)

        if key not in queries:
            queries[key] = {
                'domain': key,
                'count': 0,
                'flags': _flag_domain(key),
                'first_seen': float('inf'),
                'resolved_ips': [],
                'source_ips': [],
            }

        if is_response:
            for ip in p.get('dns_answers', []):
                if ip and ip not in queries[key]['resolved_ips']:
                    queries[key]['resolved_ips'].append(ip)
        else:
            queries[key]['count'] += 1
            rel_time = p['timestamp'] - capture_start
            if rel_time < queries[key]['first_seen']:
                queries[key]['first_seen'] = rel_time
            src_ip = p.get('src_ip')
            if src_ip and src_ip not in queries[key]['source_ips']:
                queries[key]['source_ips'].append(src_ip)

    # Use tshark as the authoritative source for resolved IPs
    if pcap_path:
        tshark_answers = _get_tshark_dns_answers(pcap_path)
        for domain, ips in tshark_answers.items():
            if domain not in queries:
                continue
            existing = queries[domain]['resolved_ips']
            for ip in ips:
                if ip not in existing:
                    existing.append(ip)

    for entry in queries.values():
        if entry['first_seen'] == float('inf'):
            entry['first_seen'] = 0.0

    sorted_queries = sorted(
        [q for q in queries.values() if q['count'] > 0 or q['resolved_ips']],
        key=lambda x: x['count'],
        reverse=True,
    )

    return {
        'queries': sorted_queries,
        'total_unique': len(sorted_queries),
        'flagged_count': sum(1 for q in sorted_queries if q['flags']),
    }
