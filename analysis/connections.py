import subprocess
from datetime import datetime, timezone
from collections import Counter

from .constants import TSHARK_PATH, COMMON_SERVICES


def analyse_connections(pcap_path):
    """
    Extract TCP SYN and SYN/ACK packets from a PCAP to build a connection log.
    Returns structured dict with connections, stats, open_ports, and scan_summary.
    """
    raw_rows = _extract_all_packets(pcap_path)
    connections = _parse_rows(raw_rows)

    syns = [c for c in connections if c['type'] == 'SYN']
    synacks = [c for c in connections if c['type'] == 'SYN/ACK']

    stats = _build_stats(syns, synacks)
    open_ports = _build_open_ports(synacks)
    scan_summary = _detect_scanner(syns)

    return {
        'connections': connections,
        'stats': stats,
        'open_ports': open_ports,
        'scan_summary': scan_summary,
    }


def _extract_all_packets(pcap_path):
    """Run tshark to extract all packets (no display filter) for Python-side filtering."""
    try:
        result = subprocess.run(
            [
                TSHARK_PATH, '-r', pcap_path,
                '-T', 'fields',
                '-e', 'frame.number',
                '-e', 'frame.time_utc',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'tcp.srcport',
                '-e', 'tcp.dstport',
                '-e', 'tcp.flags',
                '-e', 'frame.protocols',
                '-E', 'header=n',
                '-E', 'separator=/t',
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.stdout.splitlines()
    except Exception:
        return []


EXPECTED_FIELDS = 8

# TCP flag hex values for SYN-only and SYN/ACK
_SYN_FLAGS = {'0x00000002', '0x0002'}
_SYNACK_FLAGS = {'0x00000012', '0x0012'}


def _parse_rows(rows):
    """Parse tshark output rows, filtering to SYN and SYN/ACK in Python."""
    connections = []
    for line in rows:
        parts = line.split('\t')
        # Pad short rows (tshark omits trailing empty fields)
        while len(parts) < EXPECTED_FIELDS:
            parts.append('')

        frame_str = parts[0].strip()
        time_raw = parts[1].strip()
        src_ip = parts[2].strip()
        dst_ip = parts[3].strip()
        src_port_str = parts[4].strip()
        dst_port_str = parts[5].strip()
        flags_hex = parts[6].strip()
        protocols = parts[7].strip()

        # Skip non-TCP rows
        if 'tcp' not in protocols:
            continue

        # Skip rows with no flags
        if not flags_hex:
            continue

        # Classify by tcp.flags hex value
        if flags_hex in _SYNACK_FLAGS:
            conn_type = 'SYN/ACK'
        elif flags_hex in _SYN_FLAGS:
            conn_type = 'SYN'
        else:
            continue

        if not frame_str or not src_ip:
            continue

        try:
            frame_number = int(frame_str)
        except ValueError:
            continue

        try:
            src_port = int(src_port_str) if src_port_str else 0
            dst_port = int(dst_port_str) if dst_port_str else 0
        except ValueError:
            src_port = 0
            dst_port = 0

        timestamp_utc = _parse_tshark_time(time_raw)

        connections.append({
            'frame_number': frame_number,
            'timestamp_utc': timestamp_utc,
            'timestamp_raw': time_raw,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'type': conn_type,
        })

    return connections


def _parse_tshark_time(raw):
    """Parse tshark frame.time into ISO 8601 UTC string."""
    if not raw:
        return ''
    try:
        # tshark format: "Mon DD, YYYY HH:MM:SS.NNNNNNNNN TZ"
        # Truncate nanoseconds to microseconds for strptime compatibility
        # Strip leading/trailing whitespace
        cleaned = raw.strip()
        # Remove sub-microsecond precision — find the '.' and keep up to 6 decimal digits
        dot_idx = cleaned.find('.')
        if dot_idx != -1:
            # Find where the fractional seconds end (next space)
            space_after = cleaned.find(' ', dot_idx)
            if space_after != -1:
                frac = cleaned[dot_idx + 1:space_after]
                frac_trimmed = frac[:6].ljust(6, '0')
                cleaned = cleaned[:dot_idx + 1] + frac_trimmed + cleaned[space_after:]
            else:
                frac = cleaned[dot_idx + 1:]
                frac_trimmed = frac[:6].ljust(6, '0')
                cleaned = cleaned[:dot_idx + 1] + frac_trimmed

        # Try common tshark timestamp formats
        for fmt in (
            '%b %d, %Y %H:%M:%S.%f %Z',
            '%b  %d, %Y %H:%M:%S.%f %Z',
            '%b %d, %Y %H:%M:%S.%f',
            '%b  %d, %Y %H:%M:%S.%f',
        ):
            try:
                dt = datetime.strptime(cleaned, fmt)
                dt = dt.replace(tzinfo=timezone.utc)
                return dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            except ValueError:
                continue

        # Fallback: return the raw string
        return raw.strip()
    except Exception:
        return raw.strip()


def _build_stats(syns, synacks):
    """Build aggregate statistics from SYN and SYN/ACK lists."""
    first_syn_time = ''
    first_syn_frame = 0
    if syns:
        first = syns[0]  # Already in packet order from tshark
        first_syn_time = first['timestamp_utc']
        first_syn_frame = first['frame_number']

    first_synack_time = ''
    first_synack_frame = 0
    if synacks:
        first = synacks[0]
        first_synack_time = first['timestamp_utc']
        first_synack_frame = first['frame_number']

    return {
        'total_syns': len(syns),
        'total_synacks': len(synacks),
        'first_syn_time': first_syn_time,
        'first_syn_frame': first_syn_frame,
        'first_synack_time': first_synack_time,
        'first_synack_frame': first_synack_frame,
        'unique_src_ips': len({c['src_ip'] for c in syns}),
        'unique_dst_ips': len({c['dst_ip'] for c in syns}),
        'unique_dst_ports': len({c['dst_port'] for c in syns}),
    }


def _build_open_ports(synacks):
    """Build open ports list from SYN/ACK responses."""
    open_ports = []
    seen = set()
    for c in synacks:
        # In a SYN/ACK, the source is the responder; src_port is the open port
        key = (c['src_ip'], c['src_port'])
        if key in seen:
            continue
        seen.add(key)
        port = c['src_port']
        open_ports.append({
            'dst_ip': c['src_ip'],
            'port': port,
            'service': COMMON_SERVICES.get(port, ''),
            'frame_number': c['frame_number'],
            'timestamp_utc': c['timestamp_utc'],
        })
    return open_ports


def _detect_scanner(syns):
    """Identify dominant scanner IP if one accounts for >60% of SYN packets."""
    if not syns:
        return {
            'scanner_ip': None,
            'targets': [],
            'ports_scanned': [],
            'scan_duration_seconds': 0.0,
        }

    src_counts = Counter(c['src_ip'] for c in syns)
    top_ip, top_count = src_counts.most_common(1)[0]

    if top_count / len(syns) <= 0.6:
        return {
            'scanner_ip': None,
            'targets': [],
            'ports_scanned': [],
            'scan_duration_seconds': 0.0,
        }

    scanner_syns = [c for c in syns if c['src_ip'] == top_ip]
    targets = sorted({c['dst_ip'] for c in scanner_syns})
    ports_scanned = sorted({c['dst_port'] for c in scanner_syns})

    # Calculate scan duration from frame numbers (first to last)
    timestamps = [c['timestamp_utc'] for c in scanner_syns if c['timestamp_utc']]
    scan_duration = 0.0
    if len(timestamps) >= 2:
        try:
            first_dt = datetime.fromisoformat(timestamps[0].rstrip('Z')).replace(tzinfo=timezone.utc)
            last_dt = datetime.fromisoformat(timestamps[-1].rstrip('Z')).replace(tzinfo=timezone.utc)
            scan_duration = round((last_dt - first_dt).total_seconds(), 2)
        except (ValueError, TypeError):
            pass

    return {
        'scanner_ip': top_ip,
        'targets': targets,
        'ports_scanned': ports_scanned,
        'scan_duration_seconds': scan_duration,
    }
