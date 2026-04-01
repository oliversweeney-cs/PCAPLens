import pyshark


def parse_pcap(filepath):
    """Parse a PCAP file and return a list of normalised packet dicts."""
    cap = pyshark.FileCapture(filepath, keep_packets=False)
    packets = []
    try:
        for pkt in cap:
            try:
                packets.append(_extract(pkt))
            except Exception:
                continue
    finally:
        cap.close()
    return packets


def _extract(pkt):
    info = {
        'timestamp': float(pkt.sniff_timestamp) if hasattr(pkt, 'sniff_timestamp') else 0.0,
        'length': int(pkt.length) if hasattr(pkt, 'length') else 0,
        'src_ip': None,
        'dst_ip': None,
        'protocol': pkt.highest_layer,
        'src_port': None,
        'dst_port': None,
        # DNS
        'dns_query': None,
        'dns_is_response': False,
        'dns_answers': [],
        # HTTP request
        'http_host': None,
        'http_uri': None,
        'http_method': None,
        'http_user_agent': None,
        'http_auth': None,
        # HTTP response
        'http_response_code': None,
        'http_content_type': None,
        'http_content_length': None,
        'http_server': None,
    }

    if hasattr(pkt, 'ip'):
        info['src_ip'] = pkt.ip.src
        info['dst_ip'] = pkt.ip.dst
    elif hasattr(pkt, 'ipv6'):
        info['src_ip'] = pkt.ipv6.src
        info['dst_ip'] = pkt.ipv6.dst

    if hasattr(pkt, 'tcp'):
        try:
            info['src_port'] = int(pkt.tcp.srcport)
            info['dst_port'] = int(pkt.tcp.dstport)
        except Exception:
            pass
    elif hasattr(pkt, 'udp'):
        try:
            info['src_port'] = int(pkt.udp.srcport)
            info['dst_port'] = int(pkt.udp.dstport)
        except Exception:
            pass

    if hasattr(pkt, 'dns'):
        try:
            if hasattr(pkt.dns, 'qry_name'):
                info['dns_query'] = str(pkt.dns.qry_name)
            # Distinguish query from response via the QR flag
            if hasattr(pkt.dns, 'flags_response'):
                info['dns_is_response'] = str(pkt.dns.flags_response) == '1'
            # Collect resolved IPs from A / AAAA answers
            if info['dns_is_response']:
                answers = []
                try:
                    all_fields = pkt.dns._all_fields
                    for key in ('dns.a', 'dns.aaaa'):
                        val = all_fields.get(key)
                        if val is None:
                            continue
                        if isinstance(val, list):
                            answers.extend(str(v) for v in val)
                        else:
                            answers.append(str(val))
                except AttributeError:
                    a = _safe_attr(pkt.dns, 'a')
                    if a:
                        answers.append(a)
                    aaaa = _safe_attr(pkt.dns, 'aaaa')
                    if aaaa:
                        answers.append(aaaa)
                info['dns_answers'] = answers
        except Exception:
            pass

    if hasattr(pkt, 'http'):
        try:
            info['http_host'] = _safe_attr(pkt.http, 'host')
            info['http_uri'] = _safe_attr(pkt.http, 'request_uri')
            info['http_method'] = _safe_attr(pkt.http, 'request_method')
            info['http_user_agent'] = _safe_attr(pkt.http, 'user_agent')
            info['http_auth'] = _safe_attr(pkt.http, 'authorization')
            info['http_response_code'] = _safe_attr(pkt.http, 'response_code')
            info['http_content_type'] = _safe_attr(pkt.http, 'content_type')
            info['http_content_length'] = _safe_attr(pkt.http, 'content_length_header')
            info['http_server'] = _safe_attr(pkt.http, 'server')
        except Exception:
            pass

    return info


def _safe_attr(obj, attr):
    try:
        val = getattr(obj, attr, None)
        return str(val) if val is not None else None
    except Exception:
        return None
