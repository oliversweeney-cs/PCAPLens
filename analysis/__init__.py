from .parser import parse_pcap
from .overview import analyse_overview
from .top_talkers import analyse_top_talkers
from .ports import analyse_ports
from .dns import analyse_dns
from .http import analyse_http
from .files import extract_files
from .mitre import analyse_mitre
from .timeline import build_timeline


def run_analysis(filepath):
    packets = parse_pcap(filepath)
    results = {
        'overview': analyse_overview(packets),
        'top_talkers': analyse_top_talkers(packets),
        'ports': analyse_ports(packets),
        'dns': analyse_dns(packets, pcap_path=filepath),
        'http': analyse_http(packets),
        'files': extract_files(filepath),
    }
    results['mitre'] = analyse_mitre(results)
    results['timeline'] = build_timeline(results)
    return results
