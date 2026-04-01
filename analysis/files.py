import hashlib
import os
import shutil
import subprocess
from urllib.parse import unquote

from .constants import TSHARK_PATH, MAGIC_SIGNATURES, EXTENSION_CONTENT_TYPES, EXT_TO_MIME

# Protocols to extract via tshark --export-objects
_PROTOCOLS = [
    ('HTTP', 'http'),
    ('SMB', 'smb'),
    ('FTP', 'ftp-data'),
]


def extract_files(pcap_path):
    """
    Use tshark to export HTTP, SMB, and FTP objects from the PCAP.
    Each file result is tagged with its source protocol.
    Returns a list of file result dicts. Cleans up all temp directories on exit.
    """
    dirs = []
    all_files = []

    try:
        for label, tshark_proto in _PROTOCOLS:
            extract_dir = f'{pcap_path}_{label.lower()}_files'
            dirs.append(extract_dir)
            os.makedirs(extract_dir, exist_ok=True)

            try:
                subprocess.run(
                    [TSHARK_PATH, '-r', pcap_path,
                     '--export-objects', f'{tshark_proto},{extract_dir}'],
                    capture_output=True,
                    timeout=60,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                continue

            uri_map = _get_http_request_map(pcap_path) if label == 'HTTP' else {}

            try:
                names = sorted(os.listdir(extract_dir))
            except OSError:
                continue

            for fname in names:
                fpath = os.path.join(extract_dir, fname)
                if os.path.isfile(fpath):
                    result = _analyse_file(fpath, fname, uri_map)
                    if result:
                        result['protocol'] = label
                        all_files.append(result)

        return all_files
    except Exception:
        return all_files
    finally:
        for d in dirs:
            if os.path.exists(d):
                shutil.rmtree(d, ignore_errors=True)


def _get_http_request_map(pcap_path):
    """Return a dict mapping URI -> host by parsing HTTP requests with tshark."""
    try:
        result = subprocess.run(
            [
                TSHARK_PATH, '-r', pcap_path,
                '-Y', 'http.request',
                '-T', 'fields',
                '-e', 'http.request.uri',
                '-e', 'http.host',
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        uri_map = {}
        for line in result.stdout.splitlines():
            parts = line.strip().split('\t')
            if len(parts) >= 2 and parts[0]:
                uri_map[parts[0]] = parts[1]
        return uri_map
    except Exception:
        return {}


def _analyse_file(fpath, tshark_name, uri_map):
    """Analyse a single extracted file and return a result dict."""
    try:
        size = os.path.getsize(fpath)
    except OSError:
        return None

    try:
        with open(fpath, 'rb') as f:
            header = f.read(16)
            f.seek(0)
            data = f.read()
    except OSError:
        return None

    display_name, uri = _parse_display_name(tshark_name)
    source = _lookup_source(tshark_name, uri, uri_map)

    actual_mime, actual_desc = _detect_magic(header)
    ext = os.path.splitext(display_name)[1].lower()
    declared_mime = EXT_TO_MIME.get(ext, '')

    type_mismatch = False
    if actual_mime and ext:
        acceptable = EXTENSION_CONTENT_TYPES.get(ext)
        if acceptable:
            type_mismatch = actual_mime not in acceptable

    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    return {
        'filename': display_name,
        'source': source,
        'uri': uri,
        'size': size,
        'declared_type': declared_mime or 'unknown',
        'actual_type': actual_desc or 'unknown',
        'actual_mime': actual_mime or '',
        'type_mismatch': type_mismatch,
        'md5': md5,
        'sha1': sha1,
        'sha256': sha256,
        # 'protocol' is set by extract_files() after this returns
    }


def _detect_magic(header):
    """Return (mime_type, description) for the first matching magic signature, else (None, None)."""
    for prefix, mime, desc in MAGIC_SIGNATURES:
        if header[:len(prefix)] == prefix:
            return mime, desc
    return None, None


def _parse_display_name(tshark_name):
    """
    Decode a tshark export-objects filename into a (display_name, uri) pair.
    tshark names files after the URL path with some URL encoding applied.
    """
    decoded = unquote(tshark_name)
    uri = decoded if decoded.startswith('/') else '/' + decoded
    display = os.path.basename(decoded) or tshark_name
    return display or tshark_name, uri


def _lookup_source(tshark_name, uri, uri_map):
    """Best-effort lookup of the source host for a given URI."""
    if uri in uri_map:
        return uri_map[uri]
    alt = uri.lstrip('/')
    if alt in uri_map:
        return uri_map[alt]
    basename = os.path.basename(uri)
    if basename:
        for map_uri, host in uri_map.items():
            if map_uri.endswith('/' + basename):
                return host
    return ''
