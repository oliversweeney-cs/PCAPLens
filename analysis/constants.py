SUSPICIOUS_PORTS = {4444, 1337, 31337, 9001, 9030, 6667, 4899}

PORT_LABELS = {
    20: 'FTP Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
    25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    445: 'SMB', 587: 'SMTP TLS', 993: 'IMAPS', 995: 'POP3S',
    1194: 'OpenVPN', 1433: 'MSSQL', 3306: 'MySQL',
    3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
    6379: 'Redis', 8080: 'HTTP Alt', 8443: 'HTTPS Alt',
    27017: 'MongoDB',
    1337: 'Leet (suspicious)', 4444: 'Metasploit (suspicious)',
    4899: 'Radmin (suspicious)', 6667: 'IRC (suspicious)',
    9001: 'Tor OR (suspicious)', 9030: 'Tor Dir (suspicious)',
    31337: 'Elite (suspicious)',
}

EPHEMERAL_PORT_THRESHOLD = 49152

DGA_ENTROPY_THRESHOLD = 3.5
LONG_SUBDOMAIN_THRESHOLD = 50  # characters in the full subdomain portion

BAD_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.pw', '.cc'}

# Compound TLDs where the registerable domain is 3 segments (e.g. example.co.uk)
COMPOUND_TLDS = {
    '.co.uk', '.co.jp', '.co.kr', '.co.nz', '.co.za', '.co.in', '.co.id',
    '.com.au', '.com.br', '.com.cn', '.com.mx', '.com.tw', '.com.sg',
    '.org.uk', '.org.au', '.net.au', '.net.nz',
    '.gov.uk', '.gov.au', '.ac.uk', '.edu.au',
    '.ne.jp', '.or.jp',
}

# MIME types that indicate executable content (for SMB executable detection)
EXECUTABLE_MIMES = {
    'application/x-dosexec', 'application/x-elf', 'application/x-mach-binary',
}

# Substring patterns matched case-insensitively against User-Agent strings
SUSPICIOUS_UA_PATTERNS = ['powershell', 'curl/', 'wget/', 'python-requests', 'go-http-client']

# RFC 1918 + link-local ranges used for internal IP tagging
RFC1918_CIDRS = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16']

# tshark binary path (confirmed installed)
TSHARK_PATH = '/usr/bin/tshark'

# Magic byte signatures: (bytes_prefix, mime_type, human_description)
MAGIC_SIGNATURES = [
    (b'\x25\x50\x44\x46',             'application/pdf',             'PDF document'),
    (b'\x4d\x5a',                      'application/x-dosexec',       'PE/EXE (Windows executable)'),
    (b'\x7f\x45\x4c\x46',             'application/x-elf',           'ELF (Linux/Unix executable)'),
    (b'\xfe\xed\xfa\xce',             'application/x-mach-binary',   'Mach-O (macOS executable)'),
    (b'\xfe\xed\xfa\xcf',             'application/x-mach-binary',   'Mach-O (macOS executable)'),
    (b'\xce\xfa\xed\xfe',             'application/x-mach-binary',   'Mach-O (macOS executable)'),
    (b'\xcf\xfa\xed\xfe',             'application/x-mach-binary',   'Mach-O (macOS executable)'),
    (b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a', 'image/png',             'PNG image'),
    (b'\xff\xd8\xff',                  'image/jpeg',                  'JPEG image'),
    (b'\x47\x49\x46\x38',             'image/gif',                   'GIF image'),
    (b'\x50\x4b\x03\x04',             'application/zip',             'ZIP archive'),
    (b'\x1f\x8b',                      'application/gzip',            'gzip archive'),
    (b'Rar!\x1a\x07',                  'application/x-rar',           'RAR archive'),
    (b'\x37\x7a\xbc\xaf\x27\x1c',    'application/x-7z-compressed', '7-Zip archive'),
    (b'\x23\x21',                      'text/x-shellscript',          'Shell script (#!)'),
    (b'%!PS',                          'application/postscript',      'PostScript document'),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'application/msword',    'OLE2 (Office 97-2003 doc/xls/ppt)'),
]

# Extension → set of acceptable MIME types (for server Content-Type mismatch detection)
EXTENSION_CONTENT_TYPES = {
    '.pdf':  {'application/pdf'},
    '.exe':  {'application/octet-stream', 'application/x-dosexec', 'application/x-msdownload',
               'application/vnd.microsoft.portable-executable'},
    '.dll':  {'application/octet-stream', 'application/x-dosexec', 'application/x-msdownload'},
    '.zip':  {'application/zip', 'application/x-zip-compressed', 'application/octet-stream'},
    '.gz':   {'application/gzip', 'application/x-gzip', 'application/octet-stream'},
    '.tar':  {'application/x-tar', 'application/octet-stream'},
    '.js':   {'application/javascript', 'text/javascript', 'application/x-javascript'},
    '.html': {'text/html'},
    '.htm':  {'text/html'},
    '.css':  {'text/css'},
    '.jpg':  {'image/jpeg'},
    '.jpeg': {'image/jpeg'},
    '.png':  {'image/png'},
    '.gif':  {'image/gif'},
    '.txt':  {'text/plain'},
    '.xml':  {'application/xml', 'text/xml'},
    '.json': {'application/json', 'text/json', 'text/plain'},
    # Office Open XML formats are ZIP-based
    '.docx': {'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'},
    '.xlsx': {'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/zip'},
    '.pptx': {'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/zip'},
    '.doc':  {'application/msword', 'application/octet-stream'},
    '.xls':  {'application/vnd.ms-excel', 'application/octet-stream'},
    '.sh':   {'text/plain', 'text/x-sh', 'application/x-sh', 'application/octet-stream'},
    '.ps1':  {'text/plain', 'application/x-powershell', 'application/octet-stream'},
    '.bat':  {'text/plain', 'application/octet-stream'},
    '.svg':  {'image/svg+xml', 'text/xml', 'application/xml', 'text/plain'},
}

# Extension → canonical MIME type (used as "declared type" when server header is unavailable)
EXT_TO_MIME = {
    '.pdf':  'application/pdf',
    '.exe':  'application/x-dosexec',
    '.dll':  'application/x-dosexec',
    '.zip':  'application/zip',
    '.gz':   'application/gzip',
    '.tar':  'application/x-tar',
    '.js':   'application/javascript',
    '.html': 'text/html',
    '.htm':  'text/html',
    '.css':  'text/css',
    '.jpg':  'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png':  'image/png',
    '.gif':  'image/gif',
    '.txt':  'text/plain',
    '.xml':  'application/xml',
    '.json': 'application/json',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    '.doc':  'application/msword',
    '.xls':  'application/vnd.ms-excel',
    '.sh':   'text/x-shellscript',
    '.ps1':  'application/x-powershell',
    '.elf':  'application/x-elf',
    '.rar':  'application/x-rar',
    '.7z':   'application/x-7z-compressed',
}

MITRE_TECHNIQUES = [
    {
        'id': 'T1571',
        'name': 'Non-Standard Port',
        'url': 'https://attack.mitre.org/techniques/T1571',
        'trigger': 'suspicious_ports',
    },
    {
        'id': 'T1071.004',
        'name': 'Application Layer Protocol: DNS',
        'url': 'https://attack.mitre.org/techniques/T1071/004',
        'trigger': 'dns_tunnelling',
    },
    {
        'id': 'T1071.003',
        'name': 'Application Layer Protocol: IRC',
        'url': 'https://attack.mitre.org/techniques/T1071/003',
        'trigger': 'irc_traffic',
    },
    {
        'id': 'T1552.001',
        'name': 'Unsecured Credentials: Credentials In Files',
        'url': 'https://attack.mitre.org/techniques/T1552/001',
        'trigger': 'cleartext_auth',
    },
    {
        'id': 'T1059.001',
        'name': 'Command and Scripting Interpreter: PowerShell',
        'url': 'https://attack.mitre.org/techniques/T1059/001',
        'trigger': 'powershell_ua',
    },
    {
        'id': 'T1071.001',
        'name': 'Application Layer Protocol: Web Protocols',
        'url': 'https://attack.mitre.org/techniques/T1071/001',
        'trigger': 'bare_ip_http',
    },
    {
        'id': 'T1036',
        'name': 'Masquerading',
        'url': 'https://attack.mitre.org/techniques/T1036',
        'trigger': 'file_type_mismatch',
    },
    {
        'id': 'T1021.002',
        'name': 'Remote Services: SMB/Windows Admin Shares',
        'url': 'https://attack.mitre.org/techniques/T1021/002',
        'trigger': 'smb_executables',
    },
    {
        'id': 'T1071.002',
        'name': 'Application Layer Protocol: File Transfer Protocols',
        'url': 'https://attack.mitre.org/techniques/T1071/002',
        'trigger': 'ftp_files',
    },
]
