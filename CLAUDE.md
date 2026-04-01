# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

PCAPLens is a Flask web application for SOC analysts to analyse PCAP (packet capture) files. It parses captures and presents findings across tabbed sections: traffic overview, top talkers, ports/protocols, DNS, HTTP/S, and MITRE ATT&CK technique mapping. It also exports JSON and self-contained HTML reports.

## Stack

- **Language**: Python 3
- **Framework**: Flask
- **Packet parsing**: pyshark (wraps tshark); swap to direct `tshark` subprocess calls if performance is unacceptable on large captures
- **Config**: python-dotenv (`.env` file)
- **Port**: 8889 (avoids conflict with PhishLens on 8888)

## Environment Setup

```bash
cd ~/pcaplens
python3 -m venv venv
source venv/bin/activate
pip install flask pyshark python-dotenv
```

## Running the App

```bash
source venv/bin/activate
flask run --port 8889
# or
python app.py
```

## Environment Variables

A `.env.example` file should be committed to document expected variables — copy it to `.env` and fill in values locally. Expected variables:

```
FLASK_ENV=development
FLASK_SECRET_KEY=changeme
```

Never commit `.env` itself.

## .gitignore

A `.gitignore` file should exist at the repo root excluding:

```
venv/
uploads/
*.pcap
*.pcapng
.env
__pycache__/
*.pyc
```

## Uploads Directory

Uploaded PCAPs are stored temporarily in `uploads/` during analysis. Files should be deleted from `uploads/` after the analysis response is returned — do not persist them. The `uploads/` directory itself is gitignored.

## Coding Conventions

- Analysis logic lives in a dedicated module (e.g. `analysis/`) separate from Flask routes
- Each analysis section (overview, top talkers, ports, DNS, HTTP, MITRE) is its own function or module
- MITRE mappings are rule-based; keep the rules as a data structure (dict/list) rather than buried in conditionals
- Suspicious port list and bad-TLD/entropy thresholds are defined as constants, not magic numbers inline
- pyshark's async internals can block — wrap long parses to avoid locking the request thread; consider background task or streaming response for large files
- HTML export must be fully self-contained (inline CSS/JS, no external dependencies)
- JSON export structure mirrors the internal data dict returned by the analysis functions directly — this keeps exports automatically consistent with any future changes to analysis logic

## Key Behaviours to Preserve

- **Suspicious ports** flagged in red: 4444, 1337, 31337, 9001, 9030, 6667, 4899
- **DNS flagging**: long subdomains, high-entropy names (possible DGA), known bad TLDs
- **HTTP flagging**: Basic Auth headers exposed in cleartext → T1552.001
- **MITRE mappings** (minimum set):
  - Suspicious port activity → T1571
  - DNS tunnelling (long subdomains) → T1071.004
  - IRC traffic (port 6667) → T1071.003
  - Cleartext Basic Auth → T1552.001
