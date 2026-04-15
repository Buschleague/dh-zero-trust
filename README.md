# DanHil Zero Trust Assessment

Automated configuration pull and gap analysis for DanHil Containers' Cisco Duo (and eventually Meraki) deployment.

## Purpose

1. **Duo Admin API Pull** — Extract full configuration: users, groups, phones, integrations, policies, admins, auth logs, devices, trust monitor events
2. **Gap Analysis** — Map current config against zero trust best practices for a 14-site corrugated packaging manufacturer with remote sales, traveling executives, and access management concerns
3. **Meraki API Pull** (Phase 2) — Network topology, clients, VPN, security appliance rules cross-referenced with Duo identity controls

## Setup

### Prerequisites

- Python 3.10+
- Duo Admin API credentials (from Duo Admin Panel → Applications → Admin API)
  - Integration Key (ikey)
  - Secret Key (skey)
  - API Hostname

### Install

```bash
cd danhil-zero-trust
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Configure

```bash
cp config/config.example.env config/.env
# Edit config/.env with your Duo Admin API credentials
```

### Run

```bash
# Full Duo configuration pull
python -m duo.pull

# Gap analysis report (run after pull)
python -m duo.analyze
```

## Project Structure

```
danhil-zero-trust/
├── config/
│   ├── .env                  # Your API credentials (git-ignored)
│   └── config.example.env    # Template
├── duo/
│   ├── __init__.py
│   ├── client.py             # Duo Admin API client wrapper
│   ├── pull.py               # Full configuration extraction
│   └── analyze.py            # Gap analysis engine
├── meraki/                   # Phase 2
│   ├── __init__.py
│   ├── client.py
│   └── pull.py
├── reports/                  # Generated reports land here
├── requirements.txt
└── README.md
```

## Security Notes

- `.env` is git-ignored — never commit API credentials
- The Admin API key should have **read-only** permissions for the initial pull
- Required permissions: Grant resource - Read, Grant settings - Read, Grant log - Read
