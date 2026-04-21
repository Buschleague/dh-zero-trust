# DanHil Zero Trust Assessment

Automated configuration pull and gap analysis for DanHil Containers' Cisco Secure Access deployment, with Meraki cross-reference (Phase 2) and standalone Duo Admin API (Phase 3) on the roadmap.

## Purpose

1. **Secure Access API Pull** — Extract full configuration via Cisco Security Cloud Control OAuth API: sites, roaming computers, tunnel groups, internal networks, destination lists, admin users, activity logs, and more.
2. **Gap Analysis** — Map current config against zero-trust best practices for a 14-site corrugated packaging manufacturer with remote sales, traveling executives, and cross-border operations (Texas + Mexico).
3. **Meraki Cross-Reference** (Phase 2) — Network topology, clients, VPN, security appliance rules correlated with Secure Access policy.
4. **Duo Admin API** (Phase 3, deferred) — If standalone Duo Admin Panel access becomes available, pull MFA device inventory and trust monitor events.

## Setup

### Prerequisites

- Python 3.10+
- Cisco Security Cloud Control API credentials (from SCC portal → API Keys)

### Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Configure

```bash
cp config/config.example.env config/.env
# Edit config/.env with your SCC API credentials:
#   SCC_KEY_ID=<your client id>
#   SCC_ACCESS_TOKEN=<your client secret>
#   SCC_REFRESH_TOKEN=unused
```

### Run

```bash
# Full Secure Access configuration pull
python -m scc.pull

# Gap analysis report (uses latest pull automatically)
python -m scc.analyze

# Gap analysis against a specific pull file
python -m scc.analyze reports/scc_pull_20260421_223327.json

# Run tests
pytest tests/ -v
```

## Project Structure

```
dh-zero-trust/
├── config/
│   ├── .env                      # Your API credentials (git-ignored)
│   └── config.example.env        # Template
├── scc/
│   ├── auth.py                   # OAuth token management (client_credentials + fallbacks)
│   ├── client.py                 # HTTP client with pagination and rate-limit backoff
│   ├── pull.py                   # Full configuration extraction (12 categories)
│   └── analyze.py                # Zero-trust gap analysis engine
├── duo/                          # Phase 3 — Duo Admin API (deferred)
│   ├── client.py                 # Duo Admin API client wrapper
│   ├── pull.py                   # Configuration extraction
│   └── analyze.py                # Gap analysis engine
├── meraki/                       # Phase 2 — Meraki cross-reference
├── tests/                        # pytest test suite (56 tests)
├── reports/                      # Generated reports (git-ignored)
├── requirements.txt
└── README.md
```

## API Coverage

### Working Endpoints (Phase 1)

| Scope | Endpoint | Data |
|-------|----------|------|
| Deployments | `/deployments/v2/sites` | 15 sites |
| Deployments | `/deployments/v2/roamingcomputers` | 100 endpoints |
| Deployments | `/deployments/v2/networktunnelgroups` | Tunnel config |
| Deployments | `/deployments/v2/internalnetworks` | 26 networks |
| Deployments | `/deployments/v2/internaldomains` | Internal domains |
| Policies | `/policies/v2/destinationlists` | Allow/block lists |
| Policies | `/policies/v2/categories` | Content categories |
| Admin | `/admin/v2/users` | Admin accounts |
| Admin | `/admin/v2/roles` | Role definitions |
| Admin | `/admin/v2/integrations` | Third-party integrations |
| Reports | `/reports/v2/activity` | DNS/proxy/firewall activity |
| Reports | `/reports/v2/top-destinations` | Top destinations |

## Security Notes

- `config/.env` is git-ignored — never commit API credentials
- `config/.scc_tokens.json` is git-ignored — cached bearer tokens
- The API key should have **Admin** scope (read-only operations only)
- `reports/` output may contain PII (user emails, device names, site names) and is git-ignored
