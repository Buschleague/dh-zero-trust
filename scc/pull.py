"""
Cisco Secure Access configuration extraction.

Pulls configuration from all available SCC API endpoints and saves
a timestamped JSON snapshot to reports/.

Usage: python -m scc.pull
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

from scc.client import SccClient, get_scc_client

console = Console()
DEFAULT_REPORTS_DIR = Path(__file__).parent.parent / "reports"


# ── Deployment pulls ─────────────────────────────────────────────────────────

def pull_sites(client: SccClient) -> list:
    return client.get("/deployments/v2/sites")


def pull_roaming_computers(client: SccClient) -> list:
    return client.paginated_get("/deployments/v2/roamingcomputers", page_size=100)


def pull_tunnel_groups(client: SccClient) -> list:
    resp = client.get("/deployments/v2/networktunnelgroups")
    return resp.get("data", []) if isinstance(resp, dict) else resp


def pull_internal_networks(client: SccClient) -> list:
    return client.get("/deployments/v2/internalnetworks")


def pull_internal_domains(client: SccClient) -> list:
    return client.get("/deployments/v2/internaldomains")


# ── Policy pulls ─────────────────────────────────────────────────────────────

def pull_destination_lists(client: SccClient) -> list:
    resp = client.get("/policies/v2/destinationlists")
    return resp.get("data", []) if isinstance(resp, dict) else resp


def pull_categories(client: SccClient) -> list:
    return client.get("/policies/v2/categories")


# ── Admin pulls ──────────────────────────────────────────────────────────────

def pull_users(client: SccClient) -> list:
    return client.get("/admin/v2/users")


def pull_roles(client: SccClient) -> list:
    return client.get("/admin/v2/roles")


def pull_integrations(client: SccClient) -> list:
    resp = client.get("/admin/v2/integrations")
    return resp.get("data", []) if isinstance(resp, dict) else resp


# ── Report pulls ─────────────────────────────────────────────────────────────

def pull_activity(client: SccClient, days: int = 30, limit: int = 1000) -> list:
    now_ms = int(time.time() * 1000)
    from_ms = now_ms - (days * 24 * 3600 * 1000)
    resp = client.get("/reports/v2/activity", params={
        "from": str(from_ms), "to": str(now_ms), "limit": limit,
    })
    return resp.get("data", []) if isinstance(resp, dict) else resp


def pull_top_destinations(client: SccClient, days: int = 30, limit: int = 50) -> list:
    now_ms = int(time.time() * 1000)
    from_ms = now_ms - (days * 24 * 3600 * 1000)
    resp = client.get("/reports/v2/top-destinations", params={
        "from": str(from_ms), "to": str(now_ms), "offset": 0, "limit": limit,
    })
    return resp.get("data", []) if isinstance(resp, dict) else resp


# ── Orchestrator ─────────────────────────────────────────────────────────────

PULL_REGISTRY = [
    ("sites", pull_sites),
    ("roaming_computers", pull_roaming_computers),
    ("tunnel_groups", pull_tunnel_groups),
    ("internal_networks", pull_internal_networks),
    ("internal_domains", pull_internal_domains),
    ("destination_lists", pull_destination_lists),
    ("categories", pull_categories),
    ("users", pull_users),
    ("roles", pull_roles),
    ("integrations", pull_integrations),
    ("activity", pull_activity),
    ("top_destinations", pull_top_destinations),
]


def run_full_pull(
    client: SccClient,
    reports_dir: Path = DEFAULT_REPORTS_DIR,
) -> dict:
    """Pull all available SCC configuration and save to a JSON snapshot."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    data = {
        "metadata": {
            "pulled_at": datetime.now(timezone.utc).isoformat(),
            "api_base": "https://api.sse.cisco.com",
        },
    }

    table = Table(title="SCC Configuration Pull")
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right", style="green")
    table.add_column("Status", style="dim")

    for name, pull_fn in PULL_REGISTRY:
        try:
            with console.status(f"Pulling {name}..."):
                result = pull_fn(client)
            data[name] = result
            count = len(result) if isinstance(result, list) else "?"
            table.add_row(name, str(count), "OK")
        except Exception as e:
            data[name] = []
            table.add_row(name, "0", f"[red]Error: {e}[/red]")

    console.print(table)

    out_path = reports_dir / f"scc_pull_{timestamp}.json"
    out_path.write_text(json.dumps(data, indent=2, default=str))
    console.print(f"\nSaved to [bold]{out_path}[/bold]")

    return data


# ── CLI entry point ──────────────────────────────────────────────────────────

def main():
    client = get_scc_client()
    try:
        run_full_pull(client)
    finally:
        client.close()


if __name__ == "__main__":
    main()
