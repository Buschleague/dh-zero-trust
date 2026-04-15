"""
DanHil Duo Configuration Pull
Extracts full configuration state from Duo Admin API for assessment.

Usage: python -m duo.pull
"""

import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from .client import get_admin_client, paginated_fetch

console = Console()
REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


def pull_users(admin) -> list:
    """Pull all users with their phones, tokens, groups, and U2F tokens."""
    console.print("[bold cyan]Pulling users...[/]")
    users = paginated_fetch(admin, "get_users")
    console.print(f"  Found {len(users)} users")
    return users


def pull_groups(admin) -> list:
    """Pull all groups."""
    console.print("[bold cyan]Pulling groups...[/]")
    groups = paginated_fetch(admin, "get_groups")
    console.print(f"  Found {len(groups)} groups")
    return groups


def pull_phones(admin) -> list:
    """Pull all enrolled phones/devices."""
    console.print("[bold cyan]Pulling phones...[/]")
    phones = paginated_fetch(admin, "get_phones")
    console.print(f"  Found {len(phones)} phones")
    return phones


def pull_integrations(admin) -> list:
    """Pull all application integrations."""
    console.print("[bold cyan]Pulling integrations...[/]")
    integrations = paginated_fetch(admin, "get_integrations")
    console.print(f"  Found {len(integrations)} integrations")
    return integrations


def pull_admins(admin) -> list:
    """Pull all Duo administrators."""
    console.print("[bold cyan]Pulling admins...[/]")
    admins = paginated_fetch(admin, "get_admins")
    console.print(f"  Found {len(admins)} admins")
    return admins


def pull_policies(admin) -> list:
    """Pull all policies (v2 endpoint)."""
    console.print("[bold cyan]Pulling policies...[/]")
    try:
        # policies endpoint may require direct json_api_call
        response = admin.json_api_call("GET", "/admin/v2/policies", {})
        policies = response if isinstance(response, list) else [response]
        console.print(f"  Found {len(policies)} policies")
        return policies
    except Exception as e:
        console.print(f"  [yellow]Policies pull failed: {e}[/]")
        console.print("  [dim]This may require 'Grant settings - Read' permission[/]")
        return []


def pull_settings(admin) -> dict:
    """Pull account-level settings."""
    console.print("[bold cyan]Pulling account settings...[/]")
    try:
        settings = admin.get_settings()
        console.print("  Settings retrieved")
        return settings
    except Exception as e:
        console.print(f"  [yellow]Settings pull failed: {e}[/]")
        return {}


def pull_info(admin) -> dict:
    """Pull account info (edition, features, etc.)."""
    console.print("[bold cyan]Pulling account info...[/]")
    try:
        info = admin.get_info_summary()
        console.print("  Account info retrieved")
        return info
    except Exception as e:
        console.print(f"  [yellow]Account info pull failed: {e}[/]")
        return {}


def pull_registered_devices(admin) -> list:
    """Pull all Duo Desktop registered devices (trusted endpoints)."""
    console.print("[bold cyan]Pulling registered devices (Duo Desktop)...[/]")
    try:
        devices = paginated_fetch(admin, "get_registered_devices")
        console.print(f"  Found {len(devices)} registered devices")
        return devices
    except Exception as e:
        console.print(f"  [yellow]Registered devices pull failed: {e}[/]")
        return []


def pull_tokens(admin) -> list:
    """Pull all hardware tokens."""
    console.print("[bold cyan]Pulling hardware tokens...[/]")
    try:
        tokens = paginated_fetch(admin, "get_tokens")
        console.print(f"  Found {len(tokens)} tokens")
        return tokens
    except Exception as e:
        console.print(f"  [yellow]Tokens pull failed: {e}[/]")
        return []


def pull_bypass_codes(admin, users: list) -> dict:
    """Pull bypass codes for all users. Returns dict of user_id -> codes."""
    console.print("[bold cyan]Pulling bypass codes...[/]")
    bypass_map = {}
    count = 0
    for user in users:
        try:
            codes = admin.get_user_bypass_codes(user["user_id"])
            if codes:
                bypass_map[user["user_id"]] = {
                    "username": user.get("username", "unknown"),
                    "codes": codes,
                }
                count += len(codes)
        except Exception:
            continue
    console.print(f"  Found {count} active bypass codes across {len(bypass_map)} users")
    return bypass_map


def pull_auth_logs(admin, days: int = 30) -> list:
    """Pull authentication logs for the last N days."""
    console.print(f"[bold cyan]Pulling auth logs (last {days} days)...[/]")
    try:
        mintime = int((datetime.now() - timedelta(days=days)).timestamp() * 1000)
        logs = admin.get_authentication_log(api_version=2, mintime=mintime)
        log_list = logs.get("authlogs", []) if isinstance(logs, dict) else logs
        console.print(f"  Found {len(log_list)} auth log entries")
        return log_list
    except Exception as e:
        console.print(f"  [yellow]Auth logs pull failed: {e}[/]")
        return []


def pull_admin_logs(admin, days: int = 30) -> list:
    """Pull administrator action logs."""
    console.print("[bold cyan]Pulling admin logs...[/]")
    try:
        mintime = int((datetime.now() - timedelta(days=days)).timestamp())
        logs = admin.get_administrator_log(mintime=mintime)
        console.print(f"  Found {len(logs)} admin log entries")
        return logs
    except Exception as e:
        console.print(f"  [yellow]Admin logs pull failed: {e}[/]")
        return []


def pull_trust_monitor(admin) -> list:
    """Pull Trust Monitor events."""
    console.print("[bold cyan]Pulling Trust Monitor events...[/]")
    try:
        events = admin.get_trust_monitor_events_by_offset()
        console.print(f"  Found {len(events)} Trust Monitor events")
        return events
    except Exception as e:
        console.print(f"  [yellow]Trust Monitor pull failed: {e}[/]")
        console.print("  [dim]Trust Monitor may not be available on your license tier[/]")
        return []


def pull_directory_syncs(admin) -> list:
    """Pull directory sync configurations."""
    console.print("[bold cyan]Pulling directory syncs...[/]")
    try:
        response = admin.json_api_call("GET", "/admin/v1/user_dirsyncs", {})
        syncs = response if isinstance(response, list) else [response]
        console.print(f"  Found {len(syncs)} directory syncs")
        return syncs
    except Exception as e:
        console.print(f"  [yellow]Directory syncs pull failed: {e}[/]")
        return []


def main():
    console.print("\n[bold green]═══ DanHil Duo Configuration Pull ═══[/]\n")

    admin = get_admin_client()

    # Verify connectivity
    console.print("[bold]Verifying API connectivity...[/]")
    try:
        admin.json_api_call("GET", "/admin/v1/info/summary", {})
        console.print("[green]✓ Connected to Duo Admin API[/]\n")
    except Exception as e:
        console.print(f"[red]✗ Connection failed: {e}[/]")
        console.print("[dim]Check your credentials in config/.env[/]")
        return

    # Pull everything
    data = {}
    data["_meta"] = {
        "pulled_at": datetime.now().isoformat(),
        "pull_type": "full_configuration",
    }

    data["account_info"] = pull_info(admin)
    data["account_settings"] = pull_settings(admin)
    data["users"] = pull_users(admin)
    data["groups"] = pull_groups(admin)
    data["phones"] = pull_phones(admin)
    data["integrations"] = pull_integrations(admin)
    data["policies"] = pull_policies(admin)
    data["admins"] = pull_admins(admin)
    data["registered_devices"] = pull_registered_devices(admin)
    data["tokens"] = pull_tokens(admin)
    data["bypass_codes"] = pull_bypass_codes(admin, data["users"])
    data["directory_syncs"] = pull_directory_syncs(admin)
    data["auth_logs"] = pull_auth_logs(admin, days=30)
    data["admin_logs"] = pull_admin_logs(admin, days=30)
    data["trust_monitor_events"] = pull_trust_monitor(admin)

    # Save
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = REPORTS_DIR / f"duo_pull_{timestamp}.json"
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    console.print(f"\n[bold green]✓ Full pull saved to {output_path}[/]")

    # Quick summary
    console.print("\n[bold]Quick Summary:[/]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right")

    for key in ["users", "groups", "phones", "integrations", "policies",
                 "admins", "registered_devices", "tokens", "directory_syncs",
                 "auth_logs", "admin_logs", "trust_monitor_events"]:
        val = data.get(key, [])
        count = len(val) if isinstance(val, list) else ("present" if val else "0")
        table.add_row(key, str(count))

    bypass_count = sum(len(v.get("codes", [])) for v in data.get("bypass_codes", {}).values())
    table.add_row("bypass_codes", str(bypass_count))

    console.print(table)
    console.print(f"\n[dim]Next step: python -m duo.analyze {output_path}[/]")


if __name__ == "__main__":
    main()
