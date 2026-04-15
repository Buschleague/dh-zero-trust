"""
DanHil Duo Gap Analysis Engine
Maps current Duo configuration against zero trust best practices.

Usage: python -m duo.analyze [path_to_pull.json]
       or: python -m duo.analyze  (auto-finds latest pull)
"""

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()
REPORTS_DIR = Path(__file__).parent.parent / "reports"


# ─── Finding Severity ────────────────────────────────────────────────────────

class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

SEVERITY_COLORS = {
    Severity.CRITICAL: "red bold",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


class Finding:
    def __init__(self, severity: str, category: str, title: str, detail: str,
                 recommendation: str, danhil_context: str = ""):
        self.severity = severity
        self.category = category
        self.title = title
        self.detail = detail
        self.recommendation = recommendation
        self.danhil_context = danhil_context


# ─── Analysis Functions ───────────────────────────────────────────────────────

def analyze_account_info(data: dict) -> list[Finding]:
    """Check license tier and enabled features."""
    findings = []
    info = data.get("account_info", {})

    if not info:
        findings.append(Finding(
            Severity.MEDIUM, "Account",
            "Account info unavailable",
            "Could not retrieve account info — may indicate insufficient API permissions.",
            "Ensure Admin API has 'Grant settings - Read' permission."
        ))
        return findings

    edition = info.get("edition", "unknown")
    findings.append(Finding(
        Severity.INFO, "Account",
        f"Duo Edition: {edition}",
        f"Account is running Duo {edition}.",
        "Duo Advantage or Premier is required for Trusted Endpoints, Risk-Based Auth, and Adaptive Policies.",
        "DanHil needs at minimum Duo Advantage for the zero trust controls you're targeting."
    ))

    return findings


def analyze_users(data: dict) -> list[Finding]:
    """Analyze user enrollment, status, and hygiene."""
    findings = []
    users = data.get("users", [])

    if not users:
        findings.append(Finding(
            Severity.HIGH, "Users",
            "No users found",
            "The pull returned zero users.",
            "Verify Admin API permissions include 'Grant resource - Read'."
        ))
        return findings

    # Check enrollment status
    unenrolled = [u for u in users if u.get("status") == "bypass"]
    disabled = [u for u in users if u.get("status") == "disabled"]
    active = [u for u in users if u.get("status") == "active"]
    locked = [u for u in users if u.get("status") == "locked out"]

    if unenrolled:
        names = ", ".join(u.get("username", "?") for u in unenrolled[:10])
        findings.append(Finding(
            Severity.HIGH, "Users",
            f"{len(unenrolled)} users in bypass status",
            f"These users skip MFA entirely: {names}{'...' if len(unenrolled) > 10 else ''}",
            "Review each bypass user. Set enrollment deadline or enforce MFA. "
            "Bypass should only be temporary during onboarding.",
            "Every bypassed user at any of the 14 sites is an unprotected entry point."
        ))

    if locked:
        findings.append(Finding(
            Severity.MEDIUM, "Users",
            f"{len(locked)} users locked out",
            "Locked accounts may indicate brute force attempts or forgotten devices.",
            "Review locked accounts for suspicious activity before unlocking."
        ))

    # Check for users without phones
    no_phone = [u for u in users if not u.get("phones")]
    enrolled_no_phone = [u for u in no_phone if u.get("status") == "active"]
    if enrolled_no_phone:
        findings.append(Finding(
            Severity.MEDIUM, "Users",
            f"{len(enrolled_no_phone)} active users with no phone enrolled",
            "These users are marked active but have no Duo Mobile device.",
            "They may be using hardware tokens or SMS only — verify and upgrade to push if possible."
        ))

    findings.append(Finding(
        Severity.INFO, "Users",
        f"User summary: {len(active)} active, {len(unenrolled)} bypass, "
        f"{len(disabled)} disabled, {len(locked)} locked",
        f"Total: {len(users)} users in Duo.",
        ""
    ))

    return findings


def analyze_groups(data: dict) -> list[Finding]:
    """Check if groups are being used for policy segmentation."""
    findings = []
    groups = data.get("groups", [])
    users = data.get("users", [])

    if not groups:
        findings.append(Finding(
            Severity.HIGH, "Groups",
            "No groups configured",
            "Without groups, you cannot create per-group adaptive policies.",
            "Create groups aligned to your access tiers: IT, Sales, Executives, "
            "Plant Operations, Accounting, etc. Then assign group-specific policies.",
            "This is how you control blast radius for remote sales reps and "
            "apply stricter policies for traveling executives."
        ))
    else:
        findings.append(Finding(
            Severity.INFO, "Groups",
            f"{len(groups)} groups configured",
            "Groups found: " + ", ".join(g.get("name", "?") for g in groups[:20]),
            "Verify groups map to your access tiers and that each has an appropriate policy."
        ))

        # Check for users not in any group
        users_with_groups = [u for u in users if u.get("groups")]
        ungrouped = len(users) - len(users_with_groups)
        if ungrouped > 0:
            findings.append(Finding(
                Severity.MEDIUM, "Groups",
                f"{ungrouped} users not assigned to any group",
                "Ungrouped users fall back to the global policy, which is typically less restrictive.",
                "Assign all users to appropriate groups for policy enforcement."
            ))

    return findings


def analyze_integrations(data: dict) -> list[Finding]:
    """Check application integrations and coverage."""
    findings = []
    integrations = data.get("integrations", [])

    if not integrations:
        findings.append(Finding(
            Severity.HIGH, "Integrations",
            "No application integrations found",
            "Duo isn't protecting any applications.",
            "Start with high-value targets: VPN, Microsoft 365, RDP, critical internal apps."
        ))
        return findings

    # Categorize integrations
    types = {}
    for integ in integrations:
        t = integ.get("type", "unknown")
        types[t] = types.get(t, 0) + 1

    type_summary = ", ".join(f"{v}x {k}" for k, v in sorted(types.items(), key=lambda x: -x[1]))
    findings.append(Finding(
        Severity.INFO, "Integrations",
        f"{len(integrations)} integrations configured",
        f"Types: {type_summary}",
        ""
    ))

    # Check for key integrations that should exist
    integration_names = [i.get("name", "").lower() for i in integrations]
    integration_types = [i.get("type", "").lower() for i in integrations]
    all_text = " ".join(integration_names + integration_types)

    expected = {
        "vpn": "VPN integration — critical for remote sales and traveling executives",
        "rdp": "RDP/Remote Desktop — protect lateral movement within sites",
        "microsoft": "Microsoft 365 / Azure AD — core productivity suite",
        "admin api": "Admin API — you have this (it's how we're pulling data)",
    }

    for keyword, description in expected.items():
        if keyword not in all_text:
            findings.append(Finding(
                Severity.MEDIUM, "Integrations",
                f"Missing expected integration: {keyword.upper()}",
                description,
                f"Consider adding Duo protection for {keyword}.",
                "Check if this was inherited from Umbrella but not fully configured."
            ))

    # Check for integrations in "inactive" state
    inactive = [i for i in integrations if i.get("adminapi_read_resource", 0) == 0
                and i.get("type") != "adminapi"]

    return findings


def analyze_policies(data: dict) -> list[Finding]:
    """Analyze policy configuration — the core of zero trust."""
    findings = []
    policies = data.get("policies", [])

    if not policies:
        findings.append(Finding(
            Severity.CRITICAL, "Policies",
            "No custom policies found",
            "You're running on Duo's default global policy only. "
            "This means every user and every application gets the same security controls.",
            "Create per-application and per-group policies. At minimum: "
            "1) Strict policy for admin/IT access, "
            "2) Standard policy for office workers, "
            "3) Restricted policy for remote/traveling users.",
            "This is THE lever for controlling blast radius. Without custom policies, "
            "a compromised sales rep credential has the same access path as IT."
        ))
        return findings

    findings.append(Finding(
        Severity.INFO, "Policies",
        f"{len(policies)} policies configured",
        "Custom policies exist — review each for appropriate controls.",
        "Key things to verify in each policy: device trust requirements, "
        "allowed authentication methods, location restrictions, remembered devices settings."
    ))

    # Analyze each policy for key settings
    for policy in policies:
        name = policy.get("policy_name", policy.get("name", "Unknown"))

        # Check if device health is enforced
        sections = policy.get("sections", {})
        if isinstance(sections, dict):
            # Check for device health policies
            device_health = sections.get("device_health_app", {})
            if not device_health:
                findings.append(Finding(
                    Severity.MEDIUM, "Policies",
                    f"Policy '{name}' has no device health requirements",
                    "No OS version, encryption, or firewall checks are enforced.",
                    "Enable device health checks to ensure endpoints meet security baselines."
                ))

    return findings


def analyze_bypass_codes(data: dict) -> list[Finding]:
    """Check for active bypass codes — security risk."""
    findings = []
    bypass_codes = data.get("bypass_codes", {})

    total_codes = sum(len(v.get("codes", [])) for v in bypass_codes.values())

    if total_codes > 0:
        usernames = [v["username"] for v in bypass_codes.values()]
        findings.append(Finding(
            Severity.HIGH, "Bypass Codes",
            f"{total_codes} active bypass codes across {len(bypass_codes)} users",
            f"Users with bypass codes: {', '.join(usernames[:10])}",
            "Bypass codes are single-use MFA skip tokens. They should be temporary. "
            "Audit and revoke any that aren't actively needed.",
            "Each bypass code is a backdoor around your MFA. Clean these up."
        ))
    else:
        findings.append(Finding(
            Severity.INFO, "Bypass Codes",
            "No active bypass codes",
            "Clean — no bypass codes outstanding.",
            ""
        ))

    return findings


def analyze_devices(data: dict) -> list[Finding]:
    """Analyze device trust posture."""
    findings = []
    phones = data.get("phones", [])
    registered = data.get("registered_devices", [])

    if not registered:
        findings.append(Finding(
            Severity.HIGH, "Device Trust",
            "No Duo Desktop registered devices found",
            "Trusted Endpoints via Duo Desktop is not active or no devices have enrolled.",
            "Deploy Duo Desktop to all managed endpoints. This enables device health checks, "
            "OS version enforcement, and the 'trusted endpoint' signal for policies.",
            "This is foundational for zero trust. Without device trust, you're doing "
            "identity verification only — you need both identity AND device posture."
        ))
    else:
        # Check OS versions, encryption status
        os_families = {}
        for d in registered:
            os_fam = d.get("os_family", "Unknown")
            os_families[os_fam] = os_families.get(os_fam, 0) + 1

        os_summary = ", ".join(f"{v}x {k}" for k, v in os_families.items())
        findings.append(Finding(
            Severity.INFO, "Device Trust",
            f"{len(registered)} Duo Desktop devices registered",
            f"OS breakdown: {os_summary}",
            "Verify all corporate endpoints are enrolled and healthy."
        ))

    # Analyze phone fleet
    if phones:
        outdated = []
        platforms = {}
        for p in phones:
            platform = p.get("platform", "Unknown")
            platforms[platform] = platforms.get(platform, 0) + 1

            # Check for very old app versions or unactivated
            if not p.get("activated"):
                outdated.append(p)

        if outdated:
            findings.append(Finding(
                Severity.MEDIUM, "Device Trust",
                f"{len(outdated)} phones not activated",
                "These devices were enrolled but never completed Duo Mobile activation.",
                "Follow up with users to complete enrollment or remove stale entries."
            ))

        plat_summary = ", ".join(f"{v}x {k}" for k, v in platforms.items())
        findings.append(Finding(
            Severity.INFO, "Device Trust",
            f"Phone fleet: {len(phones)} devices ({plat_summary})",
            "Review for platform diversity and ensure Duo Mobile is up to date.",
            ""
        ))

    return findings


def analyze_auth_logs(data: dict) -> list[Finding]:
    """Analyze authentication patterns for anomalies."""
    findings = []
    logs = data.get("auth_logs", [])

    if not logs:
        findings.append(Finding(
            Severity.INFO, "Auth Logs",
            "No auth logs available",
            "Either no authentications in the pull window or insufficient permissions.",
            ""
        ))
        return findings

    # Count results
    results = {}
    for log in logs:
        result = log.get("result", "unknown")
        results[result] = results.get(result, 0) + 1

    denied = results.get("denied", 0) + results.get("fraud", 0)
    success = results.get("success", 0)
    total = len(logs)

    findings.append(Finding(
        Severity.INFO, "Auth Logs",
        f"{total} authentications in pull window",
        f"Success: {success}, Denied: {denied}, Other: {total - success - denied}",
        ""
    ))

    # Check denial rate
    if total > 0 and denied / total > 0.1:
        findings.append(Finding(
            Severity.HIGH, "Auth Logs",
            f"High denial rate: {denied/total:.1%}",
            f"{denied} denials out of {total} attempts.",
            "Investigate denied authentications — could indicate credential attacks, "
            "misconfigured policies, or user friction causing support tickets."
        ))

    # Check for fraud reports
    fraud = results.get("fraud", 0)
    if fraud > 0:
        findings.append(Finding(
            Severity.CRITICAL, "Auth Logs",
            f"{fraud} fraud reports detected",
            "Users reported push notifications they didn't initiate as fraudulent.",
            "Investigate immediately — this indicates active credential compromise attempts."
        ))

    # Check for geographic anomalies (if access_device info available)
    countries = {}
    for log in logs:
        access_device = log.get("access_device", {})
        location = access_device.get("location", {})
        country = location.get("country")
        if country:
            countries[country] = countries.get(country, 0) + 1

    if countries and len(countries) > 1:
        country_summary = ", ".join(f"{v}x {k}" for k, v in
                                     sorted(countries.items(), key=lambda x: -x[1]))
        findings.append(Finding(
            Severity.INFO, "Auth Logs",
            f"Authentications from {len(countries)} countries",
            f"Country breakdown: {country_summary}",
            "Review non-US authentications. Expected for traveling executives and Mexico sites, "
            "but unexpected countries should be investigated.",
            "DanHil operates in the US and Mexico — flag anything outside those."
        ))

    return findings


def analyze_directory_sync(data: dict) -> list[Finding]:
    """Check directory synchronization configuration."""
    findings = []
    syncs = data.get("directory_syncs", [])

    if not syncs:
        findings.append(Finding(
            Severity.HIGH, "Directory Sync",
            "No directory sync configured",
            "Users are being managed manually in Duo, not synced from Active Directory or Entra ID.",
            "Configure directory sync with your AD/Entra ID. This ensures: "
            "1) Users are auto-provisioned/deprovisioned, "
            "2) Group memberships stay current, "
            "3) Terminated users are automatically disabled in Duo.",
            "With 14 sites, manual user management is a security gap. "
            "A terminated employee could retain Duo access indefinitely."
        ))
    else:
        for sync in syncs:
            name = sync.get("name", "Unknown")
            sync_type = sync.get("directory_type", "unknown")
            last_sync = sync.get("last_full_sync_time", "never")
            findings.append(Finding(
                Severity.INFO, "Directory Sync",
                f"Directory sync configured: {name} ({sync_type})",
                f"Last sync: {last_sync}",
                "Ensure sync is running on schedule and not paused."
            ))

    return findings


def analyze_trust_monitor(data: dict) -> list[Finding]:
    """Check Trust Monitor for threat intelligence."""
    findings = []
    events = data.get("trust_monitor_events", [])

    if not events:
        findings.append(Finding(
            Severity.INFO, "Trust Monitor",
            "No Trust Monitor events (or feature not available)",
            "Trust Monitor detects anomalous access patterns automatically.",
            "If this feature is available on your license, verify it's enabled in the Admin Panel."
        ))
    else:
        # Categorize by type
        types = {}
        for e in events:
            t = e.get("type", "unknown")
            types[t] = types.get(t, 0) + 1

        type_summary = ", ".join(f"{v}x {k}" for k, v in types.items())
        findings.append(Finding(
            Severity.MEDIUM, "Trust Monitor",
            f"{len(events)} Trust Monitor events detected",
            f"Event types: {type_summary}",
            "Review each event — Trust Monitor flags impossible travel, "
            "new device enrollments, and other anomalies."
        ))

    return findings


# ─── DanHil-Specific Recommendations ─────────────────────────────────────────

def danhil_recommendations(data: dict) -> list[Finding]:
    """Generate DanHil-specific recommendations based on known context."""
    findings = []

    findings.append(Finding(
        Severity.INFO, "DanHil Roadmap",
        "Recommended Implementation Order",
        "Based on DanHil's 14-site operations with remote sales and traveling executives:",
        "Phase 1 (Immediate): \n"
        "  • Fix bypass users and stale bypass codes\n"
        "  • Set up directory sync with AD/Entra ID\n"
        "  • Create groups: IT, Sales, Executives, Plant Ops, Accounting\n"
        "  • Apply per-group policies\n\n"
        "Phase 2 (30 days): \n"
        "  • Deploy Duo Desktop to all managed endpoints\n"
        "  • Enable device health policies (OS version, encryption, firewall)\n"
        "  • Configure Trusted Endpoints for corporate devices\n"
        "  • Test risk-based auth for executive travel scenarios\n\n"
        "Phase 3 (60 days): \n"
        "  • Duo Network Gateway for agentless app access\n"
        "  • Meraki integration for network-level + identity-level convergence\n"
        "  • Adaptive policies with location awareness (US + Mexico = normal, elsewhere = step-up)\n"
        "  • Remove VPN dependency for standard app access\n\n"
        "Phase 4 (90 days): \n"
        "  • Full zero trust: device trust + identity + risk signal on every access\n"
        "  • Automated device compliance enforcement\n"
        "  • Trust Monitor alerts integrated with your incident response workflow",
        "This maps to your NIST CSF v2.0 gap remediation plan."
    ))

    return findings


# ─── Main ─────────────────────────────────────────────────────────────────────

def find_latest_pull() -> Path:
    """Find the most recent pull JSON in reports/."""
    pulls = sorted(REPORTS_DIR.glob("duo_pull_*.json"), reverse=True)
    if not pulls:
        console.print("[red]No pull files found in reports/. Run 'python -m duo.pull' first.[/]")
        sys.exit(1)
    return pulls[0]


def main():
    console.print("\n[bold green]═══ DanHil Duo Gap Analysis ═══[/]\n")

    # Load data
    if len(sys.argv) > 1:
        pull_path = Path(sys.argv[1])
    else:
        pull_path = find_latest_pull()

    console.print(f"[dim]Analyzing: {pull_path}[/]\n")

    with open(pull_path) as f:
        data = json.load(f)

    # Run all analyzers
    all_findings = []
    analyzers = [
        analyze_account_info,
        analyze_users,
        analyze_groups,
        analyze_integrations,
        analyze_policies,
        analyze_bypass_codes,
        analyze_devices,
        analyze_auth_logs,
        analyze_directory_sync,
        analyze_trust_monitor,
        danhil_recommendations,
    ]

    for analyzer in analyzers:
        all_findings.extend(analyzer(data))

    # Display results
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

    for severity in severity_order:
        findings = [f for f in all_findings if f.severity == severity]
        if not findings:
            continue

        console.print(f"\n[{SEVERITY_COLORS[severity]}]── {severity} ({len(findings)}) ──[/]")
        for f in findings:
            console.print(Panel(
                f"[bold]{f.title}[/]\n\n"
                f"{f.detail}\n\n"
                f"[green]Recommendation:[/] {f.recommendation}"
                + (f"\n\n[cyan]DanHil Context:[/] {f.danhil_context}" if f.danhil_context else ""),
                title=f"[{SEVERITY_COLORS[severity]}]{severity}[/] | {f.category}",
                border_style=SEVERITY_COLORS[severity].split()[0],
            ))

    # Summary counts
    console.print("\n[bold]Finding Summary:[/]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for severity in severity_order:
        count = len([f for f in all_findings if f.severity == severity])
        if count > 0:
            table.add_row(
                Text(severity, style=SEVERITY_COLORS[severity]),
                str(count)
            )
    console.print(table)

    # Save report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = REPORTS_DIR / f"duo_analysis_{timestamp}.md"
    with open(report_path, "w") as f:
        f.write("# DanHil Duo Zero Trust Gap Analysis\n\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write(f"Source: {pull_path.name}\n\n")

        for severity in severity_order:
            findings = [fi for fi in all_findings if fi.severity == severity]
            if not findings:
                continue
            f.write(f"## {severity}\n\n")
            for fi in findings:
                f.write(f"### [{fi.category}] {fi.title}\n\n")
                f.write(f"{fi.detail}\n\n")
                if fi.recommendation:
                    f.write(f"**Recommendation:** {fi.recommendation}\n\n")
                if fi.danhil_context:
                    f.write(f"**DanHil Context:** {fi.danhil_context}\n\n")
                f.write("---\n\n")

    console.print(f"\n[bold green]✓ Analysis report saved to {report_path}[/]")


if __name__ == "__main__":
    main()
