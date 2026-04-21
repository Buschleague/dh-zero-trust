"""
Cisco Secure Access zero-trust gap analysis.

Analyzes a pull snapshot against zero-trust best practices tailored
to DanHil Containers (14-site corrugated manufacturer, remote sales,
traveling executives, Mexico + Texas operations).

Usage: python -m scc.analyze [path_to_pull.json]
"""

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
REPORTS_DIR = Path(__file__).parent.parent / "reports"


# ── Finding model ────────────────────────────────────────────────────────────

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

SEVERITY_ORDER = {
    Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
    Severity.LOW: 3, Severity.INFO: 4,
}


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    recommendation: str
    evidence: list = field(default_factory=list)


# ── Analysis functions ───────────────────────────────────────────────────────

def analyze_users(data: dict) -> list[Finding]:
    findings = []
    users = data.get("users", [])
    if not users:
        return [Finding(Severity.MEDIUM, "Admin Security", "No admin users found", "Verify API scope covers user data")]

    no_2fa = [u for u in users if not u.get("twoFactorEnable", False)]
    admins_no_2fa = [u for u in no_2fa if "admin" in u.get("role", "").lower()]

    if admins_no_2fa:
        names = [f"{u['firstname']} {u['lastname']}" for u in admins_no_2fa]
        findings.append(Finding(
            Severity.CRITICAL, "Admin Security",
            "Admin accounts without 2FA/MFA",
            "Enable two-factor authentication for all admin accounts immediately. "
            "Admin accounts are the highest-value targets for credential theft.",
            [f"{n} ({u['role']})" for n, u in zip(names, admins_no_2fa)],
        ))

    readonly_no_2fa = [u for u in no_2fa if "admin" not in u.get("role", "").lower()]
    if readonly_no_2fa:
        names = [f"{u['firstname']} {u['lastname']}" for u in readonly_no_2fa]
        findings.append(Finding(
            Severity.HIGH, "Admin Security",
            "Read-only accounts without 2FA/MFA",
            "Enable 2FA for all console users. Read-only access still exposes "
            "configuration details an attacker could use for reconnaissance.",
            [f"{n} ({u['role']})" for n, u in zip(names, readonly_no_2fa)],
        ))

    if not no_2fa:
        findings.append(Finding(Severity.INFO, "Admin Security", "All users have 2FA enabled", "No action needed"))

    return findings


def analyze_sites(data: dict) -> list[Finding]:
    findings = []
    sites = data.get("sites", [])
    tunnels = data.get("tunnel_groups", [])
    networks = data.get("internal_networks", [])

    # Sites without VAs
    named_sites = [s for s in sites if s.get("name") != "Default Site"]
    no_va = [s for s in named_sites if s.get("vaCount", 0) == 0]
    if no_va:
        findings.append(Finding(
            Severity.HIGH, "Site Security",
            "Sites without virtual appliances (VAs)",
            "Deploy virtual appliances at each site for local DNS enforcement "
            "and redundancy. Without VAs, DNS queries route through the cloud "
            "tunnel only — a single point of failure.",
            [s["name"] for s in no_va],
        ))

    # Single tunnel group for multiple sites
    if len(tunnels) <= 1 and len(named_sites) > 1:
        findings.append(Finding(
            Severity.MEDIUM, "Site Security",
            "Single tunnel group for all sites — no redundancy",
            "Consider regional tunnel groups to reduce blast radius of a tunnel "
            "failure and improve latency for Mexico-based sites.",
            [f"{t['name']} ({t['region']})" for t in tunnels] if tunnels else ["No tunnels configured"],
        ))

    # Sites without internal networks
    sites_with_nets = set(n.get("siteName", "") for n in networks)
    no_nets = [s for s in named_sites if s["name"] not in sites_with_nets]
    if no_nets:
        findings.append(Finding(
            Severity.MEDIUM, "Site Security",
            "Sites with no internal networks defined",
            "Define internal network ranges for each site to enable proper "
            "identity-based policy enforcement.",
            [s["name"] for s in no_nets],
        ))

    if named_sites:
        findings.append(Finding(
            Severity.INFO, "Site Security",
            f"{len(named_sites)} sites configured across {len(sites_with_nets)} networked locations",
            "Review site inventory annually",
            [s["name"] for s in named_sites],
        ))

    return findings


def analyze_roaming_computers(data: dict) -> list[Finding]:
    findings = []
    computers = data.get("roaming_computers", [])
    if not computers:
        return [Finding(Severity.HIGH, "Endpoint Security", "No roaming computers found", "Deploy Cisco Secure Client to all endpoints")]

    total = len(computers)
    offline = [c for c in computers if c.get("status") == "Off"]
    versions = set(c.get("version", "") for c in computers)
    latest = max(versions) if versions else "unknown"
    outdated = [c for c in computers if c.get("version", "") < latest]

    if offline:
        pct = len(offline) / total * 100
        findings.append(Finding(
            Severity.HIGH if pct > 20 else Severity.MEDIUM,
            "Endpoint Security",
            f"{len(offline)}/{total} roaming agents inactive/offline ({pct:.0f}%)",
            "Investigate offline agents — they are not enforcing DNS security "
            "policies. For traveling executives and remote sales staff, this "
            "means they have no zero-trust protection when off-network.",
            [f"{c['name']} (last: {c.get('lastSync', 'unknown')})" for c in offline[:10]],
        ))

    if outdated:
        findings.append(Finding(
            Severity.MEDIUM, "Endpoint Security",
            f"{len(outdated)} agents on outdated versions (latest: {latest})",
            "Standardize all endpoints on the latest Cisco Secure Client version "
            "to ensure consistent security posture and feature parity.",
            [f"{c['name']}: v{c['version']}" for c in outdated[:10]],
        ))

    # OS breakdown
    os_counts: dict[str, int] = {}
    for c in computers:
        os_name = c.get("osVersionName", "Unknown")
        os_counts[os_name] = os_counts.get(os_name, 0) + 1
    findings.append(Finding(
        Severity.INFO, "Endpoint Security",
        f"{total} roaming computers across {len(os_counts)} OS versions",
        "Review OS distribution for end-of-life systems",
        [f"{os}: {count}" for os, count in sorted(os_counts.items(), key=lambda x: -x[1])],
    ))

    return findings


def analyze_destination_lists(data: dict) -> list[Finding]:
    findings = []
    lists = data.get("destination_lists", [])

    allow_lists = [d for d in lists if d.get("access") == "allow"]
    block_lists = [d for d in lists if d.get("access") == "block"]

    global_allow = [d for d in allow_lists if d.get("isGlobal")]
    if global_allow:
        for al in global_allow:
            domain_count = al.get("meta", {}).get("domainCount", 0)
            if domain_count > 50:
                findings.append(Finding(
                    Severity.MEDIUM, "Policy",
                    f"Global allow list has {domain_count} domains",
                    "Review and minimize the global allow list. Large allow lists "
                    "can create bypass paths that undermine DNS security.",
                    [al["name"]],
                ))

    findings.append(Finding(
        Severity.INFO, "Policy",
        f"{len(lists)} destination lists ({len(allow_lists)} allow, {len(block_lists)} block)",
        "Review destination lists quarterly for stale entries",
        [f"{d['name']}: {d['access']}" for d in lists],
    ))

    return findings


def analyze_integrations(data: dict) -> list[Finding]:
    findings = []
    integrations = data.get("integrations", [])
    if not integrations:
        findings.append(Finding(
            Severity.LOW, "Integrations",
            "No third-party integrations configured",
            "Consider integrating with SIEM, SOAR, or ticketing systems "
            "for automated incident response.",
        ))
    return findings


# ── Orchestrator ─────────────────────────────────────────────────────────────

ANALYZERS = [
    analyze_users,
    analyze_sites,
    analyze_roaming_computers,
    analyze_destination_lists,
    analyze_integrations,
]


def run_analysis(data: dict) -> list[Finding]:
    """Run all analyzers against pull data and return sorted findings."""
    findings = []
    for analyzer in ANALYZERS:
        findings.extend(analyzer(data))
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return findings


# ── Output ───────────────────────────────────────────────────────────────────

def print_findings(findings: list[Finding]) -> None:
    """Display findings as Rich panels grouped by severity."""
    for f in findings:
        color = SEVERITY_COLORS.get(f.severity, "white")
        evidence_text = "\n".join(f"  - {e}" for e in f.evidence) if f.evidence else ""
        body = f"{f.recommendation}"
        if evidence_text:
            body += f"\n\n[dim]Evidence:[/dim]\n{evidence_text}"
        console.print(Panel(body, title=f"[{color}][{f.severity}][/{color}] {f.title}", subtitle=f.category, border_style=color))


def save_markdown_report(findings: list[Finding], pull_path: str = "") -> Path:
    """Save findings as a Markdown report."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = REPORTS_DIR / f"scc_analysis_{timestamp}.md"

    lines = [
        "# DanHil Containers — Secure Access Zero-Trust Assessment",
        f"\nGenerated: {datetime.now(timezone.utc).isoformat()}",
        f"Source: {pull_path or 'live pull'}",
        "",
    ]

    by_severity = {}
    for f in findings:
        by_severity.setdefault(f.severity, []).append(f)

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        group = by_severity.get(sev, [])
        if not group:
            continue
        lines.append(f"\n## {sev} ({len(group)} finding{'s' if len(group) != 1 else ''})\n")
        for f in group:
            lines.append(f"### {f.title}\n")
            lines.append(f"**Category:** {f.category}\n")
            lines.append(f"{f.recommendation}\n")
            if f.evidence:
                lines.append("**Evidence:**\n")
                for e in f.evidence:
                    lines.append(f"- {e}")
                lines.append("")

    out_path.write_text("\n".join(lines))
    return out_path


# ── CLI entry point ──────────────────────────────────────────────────────────

def main():
    if len(sys.argv) > 1:
        pull_path = Path(sys.argv[1])
    else:
        pulls = sorted(REPORTS_DIR.glob("scc_pull_*.json"), reverse=True)
        if not pulls:
            console.print("[red]No pull files found. Run 'python -m scc.pull' first.[/red]")
            sys.exit(1)
        pull_path = pulls[0]
        console.print(f"Using latest pull: [bold]{pull_path.name}[/bold]")

    data = json.loads(pull_path.read_text())
    findings = run_analysis(data)
    print_findings(findings)

    report_path = save_markdown_report(findings, str(pull_path))
    console.print(f"\nReport saved to [bold]{report_path}[/bold]")

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = ", ".join(f"{sev}: {c}" for sev, c in sorted(counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 99)))
    console.print(f"\n[bold]Summary:[/bold] {summary}")


if __name__ == "__main__":
    main()
