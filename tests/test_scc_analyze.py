"""Tests for scc.analyze — zero-trust gap analysis."""

import pytest


# ── Fixture data matching real DanHil shapes ─────────────────────────────────

@pytest.fixture
def pull_data():
    """Realistic pull data based on actual DanHil responses."""
    return {
        "sites": [
            {"originId": 1, "name": "Brownwood", "type": "site", "internalNetworkCount": 2, "vaCount": 0, "siteId": 100},
            {"originId": 2, "name": "Acuna", "type": "site", "internalNetworkCount": 1, "vaCount": 0, "siteId": 101},
            {"originId": 3, "name": "Default Site", "type": "site", "internalNetworkCount": 0, "vaCount": 2, "siteId": 102},
        ],
        "roaming_computers": [
            {"originId": 10, "name": "dhbwd-terryl", "status": "Off", "osVersionName": "Windows 10", "version": "5.1.14"},
            {"originId": 11, "name": "dhacn-maria", "status": "VA", "osVersionName": "Windows 11", "version": "5.1.14"},
            {"originId": 12, "name": "dhacn-jose", "status": "Encrypted", "osVersionName": "Windows 11", "version": "5.1.14"},
            {"originId": 13, "name": "dhlbk-old", "status": "Off", "osVersionName": "Windows 10", "version": "4.9.0"},
        ],
        "tunnel_groups": [
            {"id": 1, "name": "DH Tunnel", "region": "us-east-2", "deviceType": "Meraki MX"},
        ],
        "internal_networks": [
            {"originId": 20, "ipAddress": "192.168.3.0", "prefixLength": 24, "siteName": "Brownwood"},
            {"originId": 21, "ipAddress": "192.168.4.0", "prefixLength": 24, "siteName": "Acuna"},
        ],
        "internal_domains": [
            {"id": 30, "domain": "budgetbox.com", "includeAllVAs": True},
        ],
        "destination_lists": [
            {"id": 40, "name": "Global Allow List", "access": "allow", "isGlobal": True,
             "meta": {"domainCount": 57, "urlCount": 0, "ipv4Count": 0}},
            {"id": 41, "name": "Global Block List", "access": "block", "isGlobal": True,
             "meta": {"domainCount": 10, "urlCount": 0, "ipv4Count": 0}},
        ],
        "users": [
            {"id": 1, "firstname": "Casey", "lastname": "Admin", "role": "Full Admin", "status": "Active", "twoFactorEnable": False, "email": "casey@danhil.com"},
            {"id": 2, "firstname": "David", "lastname": "Analyst", "role": "Read Only", "status": "Active", "twoFactorEnable": False, "email": "david@bps.com"},
        ],
        "roles": [
            {"roleId": 1, "label": "Full Admin"},
            {"roleId": 2, "label": "Read Only"},
        ],
        "integrations": [],
        "categories": [
            {"categoryId": 1, "name": "Malware", "enabled": "y"},
            {"categoryId": 2, "name": "Phishing", "enabled": "y"},
        ],
    }


# ── Severity and Finding ────────────────────────────────────────────────────

class TestFindingModel:
    def test_finding_has_required_fields(self):
        from scc.analyze import Finding, Severity
        f = Finding(Severity.HIGH, "Admin Security", "No 2FA", "Enable 2FA", ["user:casey"])
        assert f.severity == Severity.HIGH
        assert f.category == "Admin Security"
        assert len(f.evidence) == 1

    def test_severity_ordering(self):
        from scc.analyze import Severity
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        assert len(order) == 5


# ── Admin analysis ──────────────────────────────────────────────────────────

class TestAnalyzeUsers:
    def test_flags_no_2fa_as_critical(self, pull_data):
        from scc.analyze import analyze_users
        findings = analyze_users(pull_data)
        critical = [f for f in findings if f.severity == "CRITICAL"]
        assert len(critical) >= 1
        assert any("2FA" in f.title or "MFA" in f.title or "two-factor" in f.title.lower() for f in critical)

    def test_flags_admin_without_2fa(self, pull_data):
        from scc.analyze import analyze_users
        findings = analyze_users(pull_data)
        admin_findings = [f for f in findings if "admin" in f.title.lower() or "admin" in f.category.lower()]
        assert len(admin_findings) >= 1

    def test_no_findings_when_2fa_enabled(self, pull_data):
        from scc.analyze import analyze_users
        for u in pull_data["users"]:
            u["twoFactorEnable"] = True
        findings = analyze_users(pull_data)
        critical = [f for f in findings if f.severity == "CRITICAL"]
        assert len(critical) == 0


# ── Site/deployment analysis ────────────────────────────────────────────────

class TestAnalyzeSites:
    def test_flags_sites_without_vas(self, pull_data):
        from scc.analyze import analyze_sites
        findings = analyze_sites(pull_data)
        va_findings = [f for f in findings if "VA" in f.title or "virtual appliance" in f.title.lower()]
        assert len(va_findings) >= 1

    def test_flags_single_tunnel_group(self, pull_data):
        from scc.analyze import analyze_sites
        findings = analyze_sites(pull_data)
        tunnel_findings = [f for f in findings if "tunnel" in f.title.lower() or "redundan" in f.title.lower()]
        assert len(tunnel_findings) >= 1


# ── Roaming computer analysis ──────────────────────────────────────────────

class TestAnalyzeRoaming:
    def test_flags_offline_agents(self, pull_data):
        from scc.analyze import analyze_roaming_computers
        findings = analyze_roaming_computers(pull_data)
        offline = [f for f in findings if "off" in f.title.lower() or "inactive" in f.title.lower()]
        assert len(offline) >= 1

    def test_flags_outdated_agents(self, pull_data):
        from scc.analyze import analyze_roaming_computers
        findings = analyze_roaming_computers(pull_data)
        # dhlbk-old has version 4.9.0 vs 5.1.14
        outdated = [f for f in findings if "version" in f.title.lower() or "outdated" in f.title.lower() or "update" in f.title.lower()]
        assert len(outdated) >= 1


# ── Destination list analysis ───────────────────────────────────────────────

class TestAnalyzeDestinationLists:
    def test_reports_list_counts(self, pull_data):
        from scc.analyze import analyze_destination_lists
        findings = analyze_destination_lists(pull_data)
        assert len(findings) >= 1  # at minimum an INFO-level summary


# ── Full analysis orchestrator ──────────────────────────────────────────────

class TestRunAnalysis:
    def test_returns_findings_list(self, pull_data):
        from scc.analyze import run_analysis
        findings = run_analysis(pull_data)
        assert isinstance(findings, list)
        assert len(findings) > 0

    def test_includes_all_categories(self, pull_data):
        from scc.analyze import run_analysis
        findings = run_analysis(pull_data)
        categories = set(f.category for f in findings)
        assert len(categories) >= 3  # at least admin, sites, roaming
