"""Tests for scc.pull — Secure Access configuration extraction."""

import json
import time
from pathlib import Path
from unittest.mock import patch, MagicMock, call

import pytest


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_client():
    """Mock SccClient with canned responses matching real API shapes."""
    client = MagicMock()

    responses = {
        "/deployments/v2/sites": [
            {"originId": 1, "name": "Brownwood", "type": "site", "siteId": 100, "internalNetworkCount": 2, "vaCount": 0},
            {"originId": 2, "name": "Acuna", "type": "site", "siteId": 101, "internalNetworkCount": 1, "vaCount": 0},
        ],
        "/deployments/v2/roamingcomputers": [
            {"originId": 10, "deviceId": "abc123", "name": "dhbwd-terryl", "status": "On", "osVersionName": "Windows 10", "version": "5.1.14"},
            {"originId": 11, "deviceId": "def456", "name": "dhacn-maria", "status": "Off", "osVersionName": "Windows 11", "version": "5.1.14"},
        ],
        "/deployments/v2/networktunnelgroups": {
            "data": [{"id": 1, "name": "DH Tunnel", "region": "us-east-2", "deviceType": "Meraki MX"}],
            "total": 1,
        },
        "/deployments/v2/internalnetworks": [
            {"originId": 20, "ipAddress": "192.168.3.0", "prefixLength": 24, "siteName": "Brownwood", "name": "DH Brownwood"},
        ],
        "/deployments/v2/internaldomains": [
            {"id": 30, "domain": "budgetbox.com", "includeAllVAs": True},
        ],
        "/policies/v2/destinationlists": {
            "data": [
                {"id": 40, "name": "Global Allow List", "access": "allow", "isGlobal": True},
                {"id": 41, "name": "Global Block List", "access": "block", "isGlobal": True},
            ],
            "meta": {"total": 2},
            "status": {"code": 200},
        },
        "/policies/v2/categories": [
            {"categoryId": 1, "name": "Malware", "enabled": "y"},
            {"categoryId": 2, "name": "Phishing", "enabled": "y"},
        ],
        "/admin/v2/users": [
            {"id": 1, "firstname": "Blake", "lastname": "Bratu", "email": "bbratu@cisco.com", "role": "Read Only", "status": "Active", "twoFactorEnable": False},
            {"id": 2, "firstname": "Casey", "lastname": "Admin", "email": "casey@danhil.com", "role": "Full Admin", "status": "Active", "twoFactorEnable": False},
        ],
        "/admin/v2/roles": [
            {"roleId": 1, "label": "Full Admin"},
            {"roleId": 2, "label": "Read Only"},
        ],
        "/admin/v2/integrations": {"data": [], "total": 0},
    }

    def mock_get(path, params=None):
        if path in responses:
            return responses[path]
        raise Exception(f"Unmocked endpoint: {path}")

    def mock_paginated_get(path, params=None, page_size=100):
        resp = responses.get(path, [])
        if isinstance(resp, list):
            return resp
        return resp.get("data", [])

    client.get.side_effect = mock_get
    client.paginated_get.side_effect = mock_paginated_get
    return client


@pytest.fixture
def reports_dir(tmp_path):
    return tmp_path / "reports"


# ── Individual pull functions ────────────────────────────────────────────────

class TestPullFunctions:
    def test_pull_sites(self, mock_client):
        from scc.pull import pull_sites
        result = pull_sites(mock_client)
        assert len(result) == 2
        assert result[0]["name"] == "Brownwood"

    def test_pull_roaming_computers(self, mock_client):
        from scc.pull import pull_roaming_computers
        result = pull_roaming_computers(mock_client)
        assert len(result) == 2
        assert result[0]["name"] == "dhbwd-terryl"

    def test_pull_tunnel_groups(self, mock_client):
        from scc.pull import pull_tunnel_groups
        result = pull_tunnel_groups(mock_client)
        assert len(result) == 1
        assert result[0]["deviceType"] == "Meraki MX"

    def test_pull_internal_networks(self, mock_client):
        from scc.pull import pull_internal_networks
        result = pull_internal_networks(mock_client)
        assert len(result) == 1
        assert result[0]["ipAddress"] == "192.168.3.0"

    def test_pull_internal_domains(self, mock_client):
        from scc.pull import pull_internal_domains
        result = pull_internal_domains(mock_client)
        assert len(result) == 1
        assert result[0]["domain"] == "budgetbox.com"

    def test_pull_destination_lists(self, mock_client):
        from scc.pull import pull_destination_lists
        result = pull_destination_lists(mock_client)
        assert len(result) == 2
        assert result[0]["access"] == "allow"

    def test_pull_categories(self, mock_client):
        from scc.pull import pull_categories
        result = pull_categories(mock_client)
        assert len(result) == 2

    def test_pull_users(self, mock_client):
        from scc.pull import pull_users
        result = pull_users(mock_client)
        assert len(result) == 2
        assert result[0]["role"] == "Read Only"

    def test_pull_roles(self, mock_client):
        from scc.pull import pull_roles
        result = pull_roles(mock_client)
        assert len(result) == 2

    def test_pull_integrations(self, mock_client):
        from scc.pull import pull_integrations
        result = pull_integrations(mock_client)
        assert result == []


# ── Report activity ──────────────────────────────────────────────────────────

class TestPullActivity:
    def test_pull_activity_uses_epoch_ms(self, mock_client):
        from scc.pull import pull_activity

        mock_client.get.side_effect = None
        mock_client.get.return_value = {"data": [{"domain": "example.com"}], "meta": {"successful": ["dns"]}}

        result = pull_activity(mock_client, days=7)
        call_args = mock_client.get.call_args
        params = call_args.kwargs.get("params") or call_args.args[1] if len(call_args.args) > 1 else call_args.kwargs.get("params", {})
        # Verify timestamps are epoch ms (> 1e12)
        assert int(params["from"]) > 1e12
        assert int(params["to"]) > 1e12


# ── Main orchestrator ────────────────────────────────────────────────────────

class TestPullMain:
    def test_main_saves_json(self, mock_client, reports_dir):
        from scc.pull import run_full_pull

        mock_client.get.side_effect = None
        mock_client.get.return_value = {"data": [], "meta": {}}
        mock_client.paginated_get.return_value = []

        result = run_full_pull(mock_client, reports_dir=reports_dir)

        assert reports_dir.exists()
        json_files = list(reports_dir.glob("scc_pull_*.json"))
        assert len(json_files) == 1
        saved = json.loads(json_files[0].read_text())
        assert "metadata" in saved
        assert "sites" in saved

    def test_main_returns_pull_data(self, mock_client, reports_dir):
        from scc.pull import run_full_pull

        mock_client.get.side_effect = None
        mock_client.get.return_value = {"data": [], "meta": {}}
        mock_client.paginated_get.return_value = []

        result = run_full_pull(mock_client, reports_dir=reports_dir)
        assert isinstance(result, dict)
        assert "sites" in result
        assert "metadata" in result
