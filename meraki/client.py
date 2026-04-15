"""
Meraki Dashboard API client wrapper — Phase 2.
Will pull network topology, clients, VPN config, and security appliance rules
for cross-reference with Duo identity controls.

TODO:
  - pip install meraki
  - Add MERAKI_API_KEY and MERAKI_ORG_ID to config/.env
  - Pull: organizations, networks, devices, clients, VPN peers,
    security appliance L3/L7 rules, group policies
  - Cross-reference: Meraki client MACs → Duo device trust
  - Cross-reference: Meraki network segmentation → Duo group policies
"""
