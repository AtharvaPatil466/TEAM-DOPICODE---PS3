"""Rulebook tests. Focused on:

- Topology gate (_edge_reachable): external→internal only via gateway, etc.
- High-value rules EXP-001, CRED-001, NET-001, NET-002, DATA-001, SHADOW-001.
- Determinism of evaluate_all/rulebook.
"""
from backend.intelligence import edge_rules as er

from .conftest import StubAsset, StubCVE, default_ctx


def _gateway_apache() -> StubAsset:
    return StubAsset(
        id=1,
        ip_address="172.28.0.10",
        hostname="shadowlab-apache",
        exposure="internal",
        tech_stack={"internet_exposed": True},
        cves=[
            StubCVE(
                cve_id="CVE-2021-41773",
                cvss_score=9.8,
                attack_vector="NETWORK",
                attack_complexity="LOW",
                description="path traversal leading to remote code execution in Apache HTTP Server 2.4.49",
                in_kev=True,
                kev_ransomware=False,
            )
        ],
    )


def _mysql_crown() -> StubAsset:
    return StubAsset(
        id=2,
        ip_address="172.28.0.20",
        hostname="shadowlab-mysql",
        exposure="internal",
        is_crown_jewel=True,
    )


def _plain_internal(ip: str = "172.28.0.50") -> StubAsset:
    return StubAsset(id=3, ip_address=ip, exposure="internal")


def _external(ip: str = "203.0.113.5") -> StubAsset:
    return StubAsset(id=4, ip_address=ip, exposure="external")


# --- topology gate --------------------------------------------------------

def test_reachable_internet_to_external():
    assert er._edge_reachable(None, _external(), default_ctx()) is True


def test_reachable_internet_to_gateway():
    assert er._edge_reachable(None, _gateway_apache(), default_ctx()) is True


def test_unreachable_internet_to_plain_internal():
    assert er._edge_reachable(None, _plain_internal(), default_ctx()) is False


def test_unreachable_external_to_plain_internal():
    assert er._edge_reachable(_external(), _plain_internal(), default_ctx()) is False


def test_reachable_external_to_gateway():
    assert er._edge_reachable(_external(), _gateway_apache(), default_ctx()) is True


def test_unreachable_internal_to_external():
    assert er._edge_reachable(_plain_internal(), _external(), default_ctx()) is False


def test_reachable_same_subnet_internal_pair():
    a = _plain_internal("172.28.0.10")
    b = _plain_internal("172.28.0.50")
    assert er._edge_reachable(a, b, default_ctx()) is True


def test_unreachable_cross_subnet_internal_pair():
    a = _plain_internal("172.28.0.10")
    b = _plain_internal("10.0.0.10")
    assert er._edge_reachable(a, b, default_ctx()) is False


# --- EXP-001 (remote exploit) ---------------------------------------------

def test_exp_001_fires_on_internet_to_gateway_with_rce_cve():
    match = er._exp_001(None, _gateway_apache(), default_ctx())
    assert match is not None
    assert match.rule_id == "EXP-001"
    assert match.evidence["cve_id"] == "CVE-2021-41773"
    # KEV-listed → weight_modifier tightens to 0.35 (not ransomware → not 0.3)
    assert match.weight_modifier == 0.35


def test_exp_001_ransomware_kev_gets_lowest_weight():
    dst = _gateway_apache()
    dst.cves[0].kev_ransomware = True
    match = er._exp_001(None, dst, default_ctx())
    assert match is not None and match.weight_modifier == 0.3


def test_exp_001_skips_when_topology_gate_fails():
    # external src → plain internal dst: gate blocks, no rule regardless of CVE
    dst = _plain_internal()
    dst.cves = [
        StubCVE(cve_id="CVE-X", cvss_score=9.0, attack_vector="NETWORK",
                description="remote code execution")
    ]
    assert er._exp_001(_external(), dst, default_ctx()) is None


def test_exp_001_requires_network_vector():
    dst = _gateway_apache()
    dst.cves = [
        StubCVE(cve_id="CVE-L", cvss_score=9.0, attack_vector="LOCAL",
                description="remote code execution")
    ]
    assert er._exp_001(None, dst, default_ctx()) is None


# --- NET-002 (internet reachability) --------------------------------------

def test_net_002_fires_for_external_asset():
    match = er._net_002(None, _external(), default_ctx())
    assert match is not None and match.rule_id == "NET-002"


def test_net_002_fires_for_internet_exposed_internal_gateway():
    match = er._net_002(None, _gateway_apache(), default_ctx())
    assert match is not None and match.rule_id == "NET-002"


def test_net_002_skips_plain_internal():
    assert er._net_002(None, _plain_internal(), default_ctx()) is None


def test_net_002_requires_src_none():
    assert er._net_002(_external(), _external(), default_ctx()) is None


# --- NET-001 (lateral) / DATA-001 (crown jewel) / SHADOW-001 ---------------

def test_net_001_fires_only_same_subnet_internal():
    src = _plain_internal("172.28.0.10")
    dst = _plain_internal("172.28.0.20")
    assert er._net_001(src, dst, default_ctx()) is not None
    assert er._net_001(src, _plain_internal("10.0.0.20"), default_ctx()) is None


def test_data_001_only_on_crown_jewel():
    src = _plain_internal("172.28.0.10")
    assert er._data_001(src, _mysql_crown(), default_ctx()) is not None
    assert er._data_001(src, _plain_internal("172.28.0.20"), default_ctx()) is None


def test_shadow_001_requires_shadow_source():
    src = _plain_internal("172.28.0.40")
    src.is_shadow_device = True
    dst = _mysql_crown()
    assert er._shadow_001(src, dst, default_ctx()) is not None
    src.is_shadow_device = False
    assert er._shadow_001(src, dst, default_ctx()) is None


# --- CRED-001 (credential path) -------------------------------------------

def _cred_login_target() -> StubAsset:
    return StubAsset(
        id=5,
        ip_address="172.28.0.60",
        exposure="internal",
        tech_stack={"internet_exposed": True},
        admin_panels=[{"path": "/admin/login", "auth": False}],
        cves=[
            StubCVE(cve_id="CVE-AUTH", cvss_score=9.1, attack_vector="NETWORK",
                    description="authentication bypass in login form")
        ],
    )


def test_cred_001_fires_when_login_no_mfa_and_auth_cve():
    match = er._cred_001(None, _cred_login_target(), default_ctx())
    assert match is not None and match.rule_id == "CRED-001"


def test_cred_001_suppressed_by_mfa_signal():
    dst = _cred_login_target()
    dst.tech_stack = {**(dst.tech_stack or {}), "mfa": "okta verify enforced"}
    assert er._cred_001(None, dst, default_ctx()) is None


def test_cred_001_requires_reachable_topology():
    dst = _cred_login_target()
    dst.tech_stack = {}  # no longer a gateway
    assert er._cred_001(None, dst, default_ctx()) is None


# --- evaluate_all / rulebook ---------------------------------------------

def test_evaluate_all_returns_multiple_rules_for_gateway():
    matches = er.evaluate_all(None, _gateway_apache(), default_ctx())
    rule_ids = {m.rule_id for m in matches}
    assert "EXP-001" in rule_ids
    assert "NET-002" in rule_ids


def test_rulebook_ids_unique_and_stable():
    ids = [rule["id"] for rule in er.rulebook()]
    assert len(ids) == len(set(ids))
    assert er.RULES_BY_ID.keys() == set(ids)
