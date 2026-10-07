"""Phase 1 W-spec foundation: profile loader, authz gate, evidence store."""
import json
import os

import pytest

from wifidirect_pentest.core.profile import loadProfile, TargetProfile
from wifidirect_pentest.core.authz import (
    buildContext, AuthorizationError,
)
from wifidirect_pentest.core.evidence import EvidenceStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_crestron_profile_loads():
    path = os.path.join(ROOT, "profiles", "crestron-am-tx3-110.yaml")
    profile = loadProfile(path)
    assert profile.name == "Crestron AM-TX3-110"
    assert profile.ssidPattern == "DIRECT-*"
    assert profile.targetBssid == "auto"
    assert profile.bssidResolved() is False
    assert profile.wants5ghz() is True
    assert profile.linkCrypto == "wpa2_ccmp"
    assert profile.role == "client"


def test_profile_ssid_matching():
    profile = TargetProfile(
        name="x", ssidPattern="DIRECT-*", targetBssid="auto",
        bands=["5GHz"], linkCrypto="wpa2_ccmp", role="client")
    assert profile.ssidMatches("DIRECT-a9-Crestron")
    assert not profile.ssidMatches("HomeWiFi")


def test_profile_missing_required_key(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("role: client\n")
    with pytest.raises(ValueError):
        loadProfile(str(bad))


def test_authz_requires_operator_and_token(tmp_path):
    profile = loadProfile(os.path.join(ROOT, "profiles",
                                       "crestron-am-tx3-110.yaml"))
    with pytest.raises(AuthorizationError):
        buildContext("", "tok", profile, None, False, str(tmp_path / "r"))
    with pytest.raises(AuthorizationError):
        buildContext("op", "", profile, None, False, str(tmp_path / "r"))


def test_authz_writes_run_log(tmp_path):
    profile = loadProfile(os.path.join(ROOT, "profiles",
                                       "crestron-am-tx3-110.yaml"))
    runDir = str(tmp_path / "run")
    ctx = buildContext("veera", "AUTH-123", profile,
                       "02:aa:bb:cc:dd:ee", True, runDir)
    logPath = os.path.join(runDir, "authz.json")
    assert os.path.exists(logPath)
    with open(logPath) as handle:
        record = json.load(handle)
    assert record["authorization"]["operator"] == "veera"
    assert record["authorization"]["token"] == "AUTH-123"
    assert record["authorization"]["target_bssid"] == "02:aa:bb:cc:dd:ee"
    assert record["profile"]["name"] == "Crestron AM-TX3-110"


def test_active_module_blocked_without_optin(tmp_path):
    profile = loadProfile(os.path.join(ROOT, "profiles",
                                       "crestron-am-tx3-110.yaml"))
    ctx = buildContext("op", "tok", profile, "02:aa:bb:cc:dd:ee",
                       False, str(tmp_path / "r"))
    with pytest.raises(AuthorizationError):
        ctx.requireActive("W5-deauth")


def test_active_module_blocked_without_explicit_target(tmp_path):
    profile = loadProfile(os.path.join(ROOT, "profiles",
                                       "crestron-am-tx3-110.yaml"))
    # activeOptin true but target still 'auto'
    ctx = buildContext("op", "tok", profile, None, True, str(tmp_path / "r"))
    with pytest.raises(AuthorizationError):
        ctx.requireActive("W5-deauth")


def test_confinement_single_target(tmp_path):
    profile = loadProfile(os.path.join(ROOT, "profiles",
                                       "crestron-am-tx3-110.yaml"))
    ctx = buildContext("op", "tok", profile, "02:AA:BB:CC:DD:EE",
                       True, str(tmp_path / "r"))
    assert ctx.confinedTo("02:aa:bb:cc:dd:ee") is True
    assert ctx.confinedTo("11:22:33:44:55:66") is False
    assert ctx.confinedTo("") is False


def test_evidence_store_layout(tmp_path):
    store = EvidenceStore(str(tmp_path / "run"))
    assert os.path.isdir(store.pcapDir())
    assert os.path.isdir(store.moduleDir())
    path = store.writeModuleResult("W1-discover", {"bssid": "02:aa:bb:cc:dd:ee"})
    assert os.path.exists(path)
    results = store.readModuleResults()
    assert "W1-discover" in results
    assert results["W1-discover"]["bssid"] == "02:aa:bb:cc:dd:ee"
    assert results["W1-discover"]["module"] == "W1-discover"
