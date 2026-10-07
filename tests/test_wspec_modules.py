"""W2/W4/W5/W6/W7 module tests (no RF: frame builders, classifiers,
guards, report aggregation)."""
import os

import pytest

from wifidirect_pentest.scanners.pairing import (
    classifyConfigMethod, CM_PBC, DPID_PBC,
)
from wifidirect_pentest.scanners.wps import WPSFacts
from wifidirect_pentest.attacks.linkcrypto import (
    LinkCryptoTest, FRAGATTACKS_CASES, FRAGATTACKS_DESIGN_CVES,
)
from wifidirect_pentest.attacks.availability import AvailabilityTest
from wifidirect_pentest.core.authz import buildContext, AuthorizationError
from wifidirect_pentest.core.profile import loadProfile
from wifidirect_pentest.core.evidence import EvidenceStore
from wifidirect_pentest.reporting.wireless_report import buildReport, writeReports

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _wpsFacts(**kw):
    defaults = dict(
        wps_present=True, version=0x10, config_methods_hex="0x0088",
        config_methods_labels=["PushButton", "Display"],
        pbc_supported=True, pin_supported=False, ap_setup_locked=False,
        device_password_id=DPID_PBC, selected_registrar=True,
        device_name="Crestron", manufacturer="Crestron", model_name="AM-TX3",
        model_number="110", uuid_e=None, manageability=None,
        primary_device_type="7-0050f204-1")
    defaults.update(kw)
    return WPSFacts(**defaults)


# --- W2 pairing classification ---

def test_w2_classifies_pbc():
    result = classifyConfigMethod(_wpsFacts())
    assert result.configMethod == "PBC"
    assert result.pbcSupported is True


def test_w2_classifies_pin():
    facts = _wpsFacts(pbc_supported=False, pin_supported=True,
                      device_password_id=0x0000)
    result = classifyConfigMethod(facts)
    assert result.configMethod == "PIN"


# --- W4 linkcrypto ---

def test_w4_reports_tool_absence_without_crashing(tmp_path):
    test = LinkCryptoTest("wlan0mon", "02:aa:bb:cc:dd:ee", 36, "DIRECT-x",
                          krackPath="/nonexistent/krack.py",
                          fragattacksPath="/nonexistent/frag.py",
                          evidenceDir=str(tmp_path))
    result = test.run()
    assert result["cipher"] == "CCMP"
    assert result["krack_verdict"] == "tool-missing"
    assert result["tools_present"]["krackattacks"] is False
    # Matrix still enumerates every case, marked tool-missing
    assert len(result["fragattacks_matrix"]) == len(FRAGATTACKS_CASES)
    assert all(c["result"] == "tool-missing"
               for c in result["fragattacks_matrix"])
    assert "CVE-2020-24586" in result["fragattacks_design_cves"]


# --- W5 availability guards ---

def _ctx(tmp_path, active=True, bssid="02:aa:bb:cc:dd:ee"):
    profile = loadProfile(os.path.join(ROOT, "profiles",
                                       "crestron-am-tx3-110.yaml"))
    return buildContext("op", "tok", profile, bssid, active,
                        str(tmp_path / "run"))


def test_w5_refuses_broadcast(tmp_path):
    ctx = _ctx(tmp_path)
    test = AvailabilityTest("wlan0mon", "02:aa:bb:cc:dd:ee",
                            "ff:ff:ff:ff:ff:ff", ctx)
    with pytest.raises(AuthorizationError):
        test.run()


def test_w5_refuses_wrong_target(tmp_path):
    ctx = _ctx(tmp_path, bssid="02:aa:bb:cc:dd:ee")
    test = AvailabilityTest("wlan0mon", "11:22:33:44:55:66",
                            "02:00:00:00:00:01", ctx)
    with pytest.raises(AuthorizationError):
        test.run()


def test_w5_refuses_without_active_optin(tmp_path):
    ctx = _ctx(tmp_path, active=False)
    test = AvailabilityTest("wlan0mon", "02:aa:bb:cc:dd:ee",
                            "02:00:00:00:00:01", ctx)
    with pytest.raises(AuthorizationError):
        test.run()


# --- W7 reporter ---

def test_w7_ranks_findings_and_writes(tmp_path):
    store = EvidenceStore(str(tmp_path / "run"))
    store.writeModuleResult("W3-wps", {
        "pixie_verdict": "vulnerable", "pin": "12345670", "psk": "secret",
        "log_path": "pcaps/wps.log"})
    store.writeModuleResult("W4-linkcrypto", {
        "cipher": "CCMP", "krack_verdict": "not-vulnerable",
        "fragattacks_matrix": [
            {"case": "ping", "result": "vulnerable", "log": "frag.log"}]})
    store.writeModuleResult("W2-pairing", {
        "config_method": "PBC",
        "unpaired_peer_behavior": "prompt-or-accept"})
    report = buildReport(store)
    severities = [f["severity"] for f in report["findings"]]
    # critical (pixie) must rank before high (frag) before medium (pairing)
    assert severities == sorted(
        severities, key=lambda s: {"critical": 0, "high": 1, "medium": 2}[s])
    assert report["findings"][0]["severity"] == "critical"
    jsonPath, mdPath = writeReports(store)
    assert os.path.exists(jsonPath)
    assert os.path.exists(mdPath)
    with open(mdPath) as handle:
        md = handle.read()
    assert "Wireless Audit Report" in md
    assert "Pixie Dust" in md
