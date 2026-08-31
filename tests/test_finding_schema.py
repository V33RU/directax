import json
import os

from wifidirect_pentest.core import finding_builders as fb
from wifidirect_pentest.core.finding import Confidence
from wifidirect_pentest.reporting import NoveltyGate

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _schema():
    with open(os.path.join(ROOT, "docs", "finding-schema.json")) as f:
        return json.load(f)


def _validate(f_dict: dict, schema: dict):
    for k in schema["required"]:
        assert k in f_dict, f"missing {k}"
    # location shape
    assert "value" in f_dict["location"]


def test_pixie_finding_matches_schema():
    schema = _schema()
    f = fb.build_pixie_finding("aa:bb:cc:dd:ee:ff", {
        "confirmed": True, "pin": "12345670", "psk": "x",
        "ssid": "DIRECT-XX-T", "log_path": "/tmp/p.log",
    })
    assert f is not None
    d = f.to_dict()
    _validate(d, schema)
    assert d["confidence"] == "confirmed"
    assert d["cvss_v40_vector"].startswith("CVSS:4.0/")


def test_deauth_confirmed_only_when_captured():
    assert fb.build_deauth_finding("aa:bb:cc:dd:ee:ff", {"confirmed": False}) is None
    f = fb.build_deauth_finding("aa:bb:cc:dd:ee:ff",
                                {"confirmed": True, "evidence_pcap": "/tmp/x.pcap"})
    assert f.confidence == Confidence.CONFIRMED


def test_novelty_flags_pixie_as_cve_2014_9569():
    f = fb.build_pixie_finding("aa:bb:cc:dd:ee:ff", {
        "confirmed": True, "pin": "1", "psk": "x", "ssid": "y", "log_path": "z",
    })
    NoveltyGate().apply([f])
    assert f.novelty.checked is True
    assert f.novelty.known_cve == "CVE-2014-9569"


def test_wps_pin_novelty_hits():
    f = fb.build_wps_pin_finding("aa:bb:cc:dd:ee:ff", {
        "confirmed": True, "pin": "1", "psk": "x", "ssid": "y", "log_path": "z",
    })
    NoveltyGate().apply([f])
    assert f.novelty.known_cve == "CVE-2011-5053"
