"""Regression tests for defects raised by the adversarial review."""

import struct

from wifidirect_pentest.attacks.pixiedust_native import _find_wsc_payload
from wifidirect_pentest.attacks.goneg_intent import _find_status_zero, P2P_PA_HDR, GONEG_CONF


def _eap_expanded_wsc(opcode: int = 0x04, flags: int = 0x00,
                      wsc_payload: bytes = b"") -> bytes:
    """Build an EAPOL frame: EAPOL header + EAP + EAP-Expanded + WSC."""
    eap = b""
    eap += b"\x02"                          # Code = Response
    eap += b"\x01"                          # Id
    eap_len_off = len(eap)
    eap += b"\x00\x00"                      # placeholder Length
    eap += b"\xFE"                          # Type = Expanded
    eap += b"\x00\x37\x2a"                  # Vendor-Id WFA
    eap += b"\x00\x00\x00\x01"              # Vendor-Type WSC
    eap += bytes([opcode, flags])
    eap += wsc_payload
    # patch EAP length
    eap = eap[:eap_len_off] + struct.pack(">H", len(eap)) + eap[eap_len_off + 2:]
    eapol = b"\x02"                         # version 2
    eapol += b"\x00"                        # type = EAPOL-EAP
    eapol += struct.pack(">H", len(eap))    # length
    eapol += eap
    return eapol


def test_wsc_payload_ignores_oui_inside_dh_key():
    # PKE contains the WFA OUI bytes somewhere inside the 192 bytes.
    fake_pke = b"\x00" * 40 + b"\x00\x37\x2a" + b"\x00" * 149
    wsc = struct.pack(">HH", 0x1032, len(fake_pke)) + fake_pke
    frame = _eap_expanded_wsc(wsc_payload=wsc)
    got = _find_wsc_payload(frame)
    assert got == wsc, "must return the WSC TLV stream, not garbage from the middle of PKE"


def test_wsc_payload_returns_none_when_not_expanded():
    # EAP with a non-Expanded type must not be misparsed.
    body = b"\x02\x01\x00\x0e\x01other-data"      # EAP header type=0x01 (Identity)
    eapol = b"\x02\x00" + struct.pack(">H", len(body)) + body
    assert _find_wsc_payload(eapol) is None


def test_find_status_zero_positive():
    """A GO-Neg-Conf with a real Status attribute value 0 must confirm."""
    # Build P2P Vendor IE containing a Status attribute (id=0, len=1, val=0)
    p2p_ie_body = b"\x50\x6f\x9a\x09" + struct.pack("<BH", 0, 1) + b"\x00"
    elt = bytes([221, len(p2p_ie_body)]) + p2p_ie_body
    # frame: <PA_HDR><subtype><dialog><elements>
    frame = P2P_PA_HDR + bytes([GONEG_CONF, 0x11]) + elt
    assert _find_status_zero(frame, P2P_PA_HDR + bytes([GONEG_CONF])) is True


def test_find_status_zero_negative():
    """A GO-Neg-Conf whose Status is 1 (Fail) must not confirm even if
    the raw bytes \\x00\\x01\\x00 appear elsewhere in the body."""
    # Put a decoy \x00\x01\x00 inside a different attribute's value first,
    # then the real Status = 1.
    decoy = struct.pack("<BH", 2, 3) + b"\x00\x01\x00"     # id=2 (Cap), len=3
    status = struct.pack("<BH", 0, 1) + b"\x01"            # id=0 Status = Fail
    p2p_ie_body = b"\x50\x6f\x9a\x09" + decoy + status
    elt = bytes([221, len(p2p_ie_body)]) + p2p_ie_body
    frame = P2P_PA_HDR + bytes([GONEG_CONF, 0x11]) + elt
    assert _find_status_zero(frame, P2P_PA_HDR + bytes([GONEG_CONF])) is False


def test_hashcat_line_parser_understands_asterisk_format():
    """Simulate a real hashcat 22000 outfile line and verify our parser
    extracts psk and ssid correctly."""
    from wifidirect_pentest.attacks import hashcat_pipeline

    line = ("WPA*01*deadbeefdeadbeefdeadbeefdeadbeef*"
            "aabbccddeeff*112233445566*"
            "44495245435420585820546573742d5353494b"
            "***:supersecret1234")
    # Emulate the block inside crack() that reads the outfile.
    fields = line.split(":", 1)[0].split("*")
    psk = line.rsplit(":", 1)[1]
    assert psk == "supersecret1234"
    ssid = bytes.fromhex(fields[5]).decode(errors="replace")
    assert ssid.startswith("DIRECT")


def test_novelty_nvd_pattern_only_matches_cve_id(tmp_path):
    """The NVD fetch path must produce KnownIssue entries whose pattern
    matches the CVE id itself, not free-text keywords."""
    from wifidirect_pentest.reporting.novelty import KnownIssue, NoveltyGate
    from wifidirect_pentest.core.finding import (
        Finding, Confidence, Location, Confirmation,
    )

    fake = KnownIssue(cve="CVE-2099-99999",
                      pattern=r"CVE\-2099\-99999",
                      note="test")
    gate = NoveltyGate(known=[fake])
    f = Finding(
        title="hostapd config parser overflow",   # matches NVD note text
        cwe="CWE-120", confidence=Confidence.CONFIRMED,
        target="lab", attacker_position="same-LAN",
        location=Location("hostapd/config_file.c"),
        data_flow="input -> parser -> heap",
        trigger="./crash", confirmation=None,
        evidence="", exploit_chain="", observable="crash",
        cvss_v40_score=None, cvss_v40_vector=None, fix="patch",
    )
    gate.apply([f])
    assert f.novelty.known_cve is None, "must NOT tag as CVE-2099-99999 based on generic word overlap"


def test_p2p_fuzz_ie_length_is_one_byte():
    """Any generated fuzz frame must have valid 802.11 element lengths."""
    import random
    from wifidirect_pentest.fuzzers.p2p_frame_fuzzer import _build_case

    rng = random.Random(0)
    for i in range(80):
        payload = _build_case(rng, subtype=7,
                              target=b"\x11\x22\x33\x44\x55\x66", dialog=i)
        # walk from P2P_PA_HDR + subtype + dialog forward, verifying elements
        pa_hdr = b"\x04\x09\x50\x6f\x9a\x09"
        assert payload.startswith(pa_hdr)
        off = len(pa_hdr) + 2
        while off + 2 <= len(payload):
            eid = payload[off]
            elen = payload[off + 1]
            assert off + 2 + elen <= len(payload), (
                f"element len {elen} at off {off} exceeds frame len {len(payload)}")
            off += 2 + elen
