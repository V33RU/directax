"""Frame-shape assertions for the targeted CVE modules. Zero RF."""
from __future__ import annotations

import struct

from wifidirect_pentest.attacks.cve_2014_0997 import (
    MALFORMED_DEVICE_NAME, build_probe_response,
)
from wifidirect_pentest.attacks.cve_2019_17666 import (
    _noa_attribute, build_beacon, OVERFLOW_NOA_COUNT,
)
from wifidirect_pentest.attacks.cve_2021_0326 import (
    build_pd_request, _malformed_device_info,
)
from wifidirect_pentest.attacks.cve_2021_27803 import (
    build_pd_request as build_pd_27803, _dev_info,
)


def _raw(pkt) -> bytes:
    return bytes(pkt)


# --- CVE-2014-0997 ---

def test_cve_2014_device_name_is_single_nul():
    assert MALFORMED_DEVICE_NAME == b"\x00"


def test_cve_2014_probe_response_carries_nul_device_name():
    pkt = build_probe_response("02:11:22:33:44:aa", "aa:bb:cc:dd:ee:ff")
    raw = _raw(pkt)
    # WSC Device Name TLV: type 0x1011 (BE), length 0x0001, value 0x00
    marker = struct.pack(">HH", 0x1011, 1) + b"\x00"
    assert marker in raw, "malformed WSC Device Name attribute missing"


def test_cve_2014_probe_response_is_actually_probe_response():
    from scapy.layers.dot11 import Dot11, Dot11ProbeResp
    pkt = build_probe_response("02:11:22:33:44:aa", "aa:bb:cc:dd:ee:ff")
    assert pkt.haslayer(Dot11ProbeResp)
    d = pkt.getlayer(Dot11)
    assert d.subtype == 5


# --- CVE-2019-17666 ---

def test_cve_2019_noa_attribute_grows_with_count():
    small = _noa_attribute(1)
    big = _noa_attribute(32)
    # 2 (index+CTWindow) + 13 * count + 3 (attr id + LE length) header
    assert len(big) - len(small) == 13 * (32 - 1)


def test_cve_2019_beacon_contains_noa_id():
    pkt = build_beacon("02:11:22:33:44:bb")
    raw = _raw(pkt)
    # P2P OUI + type, then attribute id 12
    p2p_hdr = b"\x50\x6f\x9a\x09"
    assert p2p_hdr in raw
    idx = raw.find(p2p_hdr) + len(p2p_hdr)
    assert raw[idx] == 12, "first P2P attribute must be NoA (id 12)"


def test_cve_2019_default_count_overflows_fixed_buffer():
    # rtlwifi buffer is MAX_P2P_NOA_DESC = 4
    assert OVERFLOW_NOA_COUNT > 4


# --- CVE-2021-0326 ---

def test_cve_2021_0326_device_info_lies_about_name_length():
    body = _malformed_device_info(b"\x02\x11\x22\x33\x44\xcc")
    # Device Name TLV starts at offset 6+2+8+1 = 17
    dn_hdr = body[17:21]
    aid, alen = struct.unpack(">HH", dn_hdr)
    assert aid == 0x1011
    assert alen == 0xFFFE, "Device Name TLV must claim oversized length"
    # Actual payload is much smaller
    actual = body[21:]
    assert len(actual) < alen


def test_cve_2021_0326_pd_request_is_action_frame():
    from scapy.layers.dot11 import Dot11
    pkt = build_pd_request("02:11:22:33:44:cc", "aa:bb:cc:dd:ee:ff")
    d = pkt.getlayer(Dot11)
    assert d.type == 0 and d.subtype == 13  # Action


def test_cve_2021_0326_pd_request_carries_p2p_pa_header():
    pkt = build_pd_request("02:11:22:33:44:cc", "aa:bb:cc:dd:ee:ff")
    raw = _raw(pkt)
    assert b"\x04\x09\x50\x6f\x9a\x09\x07" in raw, "P2P PA + PD-Req subtype missing"


# --- CVE-2021-27803 ---

def test_cve_2021_27803_dev_info_addr_can_be_spoofed():
    body = _dev_info(b"\x02\xaa\xaa\xaa\xaa\xaa", b"victim-A")
    assert body[:6] == b"\x02\xaa\xaa\xaa\xaa\xaa"


def test_cve_2021_27803_two_frames_have_distinct_src():
    pkt_a = build_pd_27803("02:aa:aa:aa:aa:aa", "aa:bb:cc:dd:ee:ff",
                           "02:aa:aa:aa:aa:aa", dialog=1,
                           dev_name=b"victim-A")
    pkt_b = build_pd_27803("02:bb:bb:bb:bb:bb", "aa:bb:cc:dd:ee:ff",
                           "02:aa:aa:aa:aa:aa", dialog=2,
                           dev_name=b"victim-B")
    from scapy.layers.dot11 import Dot11
    # The two frames have distinct source MAC (SRC_A vs SRC_B on the
    # 802.11 addr2 field); this is what makes the race possible
    assert pkt_a.getlayer(Dot11).addr2 != pkt_b.getlayer(Dot11).addr2
    # But both advertise Device Info attributes that name the SAME
    # spoofed device address (the peer-entry reuse step)
    assert b"\x02\xaa\xaa\xaa\xaa\xaa" in _raw(pkt_a)
    assert b"\x02\xaa\xaa\xaa\xaa\xaa" in _raw(pkt_b)
    # And the device names are actually embedded in the frames
    assert b"victim-A" in _raw(pkt_a)
    assert b"victim-B" in _raw(pkt_b)


def test_cve_reproducers_export_confirmed_bool():
    """Every CVE runner must return a dict with a 'confirmed' bool key
    per the DIRECTAX finding schema."""
    import inspect
    from wifidirect_pentest.attacks import (
        cve_2014_0997, cve_2019_17666, cve_2021_0326, cve_2021_27803,
    )
    for mod in (cve_2014_0997, cve_2019_17666,
                cve_2021_0326, cve_2021_27803):
        cls = [c for _, c in inspect.getmembers(mod, inspect.isclass)
               if _.startswith("CVE_")][0]
        src = inspect.getsource(cls.run)
        assert '"confirmed"' in src, f"{cls.__name__}.run must set 'confirmed'"
