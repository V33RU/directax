import struct

from wifidirect_pentest.core.wfd_ie import (
    parse_wfd_ie, SE_DEVICE_INFO, SE_ASSOCIATED_BSSID,
    SE_COUPLED_SINK_INFO, SE_LOCAL_IP, SE_SESSION_INFO,
    BIT_CONTENT_PROTECTION,
)


def _sub(sid: int, body: bytes) -> bytes:
    return bytes([sid]) + struct.pack(">H", len(body)) + body


def test_wfd_device_info_primary_sink_with_hdcp():
    flags = 1 | 0x0010 | BIT_CONTENT_PROTECTION  # primary-sink, available, HDCP
    body = struct.pack(">HHH", flags, 7236, 300)
    payload = _sub(SE_DEVICE_INFO, body)
    info = parse_wfd_ie(payload)
    assert info.device_info is not None
    assert info.device_info.role == "primary-sink"
    assert info.device_info.session_mgmt_port == 7236
    assert info.device_info.max_throughput_mbps == 300
    assert info.device_info.content_protection is True
    assert info.device_info.availability == "available"


def test_wfd_device_info_source_role():
    flags = 0 | 0x0010
    body = struct.pack(">HHH", flags, 7236, 100)
    info = parse_wfd_ie(_sub(SE_DEVICE_INFO, body))
    assert info.device_info.role == "source"


def test_wfd_associated_bssid_parses():
    payload = _sub(SE_ASSOCIATED_BSSID, bytes.fromhex("112233445566"))
    info = parse_wfd_ie(payload)
    assert info.associated_bssid == "11:22:33:44:55:66"


def test_wfd_local_ip_v4():
    body = bytes([1, 192, 168, 49, 10])
    info = parse_wfd_ie(_sub(SE_LOCAL_IP, body))
    assert info.local_ip == "192.168.49.10"


def test_wfd_coupled_sink_info():
    body = bytes([0x01]) + bytes.fromhex("aabbccddeeff")
    info = parse_wfd_ie(_sub(SE_COUPLED_SINK_INFO, body))
    assert info.coupled_sink is not None
    assert info.coupled_sink.coupled_sink_mac == "aa:bb:cc:dd:ee:ff"


def test_wfd_truncated_subelement_safely_stops():
    # declares 100 bytes but only 2 present
    bad = bytes([SE_DEVICE_INFO]) + struct.pack(">H", 100) + b"\x00\x00"
    info = parse_wfd_ie(bad)
    assert info.device_info is None


def test_wfd_session_info_descriptors():
    desc = (
        bytes.fromhex("aabbccddeeff")      # device addr
        + bytes.fromhex("112233445566")    # associated bssid
        + struct.pack(">HH", 0x0011, 300)  # flags, max tp
        + bytes([0x01]) + bytes.fromhex("eeeeeeeeeeee")  # coupled
    )
    body = bytes([len(desc)]) + desc
    info = parse_wfd_ie(_sub(SE_SESSION_INFO, body))
    assert info.session_info is not None
    assert len(info.session_info.descriptors) == 1
    d = info.session_info.descriptors[0]
    assert d["device_addr"] == "aa:bb:cc:dd:ee:ff"
    assert d["associated_bssid"] == "11:22:33:44:55:66"
    assert d["max_throughput_mbps"] == 300
