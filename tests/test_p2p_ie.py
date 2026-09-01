import struct

from wifidirect_pentest.core.p2p_ie import (
    parse_p2p_ie, parse_wsc_ie, CONFIG_METHOD_BITS,
)


def _p2p_tlv(aid: int, body: bytes) -> bytes:
    return struct.pack("<BH", aid, len(body)) + body


def _wsc_tlv(t: int, v: bytes) -> bytes:
    return struct.pack(">HH", t, len(v)) + v


def build_p2p_ie() -> bytes:
    body = b""
    body += _p2p_tlv(2, bytes([0x25, 0x02]))                # capability persistent
    body += _p2p_tlv(3, bytes.fromhex("112233445566"))      # device id
    body += _p2p_tlv(6, b"US\x04\x51\x0b")                  # listen chan
    body += _p2p_tlv(17, b"US\x04\x51\x06")                 # op chan
    body += _p2p_tlv(11, b"US\x04\x51\x03\x01\x06\x0b")     # channel list
    dev_info = (
        bytes.fromhex("112233445566")
        + struct.pack(">H", 0x0088)
        + b"\x00\x01\x00\x50\xF2\x04\x00\x01"
        + b"\x00"
        + _wsc_tlv(0x1011, b"UnitTest")
    )
    body += _p2p_tlv(13, dev_info)
    return body


def test_p2p_parser_full():
    info = parse_p2p_ie(build_p2p_ie())
    assert info.capability == (0x25, 0x02)
    assert info.persistent_group is True
    assert info.device_id == "11:22:33:44:55:66"
    assert info.channel_list == [1, 6, 11]
    assert info.device_info and info.device_info.device_name == "UnitTest"
    assert info.operating_channel == ("US\x04", 0x51, 0x06)


def test_wsc_composite_bits():
    payload = _wsc_tlv(0x1008, b"\x00\x88")  # Display + PushButton only
    info = parse_wsc_ie(payload)
    assert "PushButton" in info.config_methods_labels
    assert "Display" in info.config_methods_labels
    assert "VirtualPushButton" not in info.config_methods_labels
    assert "PhysicalPushButton" not in info.config_methods_labels


def test_wsc_all_common_fields():
    payload = (
        _wsc_tlv(0x104A, b"\x10")
        + _wsc_tlv(0x1057, b"\x01")
        + _wsc_tlv(0x1041, b"\x01")
        + _wsc_tlv(0x1012, b"\x00\x04")
        + _wsc_tlv(0x1021, b"Acme")
        + _wsc_tlv(0x1023, b"Model")
        + _wsc_tlv(0x1024, b"1.0")
        + _wsc_tlv(0x1042, b"SN0001")
        + _wsc_tlv(0x1011, b"DevX")
        + _wsc_tlv(0x1008, b"\x02\x80")   # VirtualPushButton composite
        + _wsc_tlv(0x1054, b"\x00\x01\x00\x50\xF2\x04\x00\x01")
        + _wsc_tlv(0x103C, b"\x03")
    )
    info = parse_wsc_ie(payload)
    assert info.version == 0x10
    assert info.ap_setup_locked is True
    assert info.selected_registrar is True
    assert info.device_password_id == 0x0004
    assert info.manufacturer == "Acme"
    assert info.model_name == "Model"
    assert info.device_name == "DevX"
    assert "VirtualPushButton" in info.config_methods_labels
    assert info.rf_bands == 0x03


def test_config_method_bits_no_partial_match():
    # 0x0004 (Label) must not appear if 0x0004 bit not set
    payload = _wsc_tlv(0x1008, b"\x00\x80")  # PushButton only
    info = parse_wsc_ie(payload)
    assert "Label" not in info.config_methods_labels
    assert "PushButton" in info.config_methods_labels


def test_channel_list_multiple_op_classes():
    body = b"US\x04" + b"\x51\x03\x01\x06\x0b" + b"\x73\x02\x24\x28"
    p2p_body = _p2p_tlv(11, body)
    info = parse_p2p_ie(p2p_body)
    assert info.channel_list == [1, 6, 11, 36, 40]


def test_truncated_ie_does_not_crash():
    # Truncated capability attr, len says 2, only 1 byte present
    truncated = struct.pack("<BH", 2, 2) + b"\x25"
    info = parse_p2p_ie(truncated)
    assert info.capability is None
