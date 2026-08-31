import struct

from wifidirect_pentest.scanners.nan import _parse_nan_attrs, _extract_nan_payload


def test_extract_nan_payload_from_ie():
    ie = b"\xdd" + b"\x14" + b"\x50\x6f\x9a\x13" + b"A" * 16
    idx = ie.find(b"\x50\x6f\x9a\x13")
    got = _extract_nan_payload(ie)
    assert got == ie[idx + 4:]


def test_parse_service_id_list():
    body = bytes.fromhex("aaaaaaaaaaaa") + bytes.fromhex("bbbbbbbbbbbb")
    blob = bytes([0x02]) + struct.pack("<H", len(body)) + body
    attrs = list(_parse_nan_attrs(blob))
    assert len(attrs) == 1
    aid, val = attrs[0]
    assert aid == 0x02
    assert len(val) == 12


def test_truncated_attr_stops_gracefully():
    blob = bytes([0x02]) + struct.pack("<H", 8) + b"AB"
    attrs = list(_parse_nan_attrs(blob))
    assert attrs == []
