from wifidirect_pentest.core.device_type import decode
from wifidirect_pentest.core.oui import lookup


def test_decode_common_wsc_pairs():
    assert decode("1-0050f204-1") == "Computer / PC"
    assert decode("7-0050f204-1") == "Display / TV"
    assert decode("3-0050f204-5") == "All-in-One"
    assert decode("10-0050f204-5") == "Smartphone / Dual Mode"
    assert decode("11-0050f204-7") == "Audio / Home Theater"


def test_decode_unknown_returns_raw():
    assert decode("99-0050f204-99") == "99-0050f204-99"


def test_decode_vendor_namespace():
    assert decode("1-aabbccdd-1").startswith("vendor ")


def test_decode_none_and_bad_format():
    assert decode(None) == ""
    assert decode("garbage") == "garbage"


def test_oui_alfa_and_common_vendors():
    assert lookup("00:c0:ca:ba:4c:85") == "Alfa Networks"
    assert lookup("f8:b7:e2:11:22:33") == "Samsung"
    assert lookup("acbc32aabbcc") == "Apple"
    assert lookup("10:5a:95:46:2f:b2") == "Samsung Electronics"


def test_oui_unknown_returns_none():
    # aa:aa... has the LAA bit set, so it now gets tagged as LAA
    assert "LAA" in lookup("aa:aa:aa:aa:aa:aa")
    # unknown UAA (universally-administered) still returns None
    assert lookup("40:11:22:33:44:55") is None
    assert lookup("") is None
    assert lookup(None) is None


def test_oui_laa_bit_marks_randomized():
    # 7e = 0111 1110, second bit set -> LAA
    got = lookup("7e:b0:de:49:02:e2")
    assert got is not None and "LAA" in got
    # 02:... is the P2P Interface Address prefix that DIRECTAX itself uses
    got2 = lookup("02:aa:bb:cc:dd:ee")
    assert got2 is not None and "LAA" in got2
