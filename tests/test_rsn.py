import struct

from wifidirect_pentest.core.rsn import parse_rsn, requires_pmf, supports_pmf, uses_sae


def _rsn(pairwise, akm, caps: int, pmkids: list[bytes] | None = None,
         group_mgmt: bytes | None = None) -> bytes:
    b = struct.pack("<H", 1)                     # version
    b += b"\x00\x0f\xac\x04"                     # group cipher CCMP
    b += struct.pack("<H", len(pairwise))
    for c in pairwise:
        b += c
    b += struct.pack("<H", len(akm))
    for a in akm:
        b += a
    b += struct.pack("<H", caps)
    if pmkids is not None:
        b += struct.pack("<H", len(pmkids))
        for p in pmkids:
            b += p
    if group_mgmt is not None:
        b += group_mgmt
    return b


def test_wpa2_psk_no_pmf():
    payload = _rsn([b"\x00\x0f\xac\x04"], [b"\x00\x0f\xac\x02"], 0x0000)
    info = parse_rsn(payload)
    assert info.akm_suites == ["PSK"]
    assert info.pairwise_ciphers == ["CCMP"]
    assert info.mfpc is False
    assert info.mfpr is False
    assert requires_pmf(info) is False
    assert supports_pmf(info) is False
    assert uses_sae(info) is False


def test_wpa3_sae_mfpr():
    payload = _rsn(
        [b"\x00\x0f\xac\x04"],
        [b"\x00\x0f\xac\x08"],   # SAE
        0x00C0,                   # MFPR=1, MFPC=1
        pmkids=[],
        group_mgmt=b"\x00\x0f\xac\x06",   # BIP
    )
    info = parse_rsn(payload)
    assert info.akm_suites == ["SAE"]
    assert info.mfpc is True
    assert info.mfpr is True
    assert requires_pmf(info) is True
    assert uses_sae(info) is True
    assert info.group_mgmt_cipher == "BIP-CMAC-128"


def test_pmkid_list_parses():
    pmkid = bytes(range(16))
    payload = _rsn([b"\x00\x0f\xac\x04"], [b"\x00\x0f\xac\x02"], 0x0080,
                   pmkids=[pmkid])
    info = parse_rsn(payload)
    assert info.pmkids == [pmkid.hex()]
    assert info.mfpc is True
    assert info.mfpr is False


def test_truncated_rsn():
    info = parse_rsn(b"\x01")   # only 1 byte, version incomplete
    assert info.version == 0
    assert info.group_cipher is None
