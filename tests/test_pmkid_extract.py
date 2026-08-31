import struct

from wifidirect_pentest.attacks.pmkid_capture import extract_pmkid


def _build_eapol_key_with_pmkid(pmkid: bytes) -> bytes:
    # EAPOL header
    hdr = b"\x02" + b"\x03" + struct.pack(">H", 0)  # ver=2, type=3(Key)
    # EAPOL-Key body
    body = b"\x02"                     # Descriptor Type = RSN
    body += b"\x00\x8a"                # Key Info
    body += b"\x00\x10"                # Key Length
    body += b"\x00" * 8                # Replay Counter
    body += b"\x00" * 32               # Nonce
    body += b"\x00" * 16               # IV
    body += b"\x00" * 8                # RSC
    body += b"\x00" * 8                # ID
    body += b"\x00" * 16               # MIC
    # Key Data with a PMKID KDE (0xDD, len, OUI 00-0F-AC, type 04, PMKID)
    kde = b"\xdd\x14\x00\x0f\xac\x04" + pmkid   # len = 4 + 16
    body += struct.pack(">H", len(kde)) + kde
    return hdr[:4] + body


def test_extract_pmkid_from_m1():
    pmkid = bytes.fromhex("00112233445566778899aabbccddeeff")
    frame = _build_eapol_key_with_pmkid(pmkid)
    got = extract_pmkid(frame)
    assert got == pmkid.hex()


def test_extract_pmkid_absent():
    frame = _build_eapol_key_with_pmkid(b"")   # KDE with empty value
    got = extract_pmkid(frame)
    assert got is None or got != ""
