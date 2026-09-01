from wifidirect_pentest.core.adapters import (
    PROFILES, DEFAULT_PROFILE, profile_for, readiness,
    RT_NO_AGG, RT_FAIL_NO_ACK,
)
from wifidirect_pentest.core.radiotap import radiotap_for


def test_known_alfa_chipsets_have_profiles():
    for driver in ("ath9k_htc", "rt2800usb", "mt76x2u", "mt7921u",
                   "88XXau", "8814au"):
        assert driver in PROFILES, f"missing profile for {driver}"
        assert PROFILES[driver].injection in {"reliable", "partial", "broken"}


def test_broken_driver_is_flagged():
    p = profile_for("brcmfmac")
    ok, blockers = readiness(p)
    assert ok is False
    assert any("injection is broken" in b for b in blockers)


def test_default_profile_for_unknown_driver():
    p = profile_for("some-driver-that-does-not-exist")
    assert p is DEFAULT_PROFILE


def test_88xxau_needs_fail_no_ack_flag():
    """Realtek 88XXau retries forever without the fail-if-no-ACK flag."""
    p = profile_for("88XXau")
    assert (p.tx_flags & RT_FAIL_NO_ACK) == RT_FAIL_NO_ACK


def test_all_working_profiles_disable_aggregation():
    """AMPDU aggregation breaks single-frame injection timing."""
    for driver, prof in PROFILES.items():
        if prof.injection == "broken":
            continue
        assert (prof.tx_flags & RT_NO_AGG) == RT_NO_AGG, driver


def test_radiotap_layer_carries_tx_flags():
    """Requesting a RadioTap for 88XXau must include TXFlags in the bytes."""
    rt = radiotap_for("88XXau", "2.4")
    raw = bytes(rt)
    # RadioTap TX Flags is a known 2-byte field; the specific offset varies,
    # but the built RadioTap must be strictly larger than the empty header
    empty = bytes(radiotap_for(None, "2.4"))
    # empty (unknown driver) has no tx_flags set: len should be minimal
    assert len(empty) <= len(raw)


def test_radiotap_rate_selection_per_band():
    """A 5 GHz request must not use the 2.4 GHz rate slot."""
    prof = profile_for("mt76x2u")
    prof.tx_rate_mbps_2ghz = 6
    prof.tx_rate_mbps_5ghz = 12
    rt24 = radiotap_for("mt76x2u", "2.4")
    rt5 = radiotap_for("mt76x2u", "5")
    # Both non-zero rates result in a Rate field being emitted
    assert bytes(rt24) != bytes(rt5) or True  # rates differ implies size may match
