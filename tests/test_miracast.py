from wifidirect_pentest.scanners.discovery import DiscoveredDevice
from wifidirect_pentest.scanners.miracast import is_miracast, to_miracast, filter_miracast
from wifidirect_pentest.core.wfd_ie import WFDInfo, WFDDeviceInfo
from wifidirect_pentest.core.p2p_ie import WSCInfo


def _dev_with_wfd(role: str = "primary-sink", port: int = 7236):
    d = DiscoveredDevice(device_addr="aa:bb:cc:dd:ee:01")
    d.wfd = WFDInfo(device_info=WFDDeviceInfo(
        role=role, role_raw=1, session_mgmt_port=port,
        max_throughput_mbps=300, availability="available",
        content_protection=True, raw_flags_hex="0x0111"))
    d.channels_seen = {36}
    d.rssi_best = -45
    return d


def test_is_miracast_wfd_ie_present():
    assert is_miracast(_dev_with_wfd())


def test_is_miracast_display_pdt_without_wfd():
    d = DiscoveredDevice(device_addr="aa:bb:cc:dd:ee:02")
    d.wsc = WSCInfo(primary_device_type="7-0050f204-1")
    assert is_miracast(d)


def test_is_miracast_rejects_non_display_non_wfd():
    d = DiscoveredDevice(device_addr="aa:bb:cc:dd:ee:03")
    d.wsc = WSCInfo(primary_device_type="10-0050f204-5")  # smartphone
    assert not is_miracast(d)


def test_to_miracast_pulls_fields():
    d = _dev_with_wfd()
    m = to_miracast(d)
    assert m.role == "primary-sink"
    assert m.session_mgmt_port == 7236
    assert m.content_protection is True
    assert m.max_throughput_mbps == 300
    assert m.rssi_best == -45


def test_filter_miracast_drops_non_display():
    good = _dev_with_wfd()
    phone = DiscoveredDevice(device_addr="aa:bb:cc:dd:ee:04")
    phone.wsc = WSCInfo(primary_device_type="10-0050f204-5")
    out = filter_miracast([good, phone])
    assert len(out) == 1
    assert out[0].device_addr == "aa:bb:cc:dd:ee:01"
