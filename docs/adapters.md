# Adapter Compatibility

DIRECTAX detects the kernel driver of the wireless interface via
`/sys/class/net/<iface>/device/driver` and applies a per-chipset
RadioTap TX profile from `src/wifidirect_pentest/core/adapters.py`.

Profiles are spec-derived defaults. Values marked "verified on RF" have
been bench-tested against a live target; anything not so marked is a
plausible default that still needs on-air validation on your card.

## Alfa Networks and equivalent adapters

| Alfa model         | Chipset       | Driver     | Bands       | Injection | P2P mode | Notes |
|--------------------|---------------|------------|-------------|-----------|----------|-------|
| AWUS036NHA         | Atheros AR9271| ath9k_htc  | 2.4         | reliable  | yes      | mainline driver, best cheap first pick |
| AWUS036NH / NEH    | Ralink RT3070 | rt2800usb  | 2.4         | reliable  | no       | needs a second adapter for pbc-race / rogue-go |
| AWUS036ACH / ACS   | RTL8812AU/11AU| 88XXau     | 2.4 + 5     | reliable  | yes      | requires aircrack-ng DKMS driver, not rtw88 |
| AWUS036ACM         | MT7612U       | mt76x2u    | 2.4 + 5     | reliable  | yes      | mainline; best current all-round |
| AWUS1900           | RTL8814AU     | 8814au     | 2.4 + 5     | reliable  | yes      | 4x4 MIMO; aircrack-ng DKMS |
| AWUS036AXML        | MT7921AU      | mt7921u    | 2.4 + 5 + 6 | partial   | yes      | Wi-Fi 6; kernel >= 6.5 for P2P concurrency |
| Tube-UNA           | AR9271        | ath9k_htc  | 2.4         | reliable  | yes      | same silicon as AWUS036NHA |

## Adapters that will NOT work well

| Adapter                    | Driver     | Why |
|----------------------------|------------|-----|
| TL-WN722N v2 / v3          | rtl8xxxu   | RTL8188EUS; injection broken |
| RTL8812AU with mainline    | rtw88_usb  | mainline rtw88 does not support injection |
| Raspberry Pi built-in Wi-Fi| brcmfmac   | firmware-managed; injection blocked |
| Most laptop internal cards | iwlwifi    | Intel firmware restricts mgmt-frame injection |

Use these for passive `discover` and `sniff` only.

## Firmware

DIRECTAX does **not** build, patch, or flash any custom firmware. Every
attack module runs on top of the factory firmware your adapter shipped
with, plus the mainline (or DKMS) driver, plus the standard Linux Wi-Fi
stack (`nl80211`, `iw`, `hostapd`, `wpa_supplicant`, raw packet sockets
via scapy).

There is no binary to upload to the card.

### What custom firmware would unlock (informational, not required)

| Firmware project              | Card family            | What it unlocks                      | Required by DIRECTAX?             |
|-------------------------------|------------------------|--------------------------------------|-----------------------------------|
| Nexmon                        | Broadcom BCM4339/43455 | monitor + injection on Pi / Nexus    | No; those cards are out of scope  |
| ath9k_htc modded firmware     | Atheros AR9271         | small retry-timing improvements      | No                                |
| mt76 debug firmware           | MT76xx / MT79xx        | active-monitor mode                  | No; would only tighten the p2p-fuzz liveness gate |
| OpenFWWF                      | old Broadcom bcm43xx   | monitor + injection                  | No                                |
| RTL8812AU firmware patches    | RTL8812AU              | tx power beyond regulatory limits    | No; not shipped, likely illegal   |

## Kernel-module build case: RTL8812AU / RTL8814AU

The mainline `rtw88` driver does not support injection. Cards using
RTL8812AU (Alfa AWUS036ACH / ACS) or RTL8814AU (Alfa AWUS1900) require
the aircrack-ng DKMS driver on top of factory firmware. This is a
kernel module build, not a firmware flash; the card itself is not
touched.

## Installing the aircrack-ng DKMS driver for RTL8812AU / 8814AU

```
sudo apt install -y build-essential dkms git
git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
sudo make dkms_install
```

After reboot: `lsmod | grep 88XX` should show `88XXau`; `iw list` for
the interface should include `AP` and `monitor` in Supported Modes.

## Verifying detection

```
sudo python3 scan.py --preflight
```

Prints one line per wireless interface with driver, readiness state
(READY / LIMITED), supported bands, and any blockers from the profile
table.

## Contributing a profile

If you tune DIRECTAX for a card not on this list, add an entry to
`PROFILES` in `core/adapters.py` and a smoke test in
`tests/test_adapters.py`. The minimum useful profile fields are
`driver`, `bands`, `injection`, `p2p_support`, `tx_flags`, plus one
line of `notes`.
