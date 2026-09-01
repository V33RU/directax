# Adapter Compatibility

DIRECTAX detects the kernel driver of the wireless interface via
`/sys/class/net/<iface>/device/driver` and applies a per-chipset
RadioTap TX profile from `src/wifidirect_pentest/core/adapters.py`.

Profiles are spec-derived defaults. Values marked "verified on RF" have
been bench-tested against a live target; anything not so marked is a
plausible default that still needs on-air validation on your card.

## Alfa Networks supported hardware

Every row lists the kernel driver id DIRECTAX matches against in
`core/adapters.py`. "Injection" is the profile-declared reliability
class (`reliable`, `partial`, `broken`). "P2P mode" is whether the
driver advertises `P2P-GO`, `P2P-client`, and `P2P-device` interface
modes in `iw phy` output (required for `pbc-race`, `invitation`,
`rogue-go`, `goneg-hijack` on a single card). "Monitor" is
monitor-mode reliability for `discover`, `sniff`, `handshake`,
`pmkid`, and `deauth`.

### Currently sold Alfa lineup

| Alfa model              | Chipset          | Driver           | Bands         | Injection | P2P mode | Monitor  | Notes / DIRECTAX status |
|-------------------------|------------------|------------------|---------------|-----------|----------|----------|-------------------------|
| AWUS036NHA              | Atheros AR9271   | ath9k_htc        | 2.4           | reliable  | yes      | reliable | Best cheap starter; every subcommand works on a single card |
| Tube-U(N) / Tube-UNA    | Atheros AR9271   | ath9k_htc        | 2.4           | reliable  | yes      | reliable | Same silicon as AWUS036NHA in a weatherproof enclosure |
| AWUS036NH               | Ralink RT3070    | rt2800usb        | 2.4           | reliable  | no       | reliable | Needs a second adapter for pbc-race / rogue-go / invitation |
| AWUS036NEH              | Ralink RT3070    | rt2800usb        | 2.4           | reliable  | no       | reliable | Compact form factor; same driver caveat |
| AWUS036ACS              | Realtek RTL8811AU| 88XXau (DKMS)    | 2.4 + 5       | reliable  | yes      | reliable | Requires aircrack-ng DKMS driver |
| AWUS036ACH              | Realtek RTL8812AU| 88XXau (DKMS)    | 2.4 + 5       | reliable  | yes      | reliable | Requires aircrack-ng DKMS; 2x2 MIMO |
| AWUS036ACHM             | Realtek RTL8812BU| 88x2bu (DKMS)    | 2.4 + 5       | partial   | partial  | reliable | Driver less mature; deauth works, pbc-race unreliable |
| AWUS036ACM              | MediaTek MT7612U | mt76x2u          | 2.4 + 5       | reliable  | yes      | reliable | Mainline driver; best current all-round pick |
| AWUS036AC               | Realtek RTL8812AU| 88XXau (DKMS)    | 2.4 + 5       | reliable  | yes      | reliable | Older enclosure, same silicon as ACH |
| AWUS1900                | Realtek RTL8814AU| 8814au (DKMS)    | 2.4 + 5       | reliable  | yes      | reliable | 4x4 MIMO; high tx power; aircrack-ng DKMS |
| AWUS036AXM              | MediaTek MT7921U | mt7921u          | 2.4 + 5       | partial   | yes      | reliable | Wi-Fi 6 (802.11ax), 2x2 MIMO |
| AWUS036AXER             | MediaTek MT7921AU| mt7921u          | 2.4 + 5 + 6   | partial   | yes      | reliable | Wi-Fi 6E variant; 6 GHz enabled on the SKU |
| AWUS036AXML             | MediaTek MT7921AU| mt7921u          | 2.4 + 5       | partial   | yes      | reliable | Wi-Fi 6 (not 6E, not Wi-Fi 7). Chip supports 6 GHz but the AXML SKU is 2.4/5 only. Single-card monitor via `iw set type` fallback. |
| AWUS036AX               | MediaTek MT7921U | mt7921u          | 2.4 + 5       | partial   | yes      | reliable | Same driver as AXML |

### Legacy Alfa models (still work for a subset)

| Alfa model    | Chipset          | Driver     | Bands | Injection | Notes |
|---------------|------------------|------------|-------|-----------|-------|
| AWUS036H      | Realtek RTL8187  | rtl8187    | 2.4   | partial   | Very old; monitor + discovery OK, WPS attacks unreliable |
| AWUS036NEH-R  | Ralink RT3070    | rt2800usb  | 2.4   | reliable  | Refresh of AWUS036NEH |
| AWUS036N      | Realtek RTL8188RU| rtl8xxxu   | 2.4   | broken    | Do not use; passive discover only |

### Accessories (not adapters)

- APA-M25 dual-band panel antenna: pair with any of the dual-band cards
  above for +9 dBi gain.
- ARS-N19 / ARS-NT3B external antennas: swap onto any Alfa card with
  RP-SMA to raise gain a few dB. Not a DIRECTAX concern.

### DIRECTAX verification status

- All profile entries above are **spec-derived defaults** in
  `core/adapters.py`. They match published aircrack-ng compatibility
  and hostapd-mana community reports.
- **Bench-verified in this repo so far**: AWUS036AXML (MT7921AU) for
  monitor mode + driver-probe. Other rows are unverified until an
  operator runs a subcommand on that specific model and reports back.
- If you tune a profile for a card, add or edit an entry in
  `PROFILES` (core/adapters.py) and add a smoke test in
  `tests/test_adapters.py`.

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
