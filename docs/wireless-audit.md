# Wireless Audit (W-spec) Flow

Over-the-air 802.11 / Wi-Fi Direct link-layer audit, profile-driven and
authorization-gated. This is the RF-layer scope: no ADB, no firmware,
no TLS/media application testing. The Miracast modules are a separate
scope (see docs/miracast.md).

Reference target fixture: `profiles/crestron-am-tx3-110.yaml`.

## Authorization gate (W0, non-optional)

No active module runs without an explicit single target identity AND an
operator authorization token, both recorded to `<run>/authz.json`.
Default mode is passive (W1 capture only). Active modules require the
second opt-in `--authorize-active`. Frames and attacks are confined to
the one authorized BSSID; other-network frames are dropped and never
stored.

## Modules

| ID | Module | Entry point | Wraps | Active? |
|----|--------|-------------|-------|---------|
| W0 | Authorization gate | `core/authz.py` (enforced everywhere) | none | n/a |
| W1 | Discovery | `wireless-audit --modules W1` | iw, scapy | passive |
| W2 | Pairing analysis | `wireless-audit --modules W1,W2` | scapy, wpa_supplicant | passive classify, active probe under opt-in |
| W3 | WPS testing | `pixie`, `pixie-pcap`, `wps-pin` | reaver, pixiewps, bully | active |
| W4 | Link crypto (KRACK + FragAttacks) | `w4-linkcrypto` | krackattacks-scripts, fragattacks, hostapd | active |
| W5 | Availability (deauth) | `w5-availability` | aireplay-ng, scapy | active, disruptive |
| W6 | Capture + decryption | `w6-decrypt` | airdecap-ng | capture-side |
| W7 | Report | runs at end of `wireless-audit` | none | n/a |

## Profile

```yaml
name: Crestron AM-TX3-110
ssid_pattern: "DIRECT-*"
target_bssid: auto          # resolved by W1, or set explicitly
band: [5GHz]
link_crypto: wpa2_ccmp
role: client
```

## Passive run (default)

```bash
sudo python3 scan.py wireless-audit \
    -i wlan1mon \
    --profile profiles/crestron-am-tx3-110.yaml \
    --operator veera \
    --authorize ENGAGEMENT-2026-001 \
    --duration 60 \
    --modules W1,W2 \
    --out run/crestron-001
```

Produces `run/crestron-001/`:
- `authz.json` scope, operator, token, time window
- `modules/W1-discover.json`, `modules/W2-pairing.json`
- `report.md`, `report.json` (W7)

## Active modules (second opt-in)

W4 link crypto against the client (needs the rogue-AP rig and Vanhoef's
tools installed):

```bash
sudo python3 scan.py w4-linkcrypto \
    -i wlan1 --target <client-mac> --channel 36 \
    --ssid 'DIRECT-xx-Crestron' \
    --krack-path /opt/krackattacks-scripts/krack-test-client.py \
    --fragattacks-path /opt/fragattacks/fragattack.py \
    --authorized
```

W5 availability (single target only, refuses broadcast):

```bash
sudo python3 scan.py w5-availability \
    -i wlan1mon \
    --profile profiles/crestron-am-tx3-110.yaml \
    --operator veera --authorize ENGAGEMENT-2026-001 \
    --target-bssid 02:aa:bb:cc:dd:ee \
    --client 02:00:11:22:33:44 \
    --duration 5 --authorize-active
```

W6 decrypt a captured session with known PSK:

```bash
python3 scan.py w6-decrypt --pcap run/crestron-001/pcaps/session.pcap \
    --ssid 'DIRECT-xx-Crestron' --psk '<group-psk>'
```

## Acceptance against the reference device

Pointed at the AM-TX3-110 with authorization and a monitor-mode adapter:

- W1: resolves the DIRECT-* SSID, client role, 5 GHz channel, WPS methods
- W2: reports PBC vs PIN pairing
- W3: Pixie Dust verdict + lockout measurement
- W4: cipher = CCMP, plus a FragAttacks pass/fail matrix
- W6: a channel-locked session pcap

## Guards recap (what makes it a pentest tool)

- Explicit target + operator token recorded in the run log
- Passive by default; active modules need `--authorize-active`
- Single-target confinement; other-network frames dropped, never stored
- W5 refuses broadcast and multi-target, bounded duration
- Every report records scope, authorization, operator, and time window

## Tool dependencies (wrapped, not reimplemented)

- W3: `reaver`, `pixiewps`, `bully`
- W4: `krackattacks-scripts`, `fragattacks`, `hostapd` test build
- W5: `aireplay-ng`
- W6: `airdecap-ng`

Each module reports `tool-missing` cleanly when its dependency is
absent; it does not fabricate a result.
