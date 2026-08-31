```
 ____  ___ ____  _____ ____ _____  _    __  __
|  _ \|_ _|  _ \| ____/ ___|_   _|/ \   \ \/ /
| | | || || |_) |  _|| |     | | / _ \   \  /
| |_| || ||  _ <| |__| |___  | |/ ___ \  /  \
|____/|___|_| \_\_____\____| |_/_/   \_\/_/\_\
```

# DIRECTAX

Wi-Fi Direct (P2P) offensive research toolkit. Authorized lab use only.

Implements the discovery, sniffing, and attack surface defined by the
Wi-Fi Alliance P2P Technical Specification (v1.7), WSC 2.0.7 and the
relevant IEEE 802.11 amendments (11-2020, 11w, 11u). Findings follow a
two-phase model: HYPOTHESIS then CONFIRMATION. Only findings with a
recorded observable effect are emitted at `confidence: confirmed`.

## Attack surface covered

| # | Capability                                | Module                             | Confirmation artifact                       |
|---|-------------------------------------------|------------------------------------|---------------------------------------------|
| 1 | Passive P2P Device / GO / Client discovery| `scanners/discovery.py`            | device table, pcap                          |
| 2 | P2P + WSC IE full attribute parse         | `core/p2p_ie.py`                   | structured device record                    |
| 3 | P2P Service Discovery (Bonjour/UPnP/WSD)  | `scanners/service.py`              | SD-Response TLV dump                        |
| 4 | Full P2P frame sniff (Action + IE)        | `sniffers/p2p_sniffer.py`          | pcap + subtype counts                       |
| 5 | EAPOL / WSC M1..M8 sniff                  | `sniffers/eapol_sniffer.py`        | pcap + msg-type histogram                   |
| 6 | Deauth against P2P GO (no PMF)            | `attacks/deauth.py`                | pcap containing reconnect frames            |
| 7 | 4-way handshake capture                   | `attacks/handshake_capture.py`     | pcap with >=2 distinct EAPOL key-info bytes |
| 8 | WPS Pixie-Dust (reaver -K + pixiewps)     | `attacks/pixiedust.py`             | recovered PIN + PSK                         |
| 9 | WPS External Registrar PIN brute (reaver) | `attacks/pin_bruteforce.py`        | recovered PIN + PSK                         |
| 10| WPS PBC session-overlap race              | `attacks/pbc_race.py`              | credentials returned by wpa_supplicant      |
| 11| Rogue Group Owner (evil-twin)             | `attacks/rogue_go.py`              | dnsmasq DHCPACK, captive HTTP log           |
| 12| Beacon flood with synthetic P2P GOs       | `attacks/beacon_flood.py`          | scanner enumerates fake devices             |
| 13| Provision Discovery flood                 | `attacks/provision_flood.py`       | target stops answering PD-Req               |
| 14| P2P Device/Interface Address clone        | `attacks/mac_spoof.py`             | frames accepted as target                   |

Full matrix with preconditions and CVSS references: [docs/attack-matrix.md](docs/attack-matrix.md).

## Requirements

Linux, root, 802.11 adapter with monitor + injection.

External binaries: `iw`, `ip`, `rfkill`, `wpa_supplicant`, `wpa_cli`,
`hostapd`, `dnsmasq`, `aircrack-ng`, `reaver`, `pixiewps`, `tshark`.

Python: 3.10+, `scapy>=2.5`, `cryptography>=41`.

```
sudo apt install iw wireless-tools wpasupplicant hostapd dnsmasq \
                 aircrack-ng reaver pixiewps tshark rfkill
pip install -r requirements.txt
sudo python3 scan.py --preflight
```

## Supported adapters

| Chipset         | Driver              | Bands           | Notes                                         |
|-----------------|---------------------|-----------------|-----------------------------------------------|
| Atheros AR9271  | ath9k_htc           | 2.4             | Reliable injection, mainline                  |
| Ralink RT3070   | rt2800usb           | 2.4             | Legacy but stable                             |
| Realtek 8812AU  | 88XXau (aircrack-ng)| 2.4 / 5         | Requires DKMS driver, not rtw88               |
| MediaTek 7612U  | mt76x2u             | 2.4 / 5         | Mainline, best all-round pick                 |
| MediaTek 7921U  | mt7921u             | 2.4 / 5 / 6     | Wi-Fi 6, P2P concurrent mode driver-limited   |
| Intel AX2xx     | iwlwifi             | 2.4 / 5 / 6     | Monitor only; firmware blocks injection       |

Avoid RTL8188EUS (TL-WN722N v2/v3) and brcmfmac (broken injection).

## Layout

```
scan.py                                CLI entry
docs/
  usage.md                             step by step usage guide
  attack-matrix.md                     coverage + preconditions
  finding-schema.json                  JSON schema for findings output
src/wifidirect_pentest/
  core/         interface, channels, IE parser, finding model, builders
  scanners/     discovery, wps facts, service discovery
  sniffers/     p2p frames, EAPOL/WSC labelling
  attacks/      deauth, beacon flood, pd flood, pbc race, wps pin brute,
                pixiedust, handshake capture, rogue GO, mac spoof
  reporting/    JSON writer, human formatter, offline novelty gate
```

## Output model

Every finding produced by DIRECTAX conforms to
[docs/finding-schema.json](docs/finding-schema.json):

```
{
  "id": "hex12",
  "title": "...",
  "cwe": "CWE-###",
  "confidence": "confirmed",
  "target": "...",
  "attacker_position": "same-LAN | remote-internet | ...",
  "location": {"value": "...", "inferred": false},
  "data_flow": "attacker input -> ... -> sink",
  "trigger": "copy-pasteable command",
  "confirmation": {"type": "script|oneliner|manual", "content": "..."},
  "evidence": "path or inline capture",
  "cvss_v40_score": 9.3,
  "cvss_v40_vector": "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/...",
  "novelty": {"checked": true, "known_cve": "CVE-YYYY-NNNN"},
  "fix": "minimal correct fix"
}
```

Default human output shows only `confirmed`. Pass `--show-hypothesis`
to include internal triage entries.

## Safety

- `--authorized` flag is required for any injection or active module.
- Rogue GO serves a static captive page. No lateral movement, no data
  exfiltration, no persistence.
- WPS brute rate-limited (`--delay 2 --lock-delay 300`) to avoid
  bricking target WPS state.
- Memory-corruption results stop at reproducible crash + ASAN backtrace.
  No shellcode, no ROP chain, no persistence payload.

## Documentation

- [docs/usage.md](docs/usage.md) full command reference with examples
- [docs/attack-matrix.md](docs/attack-matrix.md) attack coverage
- [docs/finding-schema.json](docs/finding-schema.json) output schema

## License

MIT. See [LICENSE](LICENSE).
