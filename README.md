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

25 subcommands across discovery, sniffing, active attacks, and fuzzing.

Discovery and inspection: passive P2P device / GO / client discovery,
full P2P + WSC IE parse, RSN IE parse with PMF/AKM/PMKID detection,
driver capability probe (`iw phy`), P2P Service Discovery
(Bonjour/UPnP/WSD/SSDP), Wi-Fi Aware / NAN scanner, P2P Public Action
sniffer, EAPOL / WSC M1..M8 sniffer.

Active attacks: PMF-gated deauth, 4-way EAPOL handshake capture, PMKID
capture (Steube 2018) with correct hashcat 22000 line, hashcat 22000
pipeline, WPS Pixie-Dust (reaver -K and native-from-pcap), WPS PIN
External Registrar brute, WPS PBC session-overlap race, Rogue Group
Owner with WPA2 or WPA3-SAE transition mode, KARMA probe-response
responder, P2P Invitation Request rejoin, GO Negotiation intent
hijack, Notice-of-Absence starvation, beacon flood with synthetic
P2P GOs, Provision Discovery flood, P2P MAC clone, cross-connection
pivot probe.

Fuzzers: protocol-aware P2P Public Action fuzzer for PD-Req /
GO-Neg-Req / Invitation-Req with 802.11 element-length safe encoding
and liveness gate; Miracast RTSP mutation fuzzer plus a minimal
Miracast responder to observe source M4/M5.

Full matrix with preconditions and CVSS references: [docs/attack-matrix.md](docs/attack-matrix.md).

## Requirements

Linux, root, 802.11 adapter with monitor + injection.

External binaries: `iw`, `ip`, `rfkill`, `wpa_supplicant`, `wpa_cli`,
`hostapd`, `dnsmasq`, `aircrack-ng`, `reaver`, `pixiewps`, `tshark`.

Optional external binaries: `hcxpcapngtool`, `hashcat` (for PMKID and
4-way-handshake offline cracking).

Python: 3.10+, `scapy>=2.5`, `cryptography>=41`, `pytest>=7` for the
test suite.

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
scan.py                                CLI entry (25 subcommands)
docs/
  usage.md                             step by step usage guide
  attack-matrix.md                     coverage + preconditions
  finding-schema.json                  JSON schema for findings output
tests/                                 pytest suite (29 tests)
src/wifidirect_pentest/
  core/         interface, channels, IE parser, RSN parser,
                driver capability probe, finding model + builders
  scanners/     discovery, WSC facts, service discovery, NAN scanner
  sniffers/     P2P frames, EAPOL / WSC labelling
  attacks/      deauth (PMF-gated), beacon flood, PD flood, PBC race,
                WPS PIN brute, Pixie-Dust (reaver + native), handshake
                capture, hashcat 22000 pipeline, PMKID capture, rogue
                GO (WPA2 or SAE transition), KARMA responder,
                Invitation rejoin, GO-Neg hijack, NoA starvation,
                MAC spoof, cross-connection pivot
  fuzzers/      P2P Public Action frame fuzzer, Miracast RTSP fuzzer
  reporting/    JSON writer, human formatter, offline + NVD novelty gate
```

## Testing

```
python3 -m pytest tests/ -q
```

Covers P2P and WSC IE parsers, RSN parser, finding schema conformance,
novelty gate false-positive guard, PMKID KDE extraction, Miracast fuzz
case determinism, NAN attribute parser, and the review-fix regression
suite (WSC OUI collision with DH keys, hashcat outfile format, P2P
Status attribute walk, element-length validity).

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
