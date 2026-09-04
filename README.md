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

DIRECTAX matches the kernel driver id from
`/sys/class/net/<iface>/device/driver` against the profile table in
`core/adapters.py`. Any card whose driver is listed below works.

### Alfa Networks (currently sold)

| Model                | Chipset          | Driver           | Bands       | Injection | P2P mode | Monitor  | Notes |
|----------------------|------------------|------------------|-------------|-----------|----------|----------|-------|
| AWUS036NHA           | Atheros AR9271   | ath9k_htc        | 2.4         | reliable  | yes      | reliable | Best cheap starter; every subcommand works on one card |
| Tube-U(N) / Tube-UNA | Atheros AR9271   | ath9k_htc        | 2.4         | reliable  | yes      | reliable | Same silicon as AWUS036NHA in a weatherproof shell |
| AWUS036NH            | Ralink RT3070    | rt2800usb        | 2.4         | reliable  | no       | reliable | Needs a second adapter for pbc-race / rogue-go |
| AWUS036NEH           | Ralink RT3070    | rt2800usb        | 2.4         | reliable  | no       | reliable | Compact form factor; same driver caveat |
| AWUS036ACS           | RTL8811AU        | 88XXau (DKMS)    | 2.4 / 5     | reliable  | yes      | reliable | Requires aircrack-ng DKMS driver |
| AWUS036ACH           | RTL8812AU        | 88XXau (DKMS)    | 2.4 / 5     | reliable  | yes      | reliable | Aircrack-ng DKMS; 2x2 MIMO |
| AWUS036ACHM          | RTL8812BU        | 88x2bu (DKMS)    | 2.4 / 5     | partial   | partial  | reliable | Driver less mature; deauth works, pbc-race unreliable |
| AWUS036ACM           | MediaTek MT7612U | mt76x2u          | 2.4 / 5     | reliable  | yes      | reliable | Mainline driver; best current all-round |
| AWUS036AC            | RTL8812AU        | 88XXau (DKMS)    | 2.4 / 5     | reliable  | yes      | reliable | Older enclosure, same silicon as ACH |
| AWUS1900             | RTL8814AU        | 8814au (DKMS)    | 2.4 / 5     | reliable  | yes      | reliable | 4x4 MIMO; high tx power |
| AWUS036AXM           | MediaTek MT7921U | mt7921u          | 2.4 / 5     | partial   | yes      | reliable | Wi-Fi 6 (802.11ax), 2x2 MIMO |
| AWUS036AXER          | MediaTek MT7921AU| mt7921u          | 2.4 / 5 / 6 | partial   | yes      | reliable | Wi-Fi 6E variant with 6 GHz enabled |
| AWUS036AXML          | MediaTek MT7921AU| mt7921u          | 2.4 / 5     | partial   | yes      | reliable | **Bench-verified.** Wi-Fi 6, not Wi-Fi 7. Single-card monitor via in-place iface swap |
| AWUS036AX            | MediaTek MT7921U | mt7921u          | 2.4 / 5     | partial   | yes      | reliable | Same driver as AXML |

### Alfa legacy models (still work for a subset)

| Model         | Chipset          | Driver     | Bands | Injection | Notes |
|---------------|------------------|------------|-------|-----------|-------|
| AWUS036H      | RTL8187          | rtl8187    | 2.4   | partial   | Very old; discovery + sniff OK, WPS attacks unreliable |
| AWUS036NEH-R  | Ralink RT3070    | rt2800usb  | 2.4   | reliable  | Refresh of AWUS036NEH |
| AWUS036N      | RTL8188RU        | rtl8xxxu   | 2.4   | broken    | Do not use for injection; passive only |

### Non-Alfa adapters that also work

| Chipset         | Driver              | Bands           | Common cards                                  |
|-----------------|---------------------|-----------------|-----------------------------------------------|
| Atheros AR9271  | ath9k_htc           | 2.4             | TP-Link TL-WN722N v1, Panda PAU05             |
| Atheros AR9xxx  | ath9k               | 2.4 / 5         | Most 802.11n mini-PCIe cards                  |
| MediaTek MT7612U| mt76x2u             | 2.4 / 5         | Panda PAU0F, Comfast CF-WU782AC               |
| MediaTek MT7921U| mt7921u             | 2.4 / 5 (+6)    | Cudy WU850S, several 2024 USB Wi-Fi 6 dongles |

### Do NOT use these

| Adapter                 | Driver    | Why |
|-------------------------|-----------|-----|
| TL-WN722N v2 / v3       | rtl8xxxu  | RTL8188EUS; injection broken |
| RTL8812AU on mainline   | rtw88_usb | mainline rtw88 does not support injection; use aircrack-ng 88XXau DKMS instead |
| Raspberry Pi built-in   | brcmfmac  | firmware-managed; injection blocked |
| Most laptop internal    | iwlwifi   | Intel firmware restricts management-frame injection |
| Broadcom-based USB      | brcmfmac  | passive only |

### No firmware to flash

DIRECTAX does not build, patch, or flash any firmware. Every card
above runs on its factory firmware plus its mainline (or DKMS)
driver. Full firmware policy and the aircrack-ng DKMS install
snippet for RTL8812AU / RTL8814AU: [docs/adapters.md](docs/adapters.md#firmware).

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

## Sample run

Real bench output from a first-time run against an Alfa AWUS036AXML
(MediaTek MT7921AU, `mt7921u`). Three P2P Group Owners captured
passively on channels 1, 6, and 11 in a residential RF environment:

```
DEVICE             ROLE  SSID/NAME  CH  dBm   SIG   WPS  PBC  PIN  LOCK  PERS  MFR      TYPE / MODEL
-----------------  ----  ---------  --  ----  ----  ---  ---  ---  ----  ----  -------  ------------
10:5a:95:46:2f:b2  GO    (hidden)   11   -64  ###.  yes  no   no   yes   no    Samsung
7e:b0:de:49:02:e2  GO    (hidden)    6   -72  ##..  yes  no   no   -     no
16:32:51:cd:c6:cc  GO    (hidden)    1   -85  #...  yes  no   no   -     no
```

Full walkthrough with preflight, driver-probe, per-device detail
block, adapter picker, and `--active` mode: [docs/sample-run.md](docs/sample-run.md).

## Documentation

- [docs/usage.md](docs/usage.md) full command reference with examples
- [docs/attack-matrix.md](docs/attack-matrix.md) attack coverage
- [docs/adapters.md](docs/adapters.md) supported hardware and firmware policy
- [docs/sample-run.md](docs/sample-run.md) real bench-run walkthrough
- [docs/references.md](docs/references.md) CVEs, research papers, tools, and specs (~110 items)
- [docs/finding-schema.json](docs/finding-schema.json) output schema

## License

MIT. See [LICENSE](LICENSE).
