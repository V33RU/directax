# DIRECTAX Attack Matrix

Every module runs a HYPOTHESIS gate against parsed frame state before it
touches the RF, and reports `confidence: confirmed` only when the Phase 2
observable in the last column is captured to disk.

| # | Attack                              | Preconditions                                        | Module                                | Phase 2 confirmation                                          | CWE     |
|---|-------------------------------------|------------------------------------------------------|---------------------------------------|---------------------------------------------------------------|---------|
| 1 | Deauth flood vs P2P GO              | GO beacon RSN IE without MFPC bit                    | attacks/deauth.py                     | pcap contains EAPOL or Reassoc-Req from target client         | CWE-940 |
| 2 | 4-way handshake capture             | WPA2-PSK P2P group + reconnect triggered             | attacks/handshake_capture.py          | pcap contains >=2 distinct EAPOL key-info bytes               | CWE-326 |
| 3 | WPS Pixie-Dust                      | WSC on GO + weak PRNG chipset family                 | attacks/pixiedust.py                  | pixiewps returns PIN, reaver returns PSK                      | CWE-338 |
| 4 | WPS PIN External Registrar brute    | Keypad or Label in Config Methods, Locked=false      | attacks/pin_bruteforce.py             | reaver returns PIN + PSK + SSID                               | CWE-307 |
| 5 | WPS PBC session-overlap race        | Device Password ID=0x0004, walk-time active          | attacks/pbc_race.py                   | wpa_supplicant status contains ssid and passphrase            | CWE-362 |
| 6 | Rogue Group Owner (evil-twin)       | Client roams by RSSI on same SSID                    | attacks/rogue_go.py                   | dnsmasq DHCPACK to victim MAC or captive CREDS line           | CWE-290 |
| 7 | Beacon flood                        | monitor+inject driver                                | attacks/beacon_flood.py               | scanner enumerates injected DIRECT- devices                   | CWE-406 |
| 8 | Provision Discovery flood           | target answers a single PD-Req                       | attacks/provision_flood.py            | target stops answering legitimate PD-Req or raises UI prompts | CWE-400 |
| 9 | P2P Device / Interface Addr clone   | attacker chose target MAC                            | attacks/mac_spoof.py                  | attacker frames accepted as target in GO Neg                  | CWE-290 |
| 10| Persistent group PSK theft          | Persistent bit in Group Cap + handshake capture      | attacks/handshake_capture.py + hashcat| offline crack yields PSK                                      | CWE-521 |
| 11| P2P Service Discovery leak          | GO answers SD Req from unassociated peer             | scanners/service.py                   | Bonjour/UPnP records returned to attacker                     | CWE-200 |
| 12| Cross-connection detection          | P2P Manageability bit indicates infra bridge         | scanners/discovery.py                 | Manageability attr present in parsed IE                       | CWE-346 |

## Out of scope by policy

- Weaponized shellcode, ROP chains, or persistence.
- Automated public disclosure.
- Any test against a target the operator has not been authorized to
  attack in writing.

## Hunting notes for new CVEs

- `hostapd` and `wpa_supplicant` P2P handling: `p2p_supplicant.c`,
  `p2p_go_neg.c`, `p2p_pd.c` in the upstream tree.
- Vendor P2P daemons: Samsung `p2pd`, Xiaomi `mtkd`, Realtek
  `wpa_supplicant_8`, Broadcom `bcmp2p`.
- IEEE 802.11 fragmentation and reassembly cache (FragAttacks family).
- WSC IE parsers in vendor NDIS and Wi-Fi Direct middleware.
- Miracast RTSP layer once the P2P group is up (attach a Miracast
  fuzzer separately).
