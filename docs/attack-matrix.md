# DIRECTAX Attack Matrix

HYPOTHESIS gate on parsed frame state, then Phase 2 confirmation from
observable evidence written to `evidence/`. Findings without recorded
Phase 2 evidence stay internal at `confidence: hypothesis` and are not
emitted to default output.

## Discovery and inspection

| # | Capability | Module | Evidence |
|---|------------|--------|----------|
| 1 | Passive P2P device / GO / client discovery | scanners/discovery.py | JSON device table + optional pcap |
| 2 | Full P2P + WSC IE parse | core/p2p_ie.py | structured device record |
| 3 | RSN IE parse (PMF, AKM, PMKID list) | core/rsn.py | parsed dict |
| 4 | Driver capability probe | core/driver_probe.py | JSON caps + warnings |
| 5 | P2P Service Discovery (Bonjour, UPnP, WSD, SSDP) | scanners/service.py | SD-Response TLV dump |
| 6 | Wi-Fi Aware / NAN passive scanner | scanners/nan.py | cluster + service IDs, FTM ranging bit |
| 7 | P2P Public Action sniffer | sniffers/p2p_sniffer.py | pcap + subtype histogram |
| 8 | EAPOL / WSC M1..M8 sniffer | sniffers/eapol_sniffer.py | pcap + message-type histogram |

## Active attacks

| # | Attack | Module | Phase 2 confirmation | CWE |
|---|--------|--------|----------------------|-----|
| 9  | Deauth against P2P GO (PMF-gated) | attacks/deauth.py | EAPOL or client-to-AP Reassoc-Req captured; own-source frames filtered out | CWE-940 |
| 10 | 4-way handshake capture | attacks/handshake_capture.py | pcap with >=2 distinct EAPOL key-info variants | CWE-326 |
| 11 | PMKID capture (Steube 2018) | attacks/pmkid_capture.py | PMKID KDE extracted + hashcat 22000 line with real ESSID | CWE-326 |
| 12 | Hashcat 22000 pipeline | attacks/hashcat_pipeline.py | recovered plaintext PSK from potfile | CWE-521 |
| 13 | WPS Pixie-Dust (reaver -K path) | attacks/pixiedust.py | reaver+pixiewps returns PIN and PSK | CWE-338 |
| 14 | WPS Pixie-Dust from existing pcap | attacks/pixiedust_native.py | pixiewps returns PIN from parsed M1/M2/M3 attributes | CWE-338 |
| 15 | WPS PIN External Registrar brute | attacks/pin_bruteforce.py | reaver returns PIN + PSK + SSID | CWE-307 |
| 16 | WPS PBC session-overlap race | attacks/pbc_race.py | wpa_supplicant status yields ssid + passphrase | CWE-362 |
| 17 | Rogue Group Owner (WPA2 or SAE-transition) | attacks/rogue_go.py | dnsmasq DHCPACK; separate captive CREDS line signal | CWE-290 |
| 18 | KARMA probe-response responder | attacks/karma_responder.py | replies_sent + unique_clients set | CWE-290 |
| 19 | P2P Invitation Request rejoin | attacks/invitation.py | Invitation-Rsp Status=0 (via P2P IE walk) AND EAPOL follow-up | CWE-306 |
| 20 | GO Negotiation intent hijack | attacks/goneg_intent.py | GO-Neg-Conf with Status=0 (attribute walk, not byte scan) | CWE-346 |
| 21 | Notice-of-Absence starvation | attacks/noa_starve.py | beacons_sent + observable client stall (soft) | CWE-400 |
| 22 | Beacon flood with synthetic GOs | attacks/beacon_flood.py | scanner enumerates injected DIRECT- devices | CWE-406 |
| 23 | Provision Discovery flood | attacks/provision_flood.py | target UI prompts or PD-Rsp silence (soft) | CWE-400 |
| 24 | P2P Device / Interface Address clone | attacks/mac_spoof.py | attacker frames accepted as target in GO Neg | CWE-290 |
| 25 | Cross-connection pivot | attacks/cross_connection.py | TCP reachability to host outside P2P subnet | CWE-346 |

## Fuzzers

| # | Target | Module | Notes |
|---|--------|--------|-------|
| 26 | P2P Public Action (PD, GO-Neg, Invitation) | fuzzers/p2p_frame_fuzzer.py | protocol-aware mutation, liveness gate, 802.11 element length safe |
| 27 | Miracast (Wi-Fi Display) RTSP | fuzzers/miracast_rtsp.py | mutation cases + minimal responder to observe M4/M5 |

## Out of scope by policy

- Weaponized shellcode, ROP chains, or persistence payloads.
- Automated public disclosure.
- Any test against a target the operator has not been authorized to attack in writing.

## Bug-hunting notes

- hostapd and wpa_supplicant P2P handling: p2p_supplicant.c, p2p_go_neg.c, p2p_pd.c, p2p_invitation.c.
- Vendor P2P daemons: Samsung p2pd, Xiaomi mtkd, Realtek wpa_supplicant_8, Broadcom bcmp2p.
- IEEE 802.11 fragmentation and reassembly cache (FragAttacks family).
- WSC IE parsers in vendor NDIS and Wi-Fi Direct middleware.
- Miracast RTSP layer once the P2P group is up (fuzzers/miracast_rtsp.py is the entry point).
- NAN Service Descriptor filter parsing (Wi-Fi Aware Spec v4.0 table 10 attribute 0x03).
