# Wi-Fi Direct (P2P) Security Research - Reference Bibliography

Scope: **Wi-Fi Direct proper** and the surfaces it directly depends on.
This includes the P2P Public Action frames, the WSC (Wi-Fi Simple
Configuration) provisioning layer that P2P Group Formation uses, the
wpa_supplicant and hostapd code paths in `p2p_*.c` and `wps_*.c`,
vendor Wi-Fi Direct daemons, and driver bugs that fire specifically
on P2P attributes (e.g. Notice of Absence).

Out of scope on purpose: KRACK / FragAttacks / Kr00k / Framing Frames
/ SSID Confusion / Dragonblood / Blast-RADIUS / PEAP misconfig /
BroadPwn / general brcmfmac / general MediaTek Wi-Fi bugs. Those are
real Wi-Fi attacks, but they target 802.11 or WPA in general and are
not Wi-Fi-Direct-specific. See other repos for those.

Miracast (Wi-Fi Display) is kept because it runs *on top of* a
Wi-Fi Direct group; attacking a Miracast source or sink is a
Wi-Fi Direct pentest scenario in practice.

## CVEs

### wpa_supplicant / hostapd - P2P and WSC handling

- [CVE-2015-1863](https://nvd.nist.gov/vuln/detail/CVE-2015-1863) - wpa_supplicant P2P SSID processing heap overwrite triggered while a P2P_FIND or P2P_LISTEN is active.
- [CVE-2016-4476 / CVE-2016-4477](https://nvd.nist.gov/vuln/detail/CVE-2016-4476) - wpa_cli / hostapd_cli control interface command injection reachable through P2P device names and other attacker-controlled strings.
- [CVE-2019-16275](https://nvd.nist.gov/vuln/detail/CVE-2019-16275) - hostapd AP mode source-address validation bypass on protected management frames (P2P GO inherits this).
- [CVE-2021-0326](https://nvd.nist.gov/vuln/detail/CVE-2021-0326) - wpa_supplicant P2P peer info buffer overflow via a crafted management frame in radio range (Android Security Bulletin, Feb 2021).
- [CVE-2021-27803](https://nvd.nist.gov/vuln/detail/CVE-2021-27803) - wpa_supplicant `p2p/p2p_pd.c` Provision Discovery Request handling flaw (DoS or possible code execution, fixed in 2.10).

### WPS / WSC (the P2P provisioning layer)

- [CVE-2011-5053](https://nvd.nist.gov/vuln/detail/CVE-2011-5053) (unverified) - original WPS PIN split brute-force class assigned around Viehbock's disclosure. Applies to P2P GOs that expose Keypad or Label config methods.
- [devttys0 default WPS PIN generation research](https://github.com/devttys0/wps) - Craig Heffner's default-PIN algorithms allow offline computation of the PIN from BSSID. Applies to any P2P GO whose vendor set a computable default PIN.
- [Pixie-Dust class (no single CVE)](https://github.com/wiire-a/pixiewps) - offline WPS PIN recovery against Ralink, Broadcom, Realtek registrar-side E-S1/E-S2 nonce weaknesses (Bongard 2014). Directly applies to P2P GOs using vulnerable WSC registrar implementations.

### Realtek driver P2P-specific

- [CVE-2019-17666](https://nvd.nist.gov/vuln/detail/CVE-2019-17666) - `rtlwifi` P2P Notice of Absence IE heap overflow in `rtl_p2p_noa_ie`, remote RCE class from adjacent radio range (Nico Waisman, Github Security Lab).

### Android Wi-Fi Direct framework

- [CVE-2014-0997](https://www.coresecurity.com/core-labs/advisories/android-wifi-direct-denial-service) - crafted P2P Probe Response with malformed WSC Device Name triggers Dalvik uncaught exception and reboot (Nicolas Trippar / Andres Blanco, Core Security).
- [Android Security Bulletin index](https://source.android.com/docs/security/bulletin) - grep monthly bulletins for `WifiP2p*`, `p2p_supplicant`, `wpa_supplicant`, `wificond` entries.
- [Samsung Mobile Security bulletins (SMR)](https://security.samsungmobile.com/securityUpdate.smsb) - SVE entries covering `p2pd`, `WifiP2pService`, `omacp`, Wi-Fi Direct printing pipeline.

### Miracast (runs on top of a P2P group)

- [CVE-2023-38147](https://nvd.nist.gov/vuln/detail/CVE-2023-38147) - Windows Miracast Wireless Display heap overflow in the RTSP-carried input path, RCE from same-network attacker (Microsoft MSRC, Sep 2023).

## Foundational research

- [Viehbock, "Brute forcing Wi-Fi Protected Setup" (2011)](https://www.cs.cmu.edu/~rdriley/330/papers/viehboeck_wps.pdf) - original WPS external-registrar PIN split flaw. Applies to P2P GOs that expose WSC PIN methods.
- [Bongard, "Offline bruteforce attack on WiFi Protected Setup", Hack.lu 2014](http://archive.hack.lu/2014/Hacklu2014_offline_bruteforce_attack_on_wps.pdf) - Pixie-Dust: insecure PRNG in registrar E-S1/E-S2 nonces.
- [Blanco, "Wi-Fi Direct to Hell" (Black Hat EU 2017)](https://blackhat.com/docs/eu-17/materials/eu-17-Blanco-WI-FI-Direct-To-Hell-Attacking-WI-FI-Direct-Protocol-Implementations.pdf) - the canonical Wi-Fi Direct pentest talk. Attacks against Android, HP printers, Samsung TVs. Covers GO Negotiation, Provision Discovery, Invitation, and Group Formation flaws.
- [Blanco Black Hat EU 2017 white paper](https://blackhat.com/docs/eu-17/materials/eu-17-Blanco-WI-FI-Direct-To-Hell-Attacking-WI-FI-Direct-Protocol-Implementations-wp.pdf) - full write-up companion to the talk.

## Blog posts and write-ups

- [Core Security CoreLabs advisory - Android Wi-Fi Direct DoS (CVE-2014-0997)](https://www.coresecurity.com/core-labs/advisories/android-wifi-direct-denial-service) - malformed Device Name in P2P Probe Response.
- [SensePost, "Improvements in Rogue AP Attacks (MANA)"](https://sensepost.com/blog/2015/improvements-in-rogue-ap-attacks-mana-1/) - Karma-style probe-response attacks; the same pattern applies to P2P Listen-state probe handling.
- [t6x reaver-fork, "A brief history of WPS hacking"](https://github.com/t6x/reaver-wps-fork-t6x/wiki/A-brief-history-of-WPS-hacking) - chronology of WPS attack development.
- [Frosty Hacks, "Pixies Pwn WPS"](https://frostyhacks.blogspot.com/2015/04/pixies-pwn-wps.html) - practical write-up of the offline Pixie-Dust attack chain.
- [axcheron, "Hacking WPS Using Reaver and Pixie Dust"](https://axcheron.github.io/hacking-wps-using-reaver-and-pixie-dust-attack/) - reproducible lab walkthrough.
- [Threatpost, "Four-Year-Old Critical Linux Wi-Fi Bug"](https://threatpost.com/critical-linux-wi-fi-bug-system-compromise/149325/) - context on the rtlwifi P2P NoA bug (CVE-2019-17666).
- [Red Hat Bugzilla 1925152 - CVE-2021-0326 write-up](https://bugzilla.redhat.com/show_bug.cgi?id=1925152) - root-cause description of the wpa_supplicant P2P peer info overflow.
- [Openwall oss-security - wpa_supplicant P2P SSID processing (CVE-2015-1863)](https://www.openwall.com/lists/oss-security/2015/04/22/8) - Jouni Malinen disclosure notes.

## Tools and PoCs

- [t6x/reaver-wps-fork-t6x](https://github.com/t6x/reaver-wps-fork-t6x) - actively maintained WPS PIN attack (online brute force plus Pixie-Dust orchestration). Works against P2P GOs.
- [wiire-a/pixiewps](https://github.com/wiire-a/pixiewps) - offline WPS PIN recovery from captured M1..M3 messages.
- [aanarchyy/bully](https://github.com/aanarchyy/bully) - alternate WPS PIN brute-forcer.
- [ZerBea/hcxdumptool](https://github.com/ZerBea/hcxdumptool) - active/passive Wi-Fi capture including PMKID and WPS IE harvesting.
- [ZerBea/hcxtools](https://github.com/ZerBea/hcxtools) - conversion and analysis for hcxdumptool captures, feeds hashcat.
- [derv82/wifite2](https://github.com/derv82/wifite2) - automation wrapper that drives reaver, bully, pixiewps, hashcat.
- [v1s1t0r1sh3r3/airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon) - multi-purpose Wi-Fi audit script including WPS and Evil Twin flows.
- [kimocoder/OneShot](https://github.com/kimocoder/OneShot) - Python WPS/Pixie-Dust attacker that talks to wpa_supplicant, no monitor mode needed.
- [rofl0r/oneshot](https://github.com/rofl0r/oneshot) - C rewrite of OneShot, single-PIN Pixie-Dust.
- [devttys0/wps](https://github.com/devttys0/wps) - default-PIN generator collection.
- [SensePost hostapd-mana](https://github.com/sensepost/hostapd-mana) - Karma/MANA rogue AP framework. Useful against clients that also engage in P2P Listen.
- [6e726d/WIG](https://github.com/6e726d/WIG) - Wi-Fi Information Gathering, includes a `p2p_scanner.py` targeted at Wi-Fi Direct devices.
- [6e726d/BHEU17](https://github.com/6e726d/BHEU17) - PoC scripts from the Blanco "Wi-Fi Direct to Hell" talk.
- [aircrack-ng/aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) - `airodump-ng` shows WPS status and P2P groups.
- [aircrack-ng/mdk4](https://github.com/aircrack-ng/mdk4) - 802.11 stress and management-frame injection; exercises P2P Listen and Beacon paths.

## Standards and specifications

- [Wi-Fi Alliance Specifications index](https://www.wi-fi.org/discover-wi-fi/specifications) - master list.
- [Wi-Fi Peer-to-Peer (P2P) Technical Specification v1.9 PDF](https://www.wi-fi.org/system/files/Wi-Fi_Direct_Specification_v1.9.pdf) - the canonical Wi-Fi Direct spec: Device / Service Discovery, GO Negotiation, Provision Discovery, Invitation, Persistent Groups, P2P IEs, NoA.
- [Wi-Fi Direct Specification landing page](https://www.wi-fi.org/file/wi-fi-direct-specification) - member-gated download.
- [Wi-Fi Peer-to-Peer Services Technical Specification Package](https://www.wi-fi.org/file/wi-fi-peer-to-peer-services-technical-specification-package) - P2Ps layer on top of Wi-Fi Direct (application service discovery).
- [IBSS with Wi-Fi Protected Setup Technical Specification v1.0.0 (2012)](https://www.wi-fi.org/system/files/IBSS_with_Wi-Fi_Protected_Setup_Technical_Specification_v1.0.0.pdf) - WSC state machine reference.
- [Wi-Fi Simple Configuration Technical Specification (WSC v2.0.7)](https://www.wi-fi.org/discover-wi-fi/specifications) - the provisioning layer P2P Group Formation uses.
- [Wi-Fi Alliance Wi-Fi Display Technical Specification (Miracast)](https://www.wi-fi.org/file/wi-fi-display-technical-specification) - RTSP-based session setup and HDCP 2.x binding above P2P groups.
- [w1.fi wpa_supplicant Wi-Fi Direct / P2P module docs](https://w1.fi/wpa_supplicant/devel/p2p.html) - authoritative implementation-side reference: state machines, control interface commands, event flow.

## Talks and videos

- [Andres Blanco - "Wi-Fi Direct to Hell", Black Hat EU 2017](https://www.blackhat.com/eu-17/briefings.html#wi-fi-direct-to-hell-attacking-wi-fi-direct-protocol-implementations) (unverified session page; the white paper and slides linked above are the authoritative artifacts).
- [Dominique Bongard - "Offline bruteforce attack on WPS", Hack.lu 2014 slides](http://archive.hack.lu/2014/Hacklu2014_offline_bruteforce_attack_on_wps.pdf).
- [Stefan Viehbock slide deck on SlideShare](https://www.slideshare.net/slideshow/viehboeck-wps/10734227) - conference version of the 2011 WPS paper.

## Notes

- Wi-Fi Direct bugs frequently ship in wpa_supplicant. When triaging,
  grep `p2p_*.c`, `wps_*.c`, `wpas_p2p.c`, and vendor `wificond` /
  `wpa_supplicant_binder` glue.
- General WPA2 / WPA3 / 802.11 attacks (KRACK, FragAttacks, Kr00k,
  Framing Frames, SSID Confusion, Dragonblood, Blast-RADIUS) are
  deliberately not in this list. They apply to P2P groups because P2P
  reuses the same handshakes, but they are not Wi-Fi-Direct-specific.
  Track them via the respective researchers' repos.
- Entries marked "(unverified)" could not be fully fetched during
  collection. Verify against NVD or the vendor advisory before citing
  in a formal report.
- Contributions welcome via PR against this file.
