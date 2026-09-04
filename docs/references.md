# Wi-Fi Direct (P2P) Security Research - Reference Bibliography

Scope: attacking or auditing Wi-Fi Direct (Wi-Fi P2P) as a protocol, plus
adjacent surfaces that touch P2P group formation, WPS/WSC provisioning,
WPA2/3 handshakes in P2P groups, Miracast on top of P2P, and Neighbor
Awareness Networking. Every entry links to a real public artifact. Items
that could not be fetched and confirmed end-to-end are marked
"(unverified)".

## CVEs by category

### wpa_supplicant / hostapd - P2P and WSC handling

- [CVE-2015-1863](https://nvd.nist.gov/vuln/detail/CVE-2015-1863) - wpa_supplicant P2P SSID processing heap overwrite triggered while a P2P_FIND or P2P_LISTEN is active (Jouni Malinen, oss-security 2015).
- [CVE-2016-4476 / CVE-2016-4477](https://nvd.nist.gov/vuln/detail/CVE-2016-4476) - wpa_cli / hostapd_cli control interface command injection reachable through P2P device names and other attacker-controlled strings.
- [CVE-2019-9494](https://nvd.nist.gov/vuln/detail/CVE-2019-9494) - Dragonblood: SAE cache-timing side channel in hostapd and wpa_supplicant SAE (used by WPA3-Personal, which also covers P2P groups running WPA3).
- [CVE-2019-9495](https://nvd.nist.gov/vuln/detail/CVE-2019-9495) - Dragonblood: EAP-pwd cache-based side channel in hostapd / wpa_supplicant.
- [CVE-2019-9497](https://nvd.nist.gov/vuln/detail/CVE-2019-9497) - EAP-pwd server missing reflection check, authentication bypass without password.
- [CVE-2019-9498](https://nvd.nist.gov/vuln/detail/CVE-2019-9498) - hostapd EAP-pwd server missing commit validation, invalid scalar/element accepted.
- [CVE-2019-9499](https://nvd.nist.gov/vuln/detail/CVE-2019-9499) - wpa_supplicant EAP-pwd peer missing commit validation.
- [CVE-2019-16275](https://nvd.nist.gov/vuln/detail/CVE-2019-16275) - hostapd AP mode source-address validation bypass on protected management frames.
- [CVE-2021-0326](https://nvd.nist.gov/vuln/detail/CVE-2021-0326) - wpa_supplicant P2P (Wi-Fi Direct) peer info buffer overflow via a crafted management frame in radio range (Android Security Bulletin, Feb 2021).
- [CVE-2021-27803](https://nvd.nist.gov/vuln/detail/CVE-2021-27803) - wpa_supplicant p2p/p2p_pd.c provision discovery request handling flaw, DoS or possible code execution (fixed in 2.10).
- [CVE-2021-30004](https://nvd.nist.gov/vuln/detail/CVE-2021-30004) - hostapd forwarded EAP handling flaw.
- [CVE-2022-23303](https://nvd.nist.gov/vuln/detail/CVE-2022-23303) - Residual SAE side channel (incomplete fix for CVE-2019-9494), pre-2.10 hostapd/wpa_supplicant.
- [CVE-2022-23304](https://nvd.nist.gov/vuln/detail/CVE-2022-23304) - Residual EAP-pwd side channel (incomplete fix for CVE-2019-9495).
- [CVE-2023-52160](https://nvd.nist.gov/vuln/detail/CVE-2023-52160) - wpa_supplicant PEAP MSCHAPv2 server-cert-not-verified authentication bypass (Top10VPN 2024).
- [CVE-2024-3596](https://nvd.nist.gov/vuln/detail/CVE-2024-3596) - Blast-RADIUS: RADIUS Response Authenticator MD5 collision, affects any 802.1X/EAP path used in enterprise-provisioned P2P/hotspot flows.
- [CVE-2024-5290](https://nvd.nist.gov/vuln/detail/CVE-2024-5290) - Ubuntu wpa_supplicant D-Bus interface allowed loading arbitrary shared objects, root LPE.

### WPS / Wi-Fi Simple Configuration

- [CVE-2011-5053](https://nvd.nist.gov/vuln/detail/CVE-2011-5053) (unverified) - Original WPS PIN split brute-force class assigned around Viehbock's disclosure.
- [Belkin / Broadcom default WPS PIN generation](https://www.kb.cert.org/vuls/) - default WPS PIN algorithms allow offline computation of the PIN from BSSID (see Craig Heffner devttys0 pingens).
- [Pixie-Dust class (no single CVE)](https://github.com/wiire-a/pixiewps) - offline WPS PIN recovery against Ralink, Broadcom, Realtek registrar-side E-S1/E-S2 nonce weaknesses (Bongard 2014).
- [CVE-2019-15126 (Kr00k)](https://nvd.nist.gov/vuln/detail/CVE-2019-15126) - all-zero PTK on Broadcom/Cypress FullMAC after disassociation, decrypts buffered frames; applies to P2P groups too because they run the same 4-way handshake.

### Broadcom / Cypress Wi-Fi (FullMAC firmware and brcmfmac driver)

- [CVE-2017-3544 / CVE-2017-9417 (BroadPwn)](https://nvd.nist.gov/vuln/detail/CVE-2017-9417) - heap overflow in BCM43xx firmware WME IE handling, RCE in Wi-Fi chipset (Artenstein, Black Hat 2017).
- [CVE-2017-11120 / CVE-2017-11121](https://nvd.nist.gov/vuln/detail/CVE-2017-11120) - Project Zero Broadcom Wi-Fi firmware OOB writes reachable from associated STA (Gal Beniamini).
- [CVE-2019-9500](https://nvd.nist.gov/vuln/detail/CVE-2019-9500) - brcmfmac heap overflow in Wake-Up-on-Wireless-LAN (Quarkslab).
- [CVE-2019-9501 / CVE-2019-9502](https://nvd.nist.gov/vuln/detail/CVE-2019-9501) - brcmfmac / firmware heap overflows via oversize vendor IE in EAPOL / assoc-response paths.
- [CVE-2019-9503](https://nvd.nist.gov/vuln/detail/CVE-2019-9503) - brcmfmac frame-source-check bypass, remote firmware event injection.

### Realtek Wi-Fi (rtlwifi / rtw88 / RTL8xxx firmware)

- [CVE-2019-17666](https://nvd.nist.gov/vuln/detail/CVE-2019-17666) - rtlwifi P2P Notice of Absence IE heap overflow in `rtl_p2p_noa_ie`, remote RCE class from adjacent radio range (Nico Waisman).
- [CVE-2020-27301](https://nvd.nist.gov/vuln/detail/CVE-2020-27301) - RTL8170C stack overflow in WPA2 4-way handshake handling.
- [CVE-2020-27302](https://nvd.nist.gov/vuln/detail/CVE-2020-27302) - Second RTL8170C 4-way handshake stack overflow variant.
- [CVE-2021-28040](https://nvd.nist.gov/vuln/detail/CVE-2021-28040) (unverified) - rtlwifi USB Realtek DMA descriptor OOB.

### MediaTek Wi-Fi (mt76 / MT7615 / MT7921 / MT7925 / MT7622)

- [CVE-2024-20017](https://nvd.nist.gov/vuln/detail/CVE-2024-20017) - MT7622/MT7915 wappd zero-click OOB write, remote RCE (SonicWall write-up).
- [CVE-2022-32666](https://nvd.nist.gov/vuln/detail/CVE-2022-32666) (unverified) - MediaTek 802.11 Block Ack frame handling flaw.
- [MediaTek Product Security Bulletins - monthly index](https://corp.mediatek.com/product-security-bulletin) - authoritative list of chipset advisories including MT79xx families.
- MT7921 CLC country IE crash and MT7925 mt76 fixes appear in recent Linux kernel CVE feeds; verify against NVD before citing.

### Qualcomm Wi-Fi (QCA / WCN / FastConnect firmware)

- [Qualcomm Product Security Bulletins](https://docs.qualcomm.com/product/publicresources/securitybulletin/) - monthly QSR list, source of truth for QCA/WCN CVEs.
- [CVE-2024-21477](https://nvd.nist.gov/vuln/detail/CVE-2024-21477) - Qualcomm firmware 802.11az FTM frame DoS.
- [CVE-2025-21446](https://nvd.nist.gov/vuln/detail/CVE-2025-21446) - Qualcomm WLAN firmware DoS via crafted vendor IE in BSS Transition Management request.
- [CVE-2025-47383](https://nvd.nist.gov/vuln/detail/CVE-2025-47383) - Qualcomm WCN/QCA VoWiFi missing cryptographic step, cipher-downgrade class.

### Miracast / Wi-Fi Display

- [CVE-2023-38147](https://nvd.nist.gov/vuln/detail/CVE-2023-38147) - Windows Miracast Wireless Display heap overflow in the RTSP-carried input path, RCE from same-network attacker (Microsoft MSRC, Sep 2023).
- [scip Labs - Attacks against Miracast](https://www.scip.ch/en/?labs.20211104=) (unverified) - vendor-side survey of Miracast attack surface (RTSP, HDCP2.x, source URL handling).

### Wi-Fi Aware / NAN

- [Vanhoef et al., "OpenNAN" desynchronization and MitM against Wi-Fi Aware](https://dl.acm.org/doi/10.1145/3479241.3486689) - MSWiM 2021 paper documenting Anchor Master hijack, unicast-beacon desync, and SDF MitM against Android NAN.
- [Android Security Bulletin index](https://source.android.com/docs/security/bulletin) - track NAN / p2p / wifi_hal CVEs each month.

### 802.11 cross-cutting flaws that hit P2P groups

P2P groups reuse the WPA2/3 4-way handshake, aggregation, and fragmentation. Every one of these applies.

- [CVE-2017-13077..CVE-2017-13088 (KRACK)](https://www.krackattacks.com/) - key reinstallation across the WPA2 4-way, group-key, FT, and TDLS handshakes.
- [CVE-2020-24586 to CVE-2020-24588 and CVE-2020-26139..CVE-2020-26147 (FragAttacks)](https://www.fragattacks.com/) - design and implementation flaws in 802.11 frame aggregation and fragmentation.
- [CVE-2019-15126 (Kr00k)](https://web-assets.esetstatic.com/wls/2020/02/ESET_Kr00k.pdf) - all-zero PTK on Broadcom / Cypress after disassociation.
- [Framing Frames (USENIX Security 2023) - CVE-2022-47522 and related](https://papers.mathyvanhoef.com/usenix2023-wifi.pdf) - power-save queued-frame decryption and MAC-layer client isolation bypass.
- [CVE-2023-52424 (SSID Confusion)](https://www.top10vpn.com/research/wifi-vulnerability-ssid/) - IEEE 802.11 does not authenticate the SSID; victim connects to a different network than intended.
- [CVE-2024-3596 (Blast-RADIUS)](https://www.blastradius.fail/) - impacts enterprise-provisioned Wi-Fi where P2P groups reuse enterprise creds.

### Android P2P framework and vendor daemons

- [CVE-2014-0997 (Android Wi-Fi Direct DoS)](https://www.coresecurity.com/core-labs/advisories/android-wifi-direct-denial-service) - crafted P2P Probe Response with malformed WSC Device Name triggers Dalvik uncaught exception and reboot (Nicolas Trippar / Andres Blanco, Core Security).
- [Android Security Bulletins - keyword search "wifi", "p2p", "wpa_supplicant", "hostapd"](https://source.android.com/docs/security/bulletin) - the canonical index; entries frequently mention `p2p`, `WifiP2pServiceImpl`, `wifi_hal`, `SoftAp`, `wificond`, and vendor components like Broadcom/Qualcomm/MediaTek.
- [Samsung Mobile Security bulletins (SMR)](https://security.samsungmobile.com/securityUpdate.smsb) - SVE entries covering `p2pd`, `WifiP2pService`, `omacp`, Wi-Fi Direct printing pipeline.
- [Huawei PSIRT advisory - Wi-Fi hotspot info disclosure CVE-2020-9260](https://www.huawei.com/en/psirt/security-advisories/2020/huawei-sa-20200708-01-smartphone-en) - example of vendor Wi-Fi surface disclosure.

## Foundational research

- [Viehbock, "Brute forcing Wi-Fi Protected Setup" (2011)](https://www.cs.cmu.edu/~rdriley/330/papers/viehboeck_wps.pdf) - original WPS external-registrar PIN split flaw enabling online brute force.
- [Bongard, "Offline bruteforce attack on WiFi Protected Setup", Hack.lu 2014](http://archive.hack.lu/2014/Hacklu2014_offline_bruteforce_attack_on_wps.pdf) - the Pixie-Dust paper, insecure PRNG in registrar E-S1/E-S2 nonces on Ralink, Broadcom, Realtek chipsets.
- [Vanhoef and Piessens, "Key Reinstallation Attacks: Forcing Nonce Reuse in WPA2", CCS 2017](https://papers.mathyvanhoef.com/ccs2017.pdf) - KRACK, the WPA2 handshake reinstallation class that also affects P2P group handshakes.
- [Vanhoef and Ronen, "Dragonblood: Analyzing WPA3's Dragonfly Handshake" (2019)](https://wpa3.mathyvanhoef.com/) - side-channel and downgrade attacks against SAE/WPA3-Personal.
- [Vanhoef, "FragAttacks: Fragmentation and Aggregation Attacks in Wi-Fi" USENIX Security 2021](https://papers.mathyvanhoef.com/usenix2021.pdf) - 12 CVEs across the 802.11 stack.
- [Schepers, Vanhoef, Ranganathan, "Framing Frames: Bypassing Wi-Fi Encryption by Manipulating Transmit Queues", USENIX Security 2023](https://papers.mathyvanhoef.com/usenix2023-wifi.pdf) - power-save queued-frame decryption and client isolation bypass.
- [Vanhoef, "SSID Confusion" (2024)](https://top10vpn.com/research/wifi-vulnerability-ssid/) - CVE-2023-52424 SSID not authenticated in beacon or 4-way handshake.
- [Vanhoef publications page (index)](https://www.mathyvanhoef.com/p/publications.html) - authoritative list for KRACK, Dragonblood, FragAttacks, TunnelCrack, Framing Frames, SSID Confusion.
- [ESET, "Kr00k: CVE-2019-15126" white paper (2020)](https://web-assets.esetstatic.com/wls/2020/02/ESET_Kr00k.pdf) - all-zero PTK class on Broadcom/Cypress FullMAC.
- [Fraunhofer AISEC, "So you want to play with Wi-Fi"](https://www.cybersecurity.blog.aisec.fraunhofer.de/en/so-you-want-to-play-with-wi-fi/) - practical primer on 802.11 fuzzing and frame crafting.
- [Owfuzz, WiSec 2023](https://dl.acm.org/doi/10.1145/3558482.3590174) - over-the-air Wi-Fi management-frame fuzzing.
- [Frankenstein: Advanced Wireless Fuzzing to Exploit New Bluetooth Escalation Targets (arXiv 2020)](https://arxiv.org/pdf/2006.09809) - Broadcom Wi-Fi/Bluetooth combo firmware fuzzing (Ruhr-University).
- [Bl0ck: Paralyzing 802.11 connections through Block Ack frames (arXiv 2302.05899)](https://arxiv.org/pdf/2302.05899) - Block Ack based DoS relevant to P2P group data path.
- [Schepers and Vanhoef, "Release the Kraken: New KRACKs in the 802.11 Standard" CCS 2018](https://papers.mathyvanhoef.com/ccs2018.pdf) - follow-on KRACK variants.
- [CISPA Voice over Wi-Fi Calling security assessment](https://cispa.de/en/wlan-calling) - VoWiFi crypto weaknesses in Xiaomi / Oppo MediaTek chips.

## Blog posts and write-ups

- [Blanco, "Wi-Fi Direct to Hell", Black Hat EU 2017 slides](https://blackhat.com/docs/eu-17/materials/eu-17-Blanco-WI-FI-Direct-To-Hell-Attacking-WI-FI-Direct-Protocol-Implementations.pdf) and [white paper](https://blackhat.com/docs/eu-17/materials/eu-17-Blanco-WI-FI-Direct-To-Hell-Attacking-WI-FI-Direct-Protocol-Implementations-wp.pdf) - practical Wi-Fi Direct attack surface: Android, HP printers, Samsung TVs.
- [BHEU17 tools repo (Andres Blanco / 6e726d)](https://github.com/6e726d/BHEU17) - PoC scripts from the Wi-Fi Direct to Hell talk.
- [Core Security CoreLabs advisory - Android Wi-Fi Direct DoS (CVE-2014-0997)](https://www.coresecurity.com/core-labs/advisories/android-wifi-direct-denial-service) - malformed Device Name in P2P Probe Response.
- [Google Project Zero, "Over The Air: Exploiting Broadcom's Wi-Fi Stack, Part 1"](https://googleprojectzero.blogspot.com/2017/04/over-air-exploiting-broadcoms-wi-fi_4.html) - firmware reverse-engineering and vulnerabilities in bcmwl / dongle firmware.
- [Google Project Zero, "Over The Air, Part 2"](https://googleprojectzero.blogspot.com/2017/04/over-air-exploiting-broadcoms-wi-fi_11.html) - full-chain host-side exploitation from the Wi-Fi chip.
- [Quarkslab, "Reverse engineering Broadcom wireless chipsets"](https://blog.quarkslab.com/reverse-engineering-broadcom-wireless-chipsets.html) - dongle firmware layout and tooling.
- [SensePost, "Improvements in Rogue AP Attacks (MANA)"](https://sensepost.com/blog/2015/improvements-in-rogue-ap-attacks-mana-1/) - Karma-style probe-response attacks; also applies to P2P Listen-mode probe handling.
- [devttys0 WPS default-PIN pingens (Craig Heffner)](https://github.com/devttys0/wps) - vendor default WPS PIN algorithms for D-Link, Belkin.
- [t6x reaver-fork "A brief history of WPS hacking"](https://github.com/t6x/reaver-wps-fork-t6x/wiki/A-brief-history-of-WPS-hacking) - concise chronology of WPS attack development.
- [Frosty Hacks, "Pixies Pwn WPS"](https://frostyhacks.blogspot.com/2015/04/pixies-pwn-wps.html) - practical write-up of the offline Pixie-Dust attack chain.
- [axcheron, "Hacking WPS Using Reaver and Pixie Dust"](https://axcheron.github.io/hacking-wps-using-reaver-and-pixie-dust-attack/) - reproducible lab walkthrough.
- [kimocoder OneShot README](https://github.com/kimocoder/OneShot) - Pixie-Dust and WPS PIN attacks without monitor mode via wpa_supplicant.
- [Ubuntu Security Notice on wpa_supplicant Dragonblood set (USN-3944-1)](https://usn.ubuntu.com/3944-1/) - concise vendor-side summary of CVE-2019-9494/9495/9497/9498/9499.
- [Debian DSA-4430-1 - wpa security update](https://lists.debian.org/debian-security-announce/2019/msg00074.html) - upstream fixes for the same Dragonblood cluster.
- [Gentoo GLSA-202309-16 - hostapd/wpa_supplicant multiple vulns](https://security.gentoo.org/glsa/202309-16) - captures CVE-2022-23303/23304 residual side channel.
- [Red Hat Bugzilla 1925152 - CVE-2021-0326 write-up](https://bugzilla.redhat.com/show_bug.cgi?id=1925152) - detailed root-cause description of the P2P peer-info overflow.
- [Openwall oss-security - wpa_supplicant P2P SSID processing (CVE-2015-1863)](https://www.openwall.com/lists/oss-security/2015/04/22/8) - original Jouni Malinen disclosure notes.
- [The Hacker News, "Broadpwn: Millions of Android Devices Using Broadcom Wi-Fi Chip"](https://thehackernews.com/2017/07/android-ios-broadcom-hacking.html) - accessible summary of CVE-2017-9417.
- [Threatpost, "Four-Year-Old Critical Linux Wi-Fi Bug" (CVE-2019-17666)](https://threatpost.com/critical-linux-wi-fi-bug-system-compromise/149325/) - context on the rtlwifi P2P NoA bug.
- [SonicWall, "Critical Exploit in MediaTek Wi-Fi Chipsets: CVE-2024-20017"](https://www.sonicwall.com/blog/critical-exploit-in-mediatek-wi-fi-chipsets-zero-click-vulnerability-cve-2024-20017-threatens-routers-and-smartphones) - technical breakdown of the MT7622/MT7915 wappd bug.
- [Cisco Meraki, "FullMAC Wi-Fi chipsets vulnerability (Kr00k)"](https://documentation.meraki.com/Platform_Management/Product_Information/Privacy,_Security,_Compliance/FullMAC_Wi-Fi_chipsets_vulnerability_(kr00k)) - vendor-side explanation of the FullMAC vs SoftMAC blast radius.
- [Top10VPN, "SSID Confusion Attack"](https://www.top10vpn.com/research/wifi-vulnerability-ssid/) - lay-friendly summary of CVE-2023-52424.
- [CERT/CC VU#871675 - WPA3 design and implementation vulns](https://www.kb.cert.org/vuls/id/871675) - Dragonblood coordination note.

## Tools and PoCs

- [t6x/reaver-wps-fork-t6x](https://github.com/t6x/reaver-wps-fork-t6x) - actively maintained WPS PIN attack (online brute force plus Pixie-Dust orchestration).
- [wiire-a/pixiewps](https://github.com/wiire-a/pixiewps) - offline WPS PIN recovery from captured M1..M3 messages.
- [aanarchyy/bully](https://github.com/aanarchyy/bully) - alternate WPS PIN brute-forcer in C, sometimes more reliable than reaver against locked APs.
- [ZerBea/hcxdumptool](https://github.com/ZerBea/hcxdumptool) - active/passive Wi-Fi capture including PMKID and WPS IE harvesting.
- [ZerBea/hcxtools](https://github.com/ZerBea/hcxtools) - conversion and analysis for hcxdumptool captures, feeds hashcat.
- [derv82/wifite2](https://github.com/derv82/wifite2) - automation wrapper that drives reaver, bully, pixiewps, hashcat.
- [v1s1t0r1sh3r3/airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon) - multi-purpose Wi-Fi audit script including WPS and Evil Twin flows.
- [kimocoder/OneShot](https://github.com/kimocoder/OneShot) - Python WPS/Pixie-Dust attacker that talks to wpa_supplicant, no monitor mode needed.
- [rofl0r/oneshot](https://github.com/rofl0r/oneshot) - C rewrite of OneShot, single-PIN Pixie-Dust via wpa_supplicant.
- [nikita-yfh/OneShot-C](https://github.com/nikita-yfh/OneShot-C) (unverified) - actively forked C implementation for embedded targets.
- [drygdryg/OneShot](https://github.com/drygdryg/OneShot) (unverified) - the original Python OneShot upstream.
- [devttys0/wps](https://github.com/devttys0/wps) - Craig Heffner default-PIN generator collection.
- [SensePost hostapd-mana](https://github.com/sensepost/hostapd-mana) - Karma/MANA rogue AP framework with EAP capture; useful against clients that also engage in P2P Listen.
- [OpenSecurityResearch/hostapd-wpe](https://github.com/OpenSecurityResearch/hostapd-wpe) - hostapd with 802.1X impersonation attacks (WPE).
- [6e726d/WIG](https://github.com/6e726d/WIG) - Wi-Fi Information Gathering, includes a `p2p_scanner.py` targeted at Wi-Fi Direct devices.
- [vanhoefm/krackattacks-scripts](https://github.com/vanhoefm/krackattacks-scripts) - reproducer scripts for the KRACK class.
- [vanhoefm/fragattacks](https://github.com/vanhoefm/fragattacks) - FragAttacks test suite.
- [vanhoefm/dragondrain-and-time](https://github.com/vanhoefm/dragondrain-and-time) - Dragonblood tester for SAE.
- [vanhoefm/macstealer](https://github.com/vanhoefm/macstealer) - MAC/queue-based client isolation bypass (Framing Frames).
- [google/syzkaller Wi-Fi fuzzing docs](https://github.com/google/syzkaller/blob/master/docs/linux/wifi_fuzzing.md) - upstream 802.11 fuzzing profile via mac80211_hwsim.
- [seemoo-lab/nexmon](https://github.com/seemoo-lab/nexmon) - Broadcom/Cypress firmware patching framework, prerequisite for many BCM Wi-Fi research PoCs.
- [seemoo-lab/frankenstein](https://github.com/seemoo-lab/frankenstein) - firmware emulator used for BCM Wi-Fi/BT fuzzing.
- [seemoo-lab/owl](https://github.com/seemoo-lab/owl) - open Apple AWDL implementation, adjacent P2P surface useful for cross-comparison.
- [seemoo-lab/opendrop](https://github.com/seemoo-lab/opendrop) - AirDrop reimplementation over AWDL.
- [seemoo-lab/opennan](https://github.com/seemoo-lab/opennan) - open Wi-Fi Aware / NAN implementation used in the MSWiM 2021 attacks.
- [boofuzz](https://github.com/jtpereyda/boofuzz) - protocol fuzzer; commonly wrapped to fuzz Miracast RTSP and P2P action frames.
- [aircrack-ng/aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) - the underlying capture and injection toolkit; `airodump-ng` shows WPS status and P2P groups.
- [aircrack-ng/mdk4](https://github.com/aircrack-ng/mdk4) - 802.11 stress and management-frame injection, exercises P2P Listen and Beacon paths.
- [sensepost/mana](https://github.com/sensepost/mana) (unverified) - full evil-twin lab, historical reference.

## Standards and specifications

- [Wi-Fi Alliance Specifications index](https://www.wi-fi.org/discover-wi-fi/specifications) - master list.
- [Wi-Fi Peer-to-Peer (P2P) Technical Specification v1.9 PDF](https://www.wi-fi.org/system/files/Wi-Fi_Direct_Specification_v1.9.pdf) - the canonical Wi-Fi Direct spec: Device / Service Discovery, GO Negotiation, Provision Discovery, Invitation, Persistent Groups, P2P IEs.
- [Wi-Fi Direct Specification landing page](https://www.wi-fi.org/file/wi-fi-direct-specification) - member-gated download.
- [Wi-Fi Peer-to-Peer Services Technical Specification Package](https://www.wi-fi.org/file/wi-fi-peer-to-peer-services-technical-specification-package) - P2Ps layer on top of Wi-Fi Direct (application service discovery).
- [IBSS with Wi-Fi Protected Setup Technical Specification v1.0.0 (2012)](https://www.wi-fi.org/system/files/IBSS_with_Wi-Fi_Protected_Setup_Technical_Specification_v1.0.0.pdf) - historical, useful for WSC state machine reference.
- [Wi-Fi Easy Connect (DPP) Specification v3.0](https://www.wi-fi.org/system/files/Wi-Fi_Easy_Connect_Specification_v3.0.pdf) - the modern DPP-based provisioning that co-exists with WSC in P2P Group Owners.
- [IEEE 802.11-2020 standard (IEEE Get Program)](https://standards.ieee.org/ieee/802.11/7028/) - baseline 802.11 MAC and PHY, covers the frame formats P2P rides on.
- [Wi-Fi Alliance Wi-Fi Display Technical Specification (Miracast)](https://www.wi-fi.org/file/wi-fi-display-technical-specification) - RTSP-based session setup and HDCP 2.x binding above P2P groups.
- [Wi-Fi Alliance Neighbor Awareness Networking (Wi-Fi Aware) Specification](https://www.wi-fi.org/file/neighbor-awareness-networking-specification) - NAN discovery, ranging, and secure pairing.
- [w1.fi wpa_supplicant Wi-Fi Direct / P2P module docs](https://w1.fi/wpa_supplicant/devel/p2p.html) - authoritative implementation-side reference: state machines, control interface commands, event flow.
- [Android Wi-Fi Aware (developer reference)](https://developer.android.com/develop/connectivity/wifi/wifi-aware) - API-level view of the NAN attack surface on Android.
- [AOSP Wi-Fi Aware system implementation notes](https://source.android.com/docs/core/connect/wifi-aware) - HAL-level view into what a P2P/NAN researcher can reach.

## Talks and videos

- [Andres Blanco - "Wi-Fi Direct to Hell", Black Hat EU 2017](https://www.blackhat.com/eu-17/briefings.html#wi-fi-direct-to-hell-attacking-wi-fi-direct-protocol-implementations) (unverified session page, use white paper linked above).
- [Nitay Artenstein - "Broadpwn", Black Hat USA 2017](https://www.blackhat.com/us-17/briefings/schedule/#broadpwn-remotely-compromising-android-and-ios-via-a-bug-in-broadcoms-wi-fi-chipsets-7603) with [white paper PDF](https://blackhat.com/docs/us-17/thursday/us-17-Artenstein-Broadpwn-Remotely-Compromising-Android-And-iOS-Via-A-Bug-In-Broadcoms-Wifi-Chipsets-wp.pdf).
- [Gal Beniamini talk material via Project Zero blog (2017)](https://googleprojectzero.blogspot.com/2017/04/over-air-exploiting-broadcoms-wi-fi_11.html) - the reference for BCM Wi-Fi firmware exploitation techniques.
- [Mathy Vanhoef - KRACK announcement + CCS 2017 recording](https://www.krackattacks.com/) - talk PDF and video links.
- [Vanhoef - "FragAttacks: Breaking Wi-Fi through Frame Aggregation and Fragmentation", Black Hat USA 2021](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Fragattacks-Breaking-Wi-Fi-Through-Fragmentation-And-Aggregation-wp.pdf).
- [Vanhoef - "Attacking WPA3: New Vulnerabilities and Exploit Framework", HITB 2022](https://conference.hitb.org/hitbsecconf2022sin/materials/D1T1%20-%20Attacking%20WPA3%20-%20New%20Vulnerabilities%20and%20Exploit%20Framework%20-%20Mathy%20Vanhoef.pdf).
- [Schepers, Vanhoef - "Framing Frames", USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/schepers) - talk page with video.
- [Vanhoef - "SSID Confusion" DEF CON 32 (2024)](https://top10vpn.com/research/wifi-vulnerability-ssid/) (unverified DEF CON page) - talk companion to CVE-2023-52424.
- [Dominique Bongard - "Offline bruteforce attack on WPS", Hack.lu 2014 slides](http://archive.hack.lu/2014/Hacklu2014_offline_bruteforce_attack_on_wps.pdf).
- [Stefan Viehbock slide deck on SlideShare](https://www.slideshare.net/slideshow/viehboeck-wps/10734227) - conference-style version of the 2011 WPS paper.
- [Craig Heffner - Black Hat USA 2013 speaker page](https://www.blackhat.com/us-13/speakers/Craig-Heffner.html) - background on the reaver author.

## Notes

- "Wi-Fi Direct" bugs frequently ship in wpa_supplicant even when
  reported against Android. When triaging, grep `p2p_*.c`, `wps_*.c`,
  `wpas_p2p.c`, and vendor `wificond` / `wpa_supplicant_binder` glue.
- Full public exploits for BCM / Realtek / MediaTek firmware bugs are
  rare. The Project Zero and Quarkslab posts remain the practical
  starting points for chipset-side research.
- Entries marked "(unverified)" could not be fully fetched during
  collection. Verify against NVD or the vendor advisory before citing
  in a formal report.
- This list is not exhaustive. Contributions welcome via PR against
  this file.
