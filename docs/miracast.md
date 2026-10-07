# Miracast (Wi-Fi Display) in DIRECTAX

Miracast is the Wi-Fi Alliance Wi-Fi Display protocol, carried on
top of a Wi-Fi Direct Peer-to-Peer group. The P2P layer handles
discovery and group formation; the Miracast layer runs RTSP over
TCP (default port 7236) for session control, and RTP over UDP for
the H.264 video + LPCM/AAC/AC3 audio stream.

DIRECTAX supports the full Miracast attack chain:

```
  P2P discovery  ->  WFD IE decode  ->  Group join  ->
  RTSP M1-M3 probe  ->  Fuzz / UIBC inject / CVE-2023-38147
```

## Modules

| Subcommand          | Phase | What it does |
|---------------------|-------|--------------|
| `miracast-scan`     | discovery | Over-the-air scan filtered to Miracast devices. Decodes the WFD Information Element (OUI 50-6F-9A, OUI type 0x0A). Shows role (source / primary-sink / secondary-sink), session mgmt TCP port, max throughput Mbps, HDCP 2.x state, associated BSSID, coupled sink MAC. |
| `miracast-probe`    | post-join | TCP connect to a sink IP on port 7236, walks RTSP M1 (OPTIONS) and M3 (GET_PARAMETER wfd_video_formats, wfd_audio_codecs, wfd_client_rtp_ports, wfd_uibc_capability, wfd_content_protection, wfd_3d_video_formats, wfd_display_edid, wfd_coupled_sink, wfd_I2C, wfd_connector_type, wfd_standby_resume_capability). Parses the response. |
| `miracast-sink`     | passive attack | Trivial RTSP responder that echoes CSeq correctly and answers OPTIONS so a Miracast source will progress past M2 and start sending M3/M4 parameters to the attacker. Useful for observing source behavior. |
| `miracast-fuzz`     | active attack | Mutation fuzzer against a sink at :7236. Shapes: baseline, overlong CSeq, negative Content-Length, huge Content-Length, wfd_video_formats field mutations, negative RTP ports, bare-LF header injection, null method, random fuzz tail. Deterministic given a seed. |
| `miracast-uibc`     | active attack | UIBC HID keyboard injection into a Miracast source. Requires an authorized target source listening on a UIBC TCP port learned from its M4 wfd_uibc_capability. |
| `cve-2023-38147`    | targeted CVE | Windows Miracast Wireless Display RTSP heap overflow. Sends a SET_PARAMETER with a wfd_video_formats value carrying ~500 whitespace-separated integer tokens, overflowing a fixed parser buffer in the WirelessDisplay service. Observable: sink stops answering RTSP OPTIONS. |

## Attack chain example (lab target)

Assume you have a Miracast sink in RF range (TV, Microsoft Wireless
Display Adapter, Windows PC with "Projecting to this PC" enabled).

```bash
# 1. Find the sink and its RTSP port
sudo python3 scan.py miracast-scan --duration 60 --all-bands --active --authorized

# 2. Join its P2P group as a client (use wpa_cli outside DIRECTAX)
sudo wpa_cli -i wlan0 p2p_connect <sink-p2p-mac> pbc join

# 3. From inside the group, note the sink's IP address
ip addr show p2p-wlan0-0

# 4. RTSP probe the sink to enumerate what it supports
sudo python3 scan.py miracast-probe --sink <sink-ip> --port 7236 --authorized

# 5. If the sink is a Windows machine, test CVE-2023-38147
sudo python3 scan.py cve-2023-38147 --sink <sink-ip> --port 7236 --authorized

# 6. Fuzz the sink's RTSP parser
python3 scan.py miracast-fuzz --sink <sink-ip> --cases 256 --seed 1 --authorized

# 7. If the sink later becomes a source, inject HID via UIBC
sudo python3 scan.py miracast-uibc --source <source-ip> \
                                    --uibc-port 7239 \
                                    --text 'notepad.exe\nhello' \
                                    --authorized
```

## Protocol references

- Wi-Fi Alliance Wi-Fi Display Technical Specification v2.1.0 (requires
  Wi-Fi Alliance membership for the official PDF; subset documented in
  publicly-available vendor stacks like gstreamer `gstwfddemux` and
  openwrt `miraclecast`).
- IETF RFC 2326 (RTSP 1.0) for the message framing.
- USB HID Usage Tables 1.5, Keyboard/Keypad page, for the UIBC usage codes.

## Observable attack surface per role

### Miracast sink (TV, dongle, Windows "Projecting to this PC")

- TCP 7236 RTSP control (default): CVE-2023-38147, generic RTSP fuzz
- TCP 7250 HDCP 2.x authentication (default)
- UDP ports 1028+ RTP/RTCP for incoming media
- The sink parses: `wfd_presentation_URL`, `wfd_trigger_method`,
  `wfd_route`, `wfd_connector_type`, EDID blob from the source
- Multi-vendor known attack surface:
  - Miracast CA (Microsoft)
  - Mirroring 360, EZCast dongles (frequent CVEs 2017-2022)
  - LG WebOS, Samsung Tizen Miracast implementations

### Miracast source (laptop screen-sharing to a TV)

- TCP wfd_uibc_capability port (listening for sink input)
- TCP wfd_remote_display_control port (if advertised)
- Parses sink responses in M2, M3 responses, M5 wfd_trigger_method,
  teardown messages

### Attacker-as-sink (rogue sink)

- Receive source's EDID, screen contents (if media negotiated), audio
- Via UIBC: inject keyboard/mouse/touch into source
- Observe source's device fingerprint from M3 Server header

## Safety rules recap

- UIBC injection is a full input-takeover attack. Only against sources
  you own.
- CVE-2023-38147 crashes the Wireless Display service on an unpatched
  Windows box. Lab targets only.
- Fuzzing is bounded by the module (max cases, deterministic seed).
  Do not point `miracast-fuzz` at a sink you cannot restart.

## What is NOT in scope

- HDCP 2.x cryptographic break. HDCP keys are not published; attacks
  that leak the master key (LockDown, published in 2010 for HDCP 1.x
  only) do not apply to Miracast's HDCP 2.x.
- Media stream decryption after a successful HDCP handshake. The AES-128
  CCM session key is derived from the HDCP exchange; without the
  master key, this is a cryptographic break out of scope.
- Weaponized shellcode for CVE-2023-38147. Module stops at
  reproducible crash per the DIRECTAX RCE boundary rule.
