# Sample Run

Real bench output from a first-time run against an Alfa AWUS036AXML
(MediaTek MT7921AU, `mt7921u` driver). No fabricated data.

## Preflight

```
$ sudo python3 scan.py --preflight

all required tools present
adapters:
  wlp148s0   iwlwifi      LIMITED  Intel AX2xx / AC9xxx
             note:  firmware restricts management-frame injection;
                    deauth and beacon flood are unreliable to non-functional
             block: iwlwifi: no P2P interface mode; pbc-race, invitation,
                    and rogue-go need a second adapter
  wlx00c0caba4c85 mt7921u   READY    MediaTek MT7921AU (Alfa AWUS036AXML / AXM / AX)
             modes: P2P
             note:  Wi-Fi 6 (802.11ax), NOT Wi-Fi 7. Chip supports 6 GHz
                    but the AWUS036AXML SKU is 2.4/5 GHz only.
                    AWUS036AXER is the 6 GHz variant.
             note:  P2P concurrent mode driver-limited on kernels < 6.5
```

## Driver probe

```
$ sudo python3 scan.py driver-probe -i wlx00c0caba4c85

{
  "iface": "wlx00c0caba4c85",
  "phy": "phy2",
  "driver": "mt7921u",
  "supports_monitor": true,
  "supports_active_monitor": false,
  "supports_p2p_go": true,
  "supports_p2p_client": true,
  "supports_p2p_device": true,
  "supports_5ghz": true,
  "supports_6ghz": true,
  "supported_ciphers": [
    "WEP40", "WEP104", "TKIP", "CCMP-128", "CCMP-256",
    "GCMP-128", "GCMP-256", "CMAC", "CMAC-256",
    "GMAC-128", "GMAC-256"
  ],
  "warnings": []
}
```

Full cipher list plus every P2P interface mode. WPA3-SAE capable, so
`rogue-go --sae-transition` works on this card.

## Passive discovery

```
$ sudo python3 scan.py discover --duration 60 --detail

[directax] auto-selected wlx00c0caba4c85
           (MediaTek MT7921AU (Alfa AWUS036AXML / AXM / AX), mt7921u)
           [sole READY adapter]
[directax] override: -i <iface>  |  pick menu: --pick-adapter

 ____  ___ ____  _____ ____ _____  _    __  __
|  _ \|_ _|  _ \| ____/ ___|_   _|/ \   \ \/ /
| | | || || |_) |  _|| |     | | / _ \   \  /
| |_| || ||  _ <| |__| |___  | |/ ___ \  /  \
|____/|___|_| \_\_____\____| |_/_/   \_\/_/\_\
 Wi-Fi Direct (P2P) offensive research toolkit
 v0.1.0   authorized lab use only

INFO  wfdx.interface   swapped wlx00c0caba4c85 to monitor mode in place
INFO  wfdx.discovery   discovered 10:5a:95:46:2f:b2 (?) role=GO ch=11
INFO  wfdx.discovery   discovered 7e:b0:de:49:02:e2 (?) role=GO ch=6
INFO  wfdx.discovery   discovered 16:32:51:cd:c6:cc (?) role=GO ch=1

discovered 3 P2P devices

DEVICE             ROLE  SSID/NAME  CH  dBm   SIG   WPS  PBC  PIN  LOCK  PERS  MFR      TYPE / MODEL
-----------------  ----  ---------  --  ----  ----  ---  ---  ---  ----  ----  -------  ------------
10:5a:95:46:2f:b2  GO    (hidden)   11   -64  ###.  yes  no   no   yes   no    Samsung
7e:b0:de:49:02:e2  GO    (hidden)    6   -72  ##..  yes  no   no   -     no
16:32:51:cd:c6:cc  GO    (hidden)    1   -85  #...  yes  no   no   -     no
```

Devices are sorted by best RSSI so the strongest target is on top.

## Detail block (per device)

```
=== 10:5a:95:46:2f:b2 ===
  role              : GO
  bssids            : 10:5a:95:46:2f:b2
  ssids seen        : -
  channels seen     : 11
  rssi last / best  : -65 / -64 dBm
  first seen        : 11:29:19
  last seen         : 11:30:17
  frames            : {'beacon': 75, 'probe_req': 0, 'probe_resp': 0}
  vendor (OUI)      : Samsung Electronics
  --- WSC ---
  version           : 16
  manufacturer      : -
  model name        : -
  device name       : -
  primary dev type  : -
  uuid-e            : 123456789abcdef01234105a95462fb2
  config methods    : None []
  device password id: None
  ap setup locked   : True
  selected registrar: None
```

Three real observations from that dump alone:

1. **UUID-E is derived from the BSSID.** The last 12 hex chars of
   `123456789abcdef01234105a95462fb2` are `105a95462fb2` = the BSSID
   with colons stripped. Broadcom / hostapd reference builds sometimes
   generate UUID-E as a deterministic function of the BSSID, meaning
   any observer who has seen one beacon can predict future UUID-Es
   from the same vendor.
2. **AP Setup Locked = True.** WPS registrar is refusing new
   enrollees. `wps-pin` (reaver PIN brute) will fail immediately.
   `pixie` / `pixie-pcap` still works because it only needs one M1/M3
   exchange, not a completed registration.
3. **Only beacons observed, no probe responses.** The GO is beaconing
   but not answering probes, so the WSC IE in beacons is stripped
   (only version + UUID-E + AP Setup Locked survive). To pull the
   full manufacturer / model / device name, use `--active`.

## Active discovery (elicits richer WSC via Probe Request injection)

```
$ sudo python3 scan.py discover --duration 30 --active --authorized --detail
```

`--active` fires a P2P Search Probe Request (SSID = `DIRECT-`, plus
P2P and WSC IE) every second while the passive sniffer runs. GOs
that stayed silent under passive discovery answer these directly.

Expected additional fields in the detail block for a responsive GO:

```
  manufacturer      : Samsung Electronics
  model name        : SM-G998B
  device name       : Galaxy S21 Ultra
  primary dev type  : Smartphone / Dual Mode
  config methods    : 0x0188 [Display, PushButton, Keypad]
  device password id: 4        # PushButton
  selected registrar: True
```

## Interactive adapter picker

```
$ sudo python3 scan.py discover --pick-adapter --duration 30

Wireless adapters:
  1. wlp148s0               iwlwifi      LIMITED  Intel AX2xx / AC9xxx
  2. wlx00c0caba4c85        mt7921u      READY    MediaTek MT7921AU (Alfa AWUS036AXML / AXM / AX)

select adapter [1-2]: 2
[directax] picked adapter: wlx00c0caba4c85
```

## Verified

- Adapter used: Alfa AWUS036AXML, USB id `0e8d:7961`, driver `mt7921u`
- Monitor mode via strategy 3 (`iw dev … set type monitor`), because
  `mt7921u` refuses concurrent managed + monitor VIFs without
  active-monitor firmware support
- 3 P2P Group Owners captured on channels 1, 6, 11 in a residential
  RF environment during a 60 s passive window
- End-to-end run: preflight, adapter probe, monitor setup, channel
  hop, P2P IE parse, WSC IE parse, RSSI capture, OUI lookup, table
  render, per-device detail dump, monitor teardown, iface restored to
  managed mode
