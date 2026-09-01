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
  select-adapter Print export line for DIRECTAX_IFACE (auto-picks if only one READY)
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


def _auto_ready_iface() -> str | None:
    """Return the sole READY wireless interface, or None if 0 or >1."""
    ready: list[str] = []
    for name in _list_wireless_ifaces():
        try:
            caps = probe_driver(name)
        except Exception:
            continue
        prof = profile_for(caps.driver)
        ok, _ = readiness(prof)
        if ok:
            ready.append(name)
    return ready[0] if len(ready) == 1 else None


def _resolve_iface() -> str | None:
    """Priority: DIRECTAX_IFACE env, else the unique READY adapter."""
    env = os.environ.get("DIRECTAX_IFACE")
    if env:
        return env
    return _auto_ready_iface()


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


def _print_table(rows: list[list[str]], headers: list[str]) -> None:
    if not rows:
        return
    widths = [max(len(str(r[i])) for r in [headers] + rows)
              for i in range(len(headers))]
    def fmt(row: list) -> str:
        return "  ".join(str(cell).ljust(w) for cell, w in zip(row, widths))
    print(fmt(headers))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print(fmt(r))


def _yn(v) -> str:
    if v is True:
        return "yes"
    if v is False:
        return "no"
    return "-"


def _rssi_bar(rssi: int | None) -> str:
    """Signal strength bar. dBm typical range: -30 (excellent) to -90 (dead)."""
    if rssi is None:
        return "----"
    if rssi >= -50:
        return "####"
    if rssi >= -65:
        return "###."
    if rssi >= -75:
        return "##.."
    if rssi >= -85:
        return "#..."
    return "...."


def _print_device_detail(mac: str, d, wps) -> None:
    from wifidirect_pentest.core.device_type import decode as decode_pdt
    from wifidirect_pentest.core.oui import lookup as oui_lookup
    print(f"\n=== {mac} ===")
    print(f"  role              : {d.role}")
    print(f"  bssids            : {', '.join(sorted(d.bssids)) or '-'}")
    print(f"  interface addrs   : {', '.join(sorted(d.interface_addrs)) or '-'}")
    print(f"  ssids seen        : {', '.join(sorted(d.ssids)) or '-'}")
    print(f"  channels seen     : {', '.join(str(c) for c in sorted(d.channels_seen))}")
    print(f"  rssi last / best  : {d.rssi_last} / {d.rssi_best} dBm")
    print(f"  first seen        : {time.strftime('%H:%M:%S', time.localtime(d.first_seen))}")
    print(f"  last seen         : {time.strftime('%H:%M:%S', time.localtime(d.last_seen))}")
    print(f"  frames            : {d.frame_counts}")
    print(f"  vendor (OUI)      : {oui_lookup(mac) or 'unknown'}")
    if wps.wps_present:
        print(f"  --- WSC ---")
        print(f"  version           : {wps.version}")
        print(f"  manufacturer      : {wps.manufacturer or '-'}")
        print(f"  model name        : {wps.model_name or '-'}")
        print(f"  model number      : {getattr(wps, 'model_number', None) or '-'}")
        print(f"  device name       : {wps.device_name or '-'}")
        print(f"  primary dev type  : {decode_pdt(wps.primary_device_type) or '-'}")
        print(f"  uuid-e            : {wps.uuid_e or '-'}")
        print(f"  config methods    : {wps.config_methods_hex} "
              f"[{', '.join(wps.config_methods_labels)}]")
        print(f"  device password id: {wps.device_password_id}")
        print(f"  ap setup locked   : {wps.ap_setup_locked}")
        print(f"  selected registrar: {wps.selected_registrar}")
    if d.p2p:
        print(f"  --- P2P ---")
        print(f"  capability        : {d.p2p.capability}")
        print(f"  persistent group  : {d.p2p.persistent_group}")
        print(f"  manageability     : {d.p2p.manageability}")
        print(f"  group bssid       : {d.p2p.group_bssid or '-'}")
        print(f"  group id ssid     : {d.p2p.group_id_ssid or '-'}")
        print(f"  operating channel : {d.p2p.operating_channel or '-'}")
        print(f"  listen channel    : {d.p2p.listen_channel or '-'}")
        print(f"  channel list      : {d.p2p.channel_list or '-'}")


def cmd_discover(args) -> int:
    from wifidirect_pentest.core.device_type import decode as decode_pdt
    from wifidirect_pentest.core.oui import lookup as oui_lookup
    from wifidirect_pentest.scanners.p2p_search import P2PSearchProber
    _require_root()
    if args.active and not args.authorized:
        raise SystemExit(
            "--active requires --authorized. Probe Requests are "
            "harmless but count as injection under the DIRECTAX policy.")
    ifc, mon = _open_monitor(args.iface)
    try:
        disc = Discovery(mon, dwell_ms=args.dwell)
        if args.active:
            prober = P2PSearchProber(mon)
            # Interleave: kick off a background prober thread that fires
            # broadcast + directed Probe Requests every second while the
            # passive sniffer runs.
            import threading
            stop = threading.Event()
            known: set[str] = set()

            def _prober_loop():
                while not stop.is_set():
                    prober.probe_broadcast()
                    for b in list(known):
                        prober.probe_directed(b)
                    time.sleep(1.0)

            def _feed_known(dev):
                for b in dev.bssids:
                    known.add(b)

            disc.on_new = _feed_known
            t = threading.Thread(target=_prober_loop, daemon=True)
            t.start()
            try:
                devices = disc.run(duration=args.duration)
            finally:
                stop.set()
                t.join(timeout=2.0)
        else:
            devices = disc.run(duration=args.duration)
    finally:
        ifc.restore()
    result = {"devices": {mac: d.as_dict() for mac, d in devices.items()}}
    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2, default=str)
    print(f"\ndiscovered {len(devices)} P2P devices\n")
    if not devices:
        return 0

    rows: list[list[str]] = []
    # Rank by best RSSI descending so the strongest signal is first
    ordered = sorted(devices.items(),
                     key=lambda kv: kv[1].rssi_best or -999, reverse=True)
    for mac, d in ordered:
        wps = inspect_wps(d)
        ssid = (next(iter(d.ssids), "")
                or wps.device_name
                or (d.p2p.group_id_ssid if d.p2p else None)
                or "(hidden)")
        ch = ",".join(str(c) for c in sorted(d.channels_seen)) or "-"
        persistent = bool(getattr(d.p2p, "persistent_group", False)) if d.p2p else False
        pdt = decode_pdt(wps.primary_device_type)
        mfr = wps.manufacturer or oui_lookup(mac) or ""
        rows.append([
            mac, d.role,
            ssid[:24], ch,
            f"{d.rssi_best:>4}" if d.rssi_best is not None else "  --",
            _rssi_bar(d.rssi_best),
            _yn(wps.wps_present),
            _yn(wps.pbc_supported),
            _yn(wps.pin_supported),
            _yn(wps.ap_setup_locked),
            _yn(persistent),
            mfr[:14],
            (pdt or wps.model_name or "")[:20],
        ])
    _print_table(rows, ["DEVICE", "ROLE", "SSID/NAME", "CH",
                        "dBm", "SIG",
                        "WPS", "PBC", "PIN", "LOCK", "PERS",
                        "MFR", "TYPE / MODEL"])

    if args.detail:
        for mac, d in ordered:
            _print_device_detail(mac, d, inspect_wps(d))
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


def cmd_select_adapter(args) -> int:
    iface = args.iface or _resolve_iface()
    if not iface:
        wireless = _list_wireless_ifaces()
        print("no adapter selected. wireless interfaces detected: "
              + (", ".join(wireless) if wireless else "none"),
              file=sys.stderr)
        return 1
    try:
        caps = probe_driver(iface)
        prof = profile_for(caps.driver)
    except Exception as e:
        print(f"probe failed on {iface}: {e}", file=sys.stderr)
        return 1
    print(f"# selected {iface} ({caps.driver}, {prof.display_name})",
          file=sys.stderr)
    print(f"export DIRECTAX_IFACE={iface}")
    return 0


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
    c.add_argument("--pick-adapter", action="store_true",
                   help="show a numbered menu of wireless adapters and prompt")
    return c


def _pick_adapter_interactive() -> str | None:
    """Print every wireless iface with its DIRECTAX profile status and prompt."""
    ifaces = _list_wireless_ifaces()
    if not ifaces:
        print("no wireless interfaces detected", file=sys.stderr)
        return None
    rows: list[tuple[str, str, str, str]] = []
    for name in ifaces:
        try:
            caps = probe_driver(name)
        except Exception as e:
            rows.append((name, "?", "PROBE-FAIL", str(e)))
            continue
        prof = profile_for(caps.driver)
        ok, _ = readiness(prof)
        rows.append((name, caps.driver or "?",
                     "READY" if ok else "LIMITED",
                     prof.display_name))
    print("\nWireless adapters:", file=sys.stderr)
    for i, (name, drv, status, disp) in enumerate(rows, 1):
        print(f"  {i}. {name:22} {drv:12} {status:8} {disp}", file=sys.stderr)
    print("", file=sys.stderr)
    try:
        raw = input(f"select adapter [1-{len(rows)}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("cancelled", file=sys.stderr)
        return None
    try:
        idx = int(raw)
    except ValueError:
        # allow selection by exact iface name too
        for name, *_ in rows:
            if name == raw:
                return name
        print(f"invalid selection: {raw!r}", file=sys.stderr)
        return None
    if not 1 <= idx <= len(rows):
        print(f"out of range: {idx}", file=sys.stderr)
        return None
    return rows[idx - 1][0]


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
    d.add_argument("--detail", action="store_true",
                   help="after the table, print every parsed field per device")
    d.add_argument("--active", action="store_true",
                   help="also send P2P Search Probe Requests to elicit "
                        "richer Probe Responses (requires --authorized)")
    d.add_argument("--authorized", action="store_true",
                   help="acknowledge you have permission to send frames")
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

    sa = _add("select-adapter")
    sa.add_argument("iface", nargs="?",
                    help="iface name; omit to auto-pick the sole READY adapter")
    sa.set_defaults(func=cmd_select_adapter)

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
    # Subcommands that accept -i / --iface. Auto-fill only fires when
    # one of these appears in argv and the user did not pass -i.
    _IFACE_SUBCMDS = {
        "discover", "sniff", "deauth", "beacon-flood", "pd-flood",
        "pbc-race", "wps-pin", "pixie", "handshake", "rogue-go", "audit",
        "invitation", "noa-starve", "goneg-hijack", "pmkid", "cross-conn",
        "driver-probe", "karma", "nan-scan", "p2p-fuzz",
    }
    wants_pick = ("--pick-adapter" in sys.argv)
    asking_help = any(a in ("-h", "--help") for a in sys.argv)
    if (any(a in _IFACE_SUBCMDS for a in sys.argv)
            and not asking_help
            and not any(a in ("-i", "--iface") for a in sys.argv)):
        if wants_pick:
            resolved = _pick_adapter_interactive()
            if not resolved:
                return 2
            sys.argv.extend(["-i", resolved])
            print(f"[directax] picked adapter: {resolved}", file=sys.stderr)
        else:
            resolved = _resolve_iface()
            if resolved:
                sys.argv.extend(["-i", resolved])
                try:
                    caps = probe_driver(resolved)
                    prof = profile_for(caps.driver)
                    src = ("DIRECTAX_IFACE env" if os.environ.get("DIRECTAX_IFACE")
                           else "sole READY adapter")
                    print(f"[directax] auto-selected {resolved} "
                          f"({prof.display_name}, {caps.driver or '?'}) "
                          f"[{src}]", file=sys.stderr)
                    print(f"[directax] override: -i <iface>  |  "
                          f"pick menu: --pick-adapter", file=sys.stderr)
                except Exception:
                    print(f"[directax] auto-selected {resolved}",
                          file=sys.stderr)
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
