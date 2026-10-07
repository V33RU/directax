"""Tests for Miracast RTSP probe + CVE-2023-38147 using a local
loopback RTSP sink stub. Zero RF."""
import re
import socket
import threading
import time

from wifidirect_pentest.attacks.cve_2023_38147 import build_trigger, _options_probe
from wifidirect_pentest.attacks.miracast_probe import MiracastProbe
from wifidirect_pentest.attacks.miracast_uibc import (
    _frame_key_event, ASCII_TO_HID, MOD_LEFT_SHIFT, SHIFTED,
)


class _StubSink(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.received: list[bytes] = []
        self._stop = False

    def run(self):
        while not self._stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            c.settimeout(2.0)
            try:
                leftover = b""
                while True:
                    buf = leftover
                    while b"\r\n\r\n" not in buf:
                        try:
                            chunk = c.recv(4096)
                        except socket.timeout:
                            return
                        if not chunk:
                            return
                        buf += chunk
                    # Read Content-Length body if present
                    head, _, rest = buf.partition(b"\r\n\r\n")
                    m = re.search(rb"(?i)content-length:\s*(\d+)", head)
                    need = int(m.group(1)) if m else 0
                    while len(rest) < need:
                        try:
                            chunk = c.recv(4096)
                        except socket.timeout:
                            return
                        if not chunk:
                            return
                        rest += chunk
                    body_in = rest[:need]
                    leftover = rest[need:]
                    full = head + b"\r\n\r\n" + body_in
                    self.received.append(full)

                    cseq_m = re.search(rb"(?i)cseq:\s*(\d+)", head)
                    cseq = cseq_m.group(1).decode() if cseq_m else "1"
                    if full.startswith(b"OPTIONS"):
                        resp = (
                            f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                            f"Public: org.wfa.wfd1.0, SET_PARAMETER, GET_PARAMETER\r\n"
                            f"Server: StubSink/0.1\r\n\r\n"
                        )
                    elif full.startswith(b"GET_PARAMETER"):
                        body = ("wfd_video_formats: 00 00 02 02 00000040 none none\r\n"
                                "wfd_audio_codecs: LPCM 00000002 00\r\n"
                                "wfd_client_rtp_ports: RTP/AVP/UDP;unicast 1028 0 mode=play\r\n"
                                "wfd_uibc_capability: input_category_list=HIDC;generic_cap_list=none\r\n"
                                "wfd_content_protection: HDCP2.2 port=7250\r\n")
                        resp = (
                            f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                            f"Content-Type: text/parameters\r\n"
                            f"Content-Length: {len(body)}\r\n\r\n{body}"
                        )
                    else:
                        resp = f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n\r\n"
                    c.sendall(resp.encode())
            except Exception:
                pass
            finally:
                c.close()

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def test_miracast_probe_parses_options_and_params():
    sink = _StubSink()
    sink.start()
    try:
        probe = MiracastProbe("127.0.0.1", port=sink.port, timeout=3.0)
        r = probe.run()
    finally:
        sink.stop()
    assert r.reachable is True
    assert "SET_PARAMETER" in r.sink_options
    assert "GET_PARAMETER" in r.sink_options
    assert r.sink_user_agent == "StubSink/0.1"
    assert "wfd_video_formats" in r.wfd_params
    assert "HDCP2.2" in r.wfd_params["wfd_content_protection"]


def test_options_probe_live_vs_dead():
    sink = _StubSink()
    sink.start()
    try:
        assert _options_probe("127.0.0.1", sink.port, timeout=2.0) is True
    finally:
        sink.stop()
    time.sleep(0.1)
    assert _options_probe("127.0.0.1", 1, timeout=0.5) is False  # closed port


def test_cve_2023_38147_trigger_shape():
    pkt = build_trigger(cseq=5, field_count=500)
    assert pkt.startswith(b"SET_PARAMETER ")
    assert b"CSeq: 5\r\n" in pkt
    assert pkt.count(b"00000040") >= 500
    assert b"wfd_video_formats:" in pkt


def test_uibc_key_frame_layout():
    down = _frame_key_event(True, 0x04, 0)      # 'a' down, no modifiers
    assert len(down) == 7
    # length prefix is BE and equals total frame length
    import struct
    length = struct.unpack(">H", down[:2])[0]
    assert length == len(down)
    assert down[2] == 0x00  # Generic category
    assert down[3] == 0x00  # KeyDown subtype
    # HID usage 'a' = 0x04 packed big-endian
    assert down[4:6] == b"\x00\x04"
    assert down[6] == 0


def test_uibc_shifted_mapping_covers_uppercase():
    for ch in "ABCDEFXYZ":
        assert ch in SHIFTED
        base = SHIFTED[ch]
        assert base in ASCII_TO_HID
