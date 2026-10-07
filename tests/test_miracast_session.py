"""Tests for the Miracast session driver, HDCP test, rogue source,
UIBC pointer frames, and wfd_* fuzzer, against a local RTSP stub sink."""
import re
import socket
import struct
import threading
import time

from wifidirect_pentest.attacks.miracast_session import MiracastSession
from wifidirect_pentest.attacks.miracast_hdcp import MiracastHdcpTest
from wifidirect_pentest.attacks.miracast_rogue_source import (
    _buildRtpPacket, RTP_PAYLOAD_MP2T,
)
from wifidirect_pentest.attacks.miracast_uibc import (
    _framePointerEvent, _frameScroll, GEN_MOUSE_DOWN, GEN_TOUCH_DOWN,
    GEN_VERTICAL_SCROLL,
)
from wifidirect_pentest.fuzzers.miracast_wfd_params import WfdParamFuzzer


class _FullStubSink(threading.Thread):
    """RTSP sink that answers M1-M7 so the session driver can reach PLAY.
    enforce_hdcp=True makes it reject SET_PARAMETER when content
    protection is 'none' (to test the downgrade logic)."""

    def __init__(self, enforce_hdcp: bool = False):
        super().__init__(daemon=True)
        self.enforce_hdcp = enforce_hdcp
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self._stop = False

    def run(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,),
                             daemon=True).start()

    def _serve(self, conn):
        conn.settimeout(2.0)
        leftover = b""
        try:
            while True:
                buf = leftover
                while b"\r\n\r\n" not in buf:
                    try:
                        chunk = conn.recv(4096)
                    except socket.timeout:
                        return
                    if not chunk:
                        return
                    buf += chunk
                head, _, rest = buf.partition(b"\r\n\r\n")
                need_m = re.search(rb"(?i)content-length:\s*(\d+)", head)
                need = int(need_m.group(1)) if need_m else 0
                while len(rest) < need:
                    try:
                        chunk = conn.recv(4096)
                    except socket.timeout:
                        return
                    if not chunk:
                        return
                    rest += chunk
                body = rest[:need]
                leftover = rest[need:]
                full = head + b"\r\n\r\n" + body
                conn.sendall(self._reply(full))
        except Exception:
            pass
        finally:
            conn.close()

    def _reply(self, full: bytes) -> bytes:
        cseq_m = re.search(rb"(?i)cseq:\s*(\d+)", full)
        cseq = cseq_m.group(1).decode() if cseq_m else "1"

        def ok(extra="", body=""):
            base = f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
            if body:
                base += (f"Content-Type: text/parameters\r\n"
                         f"Content-Length: {len(body)}\r\n")
            base += extra + "\r\n" + body
            return base.encode()

        if full.startswith(b"OPTIONS"):
            return ok("Public: org.wfa.wfd1.0, SET_PARAMETER, "
                      "GET_PARAMETER, SETUP, PLAY, TEARDOWN\r\n"
                      "Server: FullStub/0.1\r\n")
        if full.startswith(b"GET_PARAMETER"):
            cp = "HDCP2.2 port=7250" if self.enforce_hdcp else "none"
            body = (f"wfd_video_formats: 00 00 02 02 00000040 none none\r\n"
                    f"wfd_audio_codecs: LPCM 00000002 00\r\n"
                    f"wfd_content_protection: {cp}\r\n"
                    f"wfd_uibc_capability: input_category_list=HIDC\r\n")
            return ok(body=body)
        if full.startswith(b"SET_PARAMETER"):
            if self.enforce_hdcp and b"wfd_content_protection: none" in full:
                return (f"RTSP/1.0 406 Not Acceptable\r\n"
                        f"CSeq: {cseq}\r\n\r\n").encode()
            return ok()
        if full.startswith(b"SETUP"):
            return ok("Session: 1804289383;timeout=30\r\n"
                      "Transport: RTP/AVP/UDP;unicast;"
                      "client_port=1028;server_port=5000\r\n")
        if full.startswith(b"PLAY") or full.startswith(b"TEARDOWN"):
            return ok()
        return ok()

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def test_session_reaches_play():
    sink = _FullStubSink()
    sink.start()
    try:
        session = MiracastSession("127.0.0.1", port=sink.port, timeout=3.0)
        result = session.run(stopAt="play")
    finally:
        sink.stop()
    assert result["reachable"] is True
    assert result["reached_state"] == "play"
    assert result["session_id"] == "1804289383"
    assert result["rtp_port"] == 5000


def test_session_stop_at_m3_collects_params():
    sink = _FullStubSink()
    sink.start()
    try:
        session = MiracastSession("127.0.0.1", port=sink.port, timeout=3.0)
        result = session.run(stopAt="m3")
    finally:
        sink.stop()
    assert result["reached_state"] == "m3"
    assert "wfd_video_formats" in result["wfd_params"]


def test_hdcp_downgrade_detects_clear_stream():
    sink = _FullStubSink(enforce_hdcp=False)
    sink.start()
    try:
        test = MiracastHdcpTest("127.0.0.1", port=sink.port, timeout=3.0)
        result = test.run()
    finally:
        sink.stop()
    assert result["streams_without_protection"] is True
    assert result["confirmed"] is True


def test_hdcp_enforced_sink_refuses_downgrade():
    sink = _FullStubSink(enforce_hdcp=True)
    sink.start()
    try:
        test = MiracastHdcpTest("127.0.0.1", port=sink.port, timeout=3.0)
        result = test.run()
    finally:
        sink.stop()
    assert result["hdcp_advertised"] is True
    assert result["streams_without_protection"] is False
    assert result["confirmed"] is False


def test_rtp_packet_header_shape():
    pkt = _buildRtpPacket(5, 90000, 0x0A0B0C0D, b"\x47" + b"\x00" * 187)
    version = (pkt[0] >> 6) & 0x03
    assert version == 2
    assert (pkt[1] & 0x7F) == RTP_PAYLOAD_MP2T
    seq = struct.unpack(">H", pkt[2:4])[0]
    assert seq == 5


def test_uibc_pointer_frame_layout():
    frame = _framePointerEvent(GEN_MOUSE_DOWN, [(0, 100, 200)])
    length = struct.unpack(">H", frame[:2])[0]
    assert length == len(frame)
    assert frame[2] == 0x00       # generic category
    assert frame[3] == GEN_MOUSE_DOWN
    assert frame[4] == 1          # one pointer
    assert frame[5] == 0          # pointer id
    assert struct.unpack(">HH", frame[6:10]) == (100, 200)


def test_uibc_touch_and_scroll_frames():
    touch = _framePointerEvent(GEN_TOUCH_DOWN, [(0, 10, 20)])
    assert touch[3] == GEN_TOUCH_DOWN
    scroll = _frameScroll(GEN_VERTICAL_SCROLL, -3)
    amount = struct.unpack(">h", scroll[4:6])[0]
    assert amount == -3


def test_wfd_fuzzer_case_generation_deterministic():
    fuzzer = WfdParamFuzzer("127.0.0.1", port=1)
    a = fuzzer.buildCases(seed=7)
    b = fuzzer.buildCases(seed=7)
    assert [c.label for c in a] == [c.label for c in b]
    labels = {c.label for c in a}
    assert "edid-corrupt-ext" in labels
    assert "rtp-port-65536" in labels
    assert any(c.parameter == "wfd_video_formats" for c in a)
