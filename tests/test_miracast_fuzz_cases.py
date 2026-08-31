from wifidirect_pentest.fuzzers.miracast_rtsp import MiracastFuzzer


def test_case_generation_is_deterministic():
    f = MiracastFuzzer("127.0.0.1")
    a = f.cases(n=32, seed=42)
    b = f.cases(n=32, seed=42)
    assert len(a) == len(b) == 32
    assert [c.label for c in a] == [c.label for c in b]
    assert [c.payload for c in a] == [c.payload for c in b]


def test_cases_include_known_shapes():
    f = MiracastFuzzer("127.0.0.1")
    labels = {c.label for c in f.cases(n=32, seed=1)}
    assert "baseline" in labels
    assert "negative-clen" in labels
    assert "huge-clen" in labels
    assert "bare-lf-header" in labels
    assert "method-null" in labels


def test_baseline_is_valid_rtsp():
    f = MiracastFuzzer("127.0.0.1")
    baseline = next(c for c in f.cases(n=8, seed=0) if c.label == "baseline")
    assert baseline.payload.startswith(b"SET_PARAMETER")
    assert b"CSeq: 3" in baseline.payload
    assert b"wfd_video_formats" in baseline.payload
