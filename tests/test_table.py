import io
import sys

sys.path.insert(0, "src")

# Re-import scan.py contents as a module for the helpers
import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("directax_scan",
                                              os.path.join(ROOT, "scan.py"))
scan = importlib.util.module_from_spec(spec)
# Skip executing __main__ block by clearing argv
sys.argv = ["scan.py"]
spec.loader.exec_module(scan)


def test_yn_maps_tri_state():
    assert scan._yn(True) == "yes"
    assert scan._yn(False) == "no"
    assert scan._yn(None) == "-"


def test_print_table_aligns_columns(capsys):
    rows = [
        ["aa:bb:cc:dd:ee:01", "GO", "Long-SSID-Name", "6", "yes"],
        ["aa:bb:cc:dd:ee:02", "GO", "X", "11", "no"],
    ]
    scan._print_table(rows, ["DEVICE", "ROLE", "SSID", "CH", "WPS"])
    out = capsys.readouterr().out.splitlines()
    # Header line, separator, then rows
    assert out[0].startswith("DEVICE")
    assert "-" in out[1]
    assert out[2].startswith("aa:bb:cc:dd:ee:01")
    # Column boundaries should align to the widest cell in each column
    header_pos = out[0].index("SSID")
    row_pos = out[2].index("Long-SSID-Name")
    assert header_pos == row_pos


def test_print_table_empty_rows_prints_nothing(capsys):
    scan._print_table([], ["a", "b"])
    assert capsys.readouterr().out == ""
