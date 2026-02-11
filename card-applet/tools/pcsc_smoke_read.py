#!/usr/bin/env python3
"""PC/SC smoke-test for the educational eMRTD applet.

Checks:
1) SELECT by AID -> 9000
2) SELECT EF.COM (FID 011E) and EF.DG1 (FID 0101) -> 9000
3) READ BINARY at a few offsets and verify bytes against demo sample files.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
from dataclasses import dataclass

DEFAULT_AID = bytes.fromhex("D276000124010001")
EF_COM_FID = bytes.fromhex("011E")
EF_DG1_FID = bytes.fromhex("0101")


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str


def parse_connection_string(value: str) -> dict[str, str | int]:
    """Parse a simple pcsc:// connection selector.

    Supported forms:
      - pcsc://index/0
      - pcsc://filter/Identive
      - pcsc://<exact reader name>
    """

    if not value.startswith("pcsc://"):
        raise ValueError("connection string must start with pcsc://")
    payload = value[len("pcsc://") :]
    if payload.startswith("index/"):
        return {"reader_index": int(payload[len("index/") :])}
    if payload.startswith("filter/"):
        return {"reader_filter": payload[len("filter/") :]}
    if not payload:
        raise ValueError("empty pcsc:// selector")
    return {"reader": payload}


def choose_reader(all_readers, args) -> str:
    names = [str(r) for r in all_readers]
    if not names:
        raise RuntimeError("No PC/SC readers found")

    if args.reader:
        for name in names:
            if name == args.reader:
                return name
        raise RuntimeError(f"Reader not found: {args.reader!r}")

    if args.reader_filters:
        filtered = [name for name in names if all(tok.lower() in name.lower() for tok in args.reader_filters)]
        if not filtered:
            raise RuntimeError(
                f"No readers matched filters={args.reader_filters!r}. Available readers: {names}"
            )
        return filtered[0]

    if args.reader_index is not None:
        if args.reader_index < 0 or args.reader_index >= len(names):
            raise RuntimeError(f"reader-index {args.reader_index} out of range (0..{len(names)-1})")
        return names[args.reader_index]

    return names[0]


def transmit(conn, apdu: list[int], label: str, expect_sw: tuple[int, int] = (0x90, 0x00)) -> tuple[CheckResult, list[int]]:
    data, sw1, sw2 = conn.transmit(apdu)
    sw_text = f"{sw1:02X}{sw2:02X}"
    ok = (sw1, sw2) == expect_sw
    detail = f"SW={sw_text}"
    if data:
        detail += f", data={bytes(data).hex().upper()}"
    print(f"[{label}] {detail}")
    return CheckResult(label, ok, detail), data


def load_bytes(path: pathlib.Path) -> bytes:
    if not path.exists():
        raise FileNotFoundError(f"Sample file not found: {path}")
    return path.read_bytes()


def check_read_slice(conn, ef_label: str, offset: int, length: int, expected: bytes) -> CheckResult:
    p1 = (offset >> 8) & 0x7F
    p2 = offset & 0xFF
    apdu = [0x00, 0xB0, p1, p2, length]
    result, data = transmit(conn, apdu, f"READ BINARY {ef_label} off={offset} len={length}")
    if not result.ok:
        return result
    got = bytes(data)
    if got != expected:
        return CheckResult(
            result.name,
            False,
            f"SW ok but data mismatch: expected={expected.hex().upper()} got={got.hex().upper()}",
        )
    return CheckResult(result.name, True, f"SW=9000 and data matched ({len(got)} bytes)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Minimal PC/SC script to validate SELECT + READ BINARY against demo sample files.",
        epilog=(
            "Connection string examples:\n"
            "  --connection-string 'pcsc://index/0'\n"
            "  --connection-string 'pcsc://filter/ACS'\n"
            "  --connection-string 'pcsc://Identive CLOUD 3700 F Contact Reader 00 00'\n"
            "\nEquivalent selector flags:\n"
            "  --reader-index 0\n"
            "  --reader-filter ACS --reader-filter Contact\n"
            "  --reader 'Exact Reader Name'"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--aid", default=DEFAULT_AID.hex().upper(), help="Applet AID as hex (default: %(default)s)")
    parser.add_argument("--reader", help="Exact PC/SC reader name")
    parser.add_argument("--reader-filter", action="append", dest="reader_filters", help="Case-insensitive substring filter (repeatable)")
    parser.add_argument("--reader-index", type=int, help="Select reader by index from detected reader list")
    parser.add_argument("--connection-string", help="Optional reader selector using pcsc://... notation")
    parser.add_argument(
        "--sample-dir",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[1] / "sample-data",
        help="Directory containing EF.COM.bin and EF.DG1.bin (default: %(default)s)",
    )
    return parser.parse_args()




def import_pcsc():
    try:
        from smartcard.System import readers
        from smartcard.Exceptions import CardConnectionException, NoReadersException
    except Exception as exc:
        print("ERROR: pyscard is required (pip install pyscard)")
        print(f"Import error: {exc}")
        raise SystemExit(2)
    return readers, CardConnectionException, NoReadersException

def main() -> int:
    args = parse_args()

    if args.connection_string:
        parsed = parse_connection_string(args.connection_string)
        if "reader" in parsed:
            args.reader = parsed["reader"]
        if "reader_filter" in parsed:
            args.reader_filters = [parsed["reader_filter"]]
        if "reader_index" in parsed:
            args.reader_index = parsed["reader_index"]

    try:
        aid = bytes.fromhex(args.aid)
    except ValueError:
        print(f"ERROR: invalid --aid hex: {args.aid!r}")
        return 2

    ef_com = load_bytes(args.sample_dir / "EF.COM.bin")
    ef_dg1 = load_bytes(args.sample_dir / "EF.DG1.bin")

    readers, CardConnectionException, NoReadersException = import_pcsc()

    try:
        r = readers()
    except NoReadersException:
        print("ERROR: PC/SC subsystem reported no readers")
        return 2

    print("Detected readers:")
    for idx, name in enumerate([str(x) for x in r]):
        print(f"  [{idx}] {name}")

    try:
        selected = choose_reader(r, args)
    except RuntimeError as exc:
        print(f"ERROR: {exc}")
        return 2

    print(f"Using reader: {selected}")
    conn = None
    for item in r:
        if str(item) == selected:
            conn = item.createConnection()
            break
    assert conn is not None

    results: list[CheckResult] = []
    try:
        conn.connect()

        res, _ = transmit(conn, [0x00, 0xA4, 0x04, 0x0C, len(aid), *aid], "SELECT AID")
        results.append(res)

        res, _ = transmit(conn, [0x00, 0xA4, 0x02, 0x0C, 0x02, EF_COM_FID[0], EF_COM_FID[1]], "SELECT EF.COM")
        results.append(res)

        # EF.COM: verify two slices to exercise offset behavior.
        results.append(check_read_slice(conn, "EF.COM", 0, 8, ef_com[0:8]))
        results.append(check_read_slice(conn, "EF.COM", 8, min(8, len(ef_com) - 8), ef_com[8:16]))

        res, _ = transmit(conn, [0x00, 0xA4, 0x02, 0x0C, 0x02, EF_DG1_FID[0], EF_DG1_FID[1]], "SELECT EF.DG1")
        results.append(res)

        # EF.DG1: verify multiple slices.
        results.append(check_read_slice(conn, "EF.DG1", 0, 10, ef_dg1[0:10]))
        results.append(check_read_slice(conn, "EF.DG1", 10, 10, ef_dg1[10:20]))
        tail_off = max(0, len(ef_dg1) - 6)
        results.append(check_read_slice(conn, "EF.DG1", tail_off, len(ef_dg1) - tail_off, ef_dg1[tail_off:]))

    except CardConnectionException as exc:
        print(f"ERROR: card communication failed: {exc}")
        return 2

    passed = sum(1 for r in results if r.ok)
    failed = len(results) - passed

    print("\nSummary:")
    for r in results:
        icon = "PASS" if r.ok else "FAIL"
        print(f"  {icon:<4} {r.name}: {r.detail}")
    print(f"Result: {passed}/{len(results)} checks passed, {failed} failed")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
