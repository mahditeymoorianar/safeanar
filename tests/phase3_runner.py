import argparse
import hashlib
import json
import os
import secrets
import struct
import subprocess
import sys
import tempfile
import time


ERROR_INVALID_PATH = "InvalidPath"
ERROR_INVALID_ARCHIVE = "InvalidArchive"
ERROR_INVALID_PADDING_TARGET = "InvalidPaddingTarget"
ERROR_CORRUPT_INPUT = "CorruptInput"
ERROR_FILE_IO = "FileIOError"

MAGIC_ARCHIVE = b"SAPK1\x00"
MAGIC_PADDED = b"SPAD1\x00"
PAD_HEADER_SIZE = len(MAGIC_PADDED) + 8


class TestFailure(Exception):
    pass


class AdapterProcess:
    def __init__(self, cmd):
        self.cmd = cmd
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def request(self, payload):
        line = json.dumps(payload, separators=(",", ":"))
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        response_line = self.proc.stdout.readline()
        if not response_line:
            stderr = self.proc.stderr.read()
            raise RuntimeError(f"adapter exited unexpectedly. stderr={stderr}")
        return json.loads(response_line)

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.terminate()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=2)
        except Exception:
            pass


def assert_true(condition, msg):
    if not condition:
        raise TestFailure(msg)


def assert_equal(actual, expected, msg):
    if actual != expected:
        raise TestFailure(f"{msg}. got={actual} expected={expected}")


def ensure_ok(resp):
    assert_true(resp.get("ok") is True, f"expected ok response, got {resp}")


def ensure_err(resp, code):
    assert_true(resp.get("ok") is False, f"expected error {code}, got {resp}")
    assert_equal(resp.get("error"), code, "error mismatch")


def ensure_err_any(resp, codes):
    assert_true(resp.get("ok") is False, f"expected error in {codes}, got {resp}")
    assert_true(resp.get("error") in codes, f"error mismatch. got={resp.get('error')} expected_one_of={codes}")


def request(adapter, op, **kwargs):
    return adapter.request({"op": op, **kwargs})


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def snapshot_dir(root):
    snap = {}
    for base, _, files in os.walk(root):
        files.sort()
        for name in files:
            full = os.path.join(base, name)
            rel = os.path.relpath(full, root).replace("\\", "/")
            snap[rel] = (os.path.getsize(full), sha256_file(full))
    return snap


def build_nested_fixture(root):
    os.makedirs(os.path.join(root, "a", "b"), exist_ok=True)
    os.makedirs(os.path.join(root, "c"), exist_ok=True)
    with open(os.path.join(root, "root.txt"), "wb") as f:
        f.write(b"safeanar-phase3-root\n")
    with open(os.path.join(root, "a", "b", "data.bin"), "wb") as f:
        f.write(secrets.token_bytes(8192))
    with open(os.path.join(root, "c", "empty.txt"), "wb") as f:
        f.write(b"")


def test_ping(adapter, _ctx):
    ensure_ok(request(adapter, "ping"))


def test_pack_unpack_single_file(adapter, _ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "secret.bin")
        archive = os.path.join(td, "archive.sap")
        outdir = os.path.join(td, "out")

        data = secrets.token_bytes(4096)
        with open(src, "wb") as f:
            f.write(data)

        r1 = request(adapter, "pack_path", input_path=src, output_path=archive)
        ensure_ok(r1)
        assert_equal(r1.get("entry_count"), 1, "entry count mismatch")

        r2 = request(adapter, "unpack_path", input_path=archive, output_dir=outdir)
        ensure_ok(r2)

        extracted = os.path.join(outdir, os.path.basename(src))
        assert_true(os.path.exists(extracted), "extracted file missing")
        assert_equal(sha256_file(extracted), sha256_file(src), "single-file hash mismatch")


def test_pack_unpack_nested_dir(adapter, _ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src")
        archive = os.path.join(td, "archive.sap")
        outdir = os.path.join(td, "out")
        os.makedirs(src, exist_ok=True)
        build_nested_fixture(src)

        r1 = request(adapter, "pack_path", input_path=src, output_path=archive)
        ensure_ok(r1)
        r2 = request(adapter, "unpack_path", input_path=archive, output_dir=outdir)
        ensure_ok(r2)

        before = snapshot_dir(src)
        after = snapshot_dir(outdir)
        assert_equal(after, before, "directory snapshot mismatch")


def test_archive_order_stable(adapter, _ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src")
        archive1 = os.path.join(td, "a1.sap")
        archive2 = os.path.join(td, "a2.sap")
        os.makedirs(src, exist_ok=True)
        build_nested_fixture(src)

        ensure_ok(request(adapter, "pack_path", input_path=src, output_path=archive1))
        ensure_ok(request(adapter, "pack_path", input_path=src, output_path=archive2))

        i1 = request(adapter, "inspect_archive", input_path=archive1)
        i2 = request(adapter, "inspect_archive", input_path=archive2)
        ensure_ok(i1)
        ensure_ok(i2)
        p1 = [e["path"] for e in i1.get("entries", [])]
        p2 = [e["path"] for e in i2.get("entries", [])]
        assert_equal(p1, sorted(p1), "archive order should be lexical")
        assert_equal(p1, p2, "archive order should be stable")


def test_pack_missing_input(adapter, _ctx):
    with tempfile.TemporaryDirectory() as td:
        missing = os.path.join(td, "missing")
        archive = os.path.join(td, "archive.sap")
        resp = request(adapter, "pack_path", input_path=missing, output_path=archive)
        ensure_err(resp, ERROR_INVALID_PATH)


def test_unpack_corrupt_archive(adapter, _ctx):
    with tempfile.TemporaryDirectory() as td:
        bad = os.path.join(td, "bad.sap")
        out = os.path.join(td, "out")
        with open(bad, "wb") as f:
            f.write(secrets.token_bytes(128))
        resp = request(adapter, "unpack_path", input_path=bad, output_dir=out)
        ensure_err_any(resp, {ERROR_INVALID_ARCHIVE, ERROR_CORRUPT_INPUT})


def test_unpack_traversal_entry_rejected(adapter, _ctx):
    with tempfile.TemporaryDirectory() as td:
        bad = os.path.join(td, "traversal.sap")
        out = os.path.join(td, "out")

        path = b"../evil.txt"
        payload = b"A"
        with open(bad, "wb") as f:
            f.write(MAGIC_ARCHIVE)
            f.write(struct.pack("<I", 1))
            f.write(struct.pack("<H", len(path)))
            f.write(path)
            f.write(struct.pack("<Q", len(payload)))
            f.write(payload)

        resp = request(adapter, "unpack_path", input_path=bad, output_dir=out)
        ensure_err_any(resp, {ERROR_INVALID_ARCHIVE, ERROR_CORRUPT_INPUT})
        assert_true(not os.path.exists(os.path.join(td, "evil.txt")), "path traversal wrote outside output dir")


def create_random_file(path, size):
    with open(path, "wb") as f:
        remaining = size
        while remaining > 0:
            n = 4096 if remaining > 4096 else remaining
            f.write(secrets.token_bytes(n))
            remaining -= n


def test_padding_accuracy_small(adapter, _ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src.bin")
        padded = os.path.join(td, "padded.bin")
        create_random_file(src, 1024 * 1024)
        target = 10 * 1024 * 1024

        resp = request(adapter, "pad_file", input_path=src, output_path=padded, target_size=target)
        ensure_ok(resp)
        assert_equal(os.path.getsize(padded), target, "padded size mismatch")


def test_unpad_restores_hash(adapter, _ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src.bin")
        padded = os.path.join(td, "padded.bin")
        restored = os.path.join(td, "restored.bin")
        create_random_file(src, 2 * 1024 * 1024)
        target = 12 * 1024 * 1024

        ensure_ok(request(adapter, "pad_file", input_path=src, output_path=padded, target_size=target))
        info = request(adapter, "inspect_padded", input_path=padded)
        ensure_ok(info)
        assert_equal(info.get("real_size"), os.path.getsize(src), "real size mismatch")
        assert_equal(info.get("total_size"), target, "total size mismatch")

        ensure_ok(request(adapter, "unpad_file", input_path=padded, output_path=restored))
        assert_equal(sha256_file(restored), sha256_file(src), "restored hash mismatch")


def test_padding_target_too_small(adapter, _ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src.bin")
        padded = os.path.join(td, "padded.bin")
        create_random_file(src, 1024)
        too_small = 512
        resp = request(adapter, "pad_file", input_path=src, output_path=padded, target_size=too_small)
        ensure_err(resp, ERROR_INVALID_PADDING_TARGET)


def test_padding_zero_length_payload(adapter, _ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "empty.bin")
        padded = os.path.join(td, "padded.bin")
        restored = os.path.join(td, "restored.bin")
        with open(src, "wb") as f:
            f.write(b"")
        ensure_ok(request(adapter, "pad_file", input_path=src, output_path=padded, target_size=4096))
        ensure_ok(request(adapter, "unpad_file", input_path=padded, output_path=restored))
        assert_equal(os.path.getsize(restored), 0, "restored file should be empty")


def test_corrupt_padded_rejected(adapter, _ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src.bin")
        padded = os.path.join(td, "padded.bin")
        broken = os.path.join(td, "broken.bin")
        restored = os.path.join(td, "restored.bin")
        create_random_file(src, 1024)
        ensure_ok(request(adapter, "pad_file", input_path=src, output_path=padded, target_size=8192))

        with open(padded, "rb") as fin:
            data = bytearray(fin.read())
        data[0] ^= 0xFF
        with open(broken, "wb") as fout:
            fout.write(data)

        resp = request(adapter, "unpad_file", input_path=broken, output_path=restored)
        ensure_err_any(resp, {ERROR_INVALID_ARCHIVE, ERROR_CORRUPT_INPUT})


def test_truncated_partial_file_handled(adapter, _ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src.bin")
        padded = os.path.join(td, "padded.bin")
        truncated = os.path.join(td, "truncated.bin")
        restored = os.path.join(td, "restored.bin")
        create_random_file(src, 65536)
        ensure_ok(request(adapter, "pad_file", input_path=src, output_path=padded, target_size=2 * 1024 * 1024))

        with open(padded, "rb") as fin:
            data = fin.read(PAD_HEADER_SIZE + 1024)
        with open(truncated, "wb") as fout:
            fout.write(data)

        resp = request(adapter, "unpad_file", input_path=truncated, output_path=restored)
        ensure_err_any(resp, {ERROR_CORRUPT_INPUT, ERROR_INVALID_ARCHIVE, ERROR_FILE_IO})
        ensure_ok(request(adapter, "ping"))


def test_no_exceptions_on_invalid(adapter, _ctx):
    with tempfile.TemporaryDirectory() as td:
        bad = os.path.join(td, "bad.bin")
        out = os.path.join(td, "out")
        with open(bad, "wb") as f:
            f.write(b"not-an-archive")
        resp = request(adapter, "unpack_path", input_path=bad, output_dir=out)
        ensure_err_any(resp, {ERROR_INVALID_ARCHIVE, ERROR_CORRUPT_INPUT})
        ensure_ok(request(adapter, "ping"))


def test_terminated_padding_process_handling(adapter, ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src.bin")
        partial = os.path.join(td, "partial.bin")
        restored = os.path.join(td, "restored.bin")
        create_random_file(src, 4 * 1024 * 1024)
        target = 200 * 1024 * 1024

        proc = subprocess.Popen(
            ctx["adapter_cmd"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            req = {"op": "pad_file", "input_path": src, "output_path": partial, "target_size": target}
            proc.stdin.write(json.dumps(req, separators=(",", ":")) + "\n")
            proc.stdin.flush()
            time.sleep(0.03)
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass

        if os.path.exists(partial):
            size = os.path.getsize(partial)
            if size < target:
                resp = request(adapter, "unpad_file", input_path=partial, output_path=restored)
                ensure_err_any(resp, {ERROR_CORRUPT_INPUT, ERROR_INVALID_ARCHIVE, ERROR_FILE_IO})
            else:
                # If operation completed before termination, validate complete recovery.
                resp = request(adapter, "unpad_file", input_path=partial, output_path=restored)
                ensure_ok(resp)
                assert_equal(sha256_file(src), sha256_file(restored), "completed interrupted-run hash mismatch")
        ensure_ok(request(adapter, "ping"))


def test_padding_accuracy_1gb(adapter, _ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src_1mb.bin")
        padded = os.path.join(td, "padded_1gb.bin")
        create_random_file(src, 1024 * 1024)
        target = 1_000_000_000
        ensure_ok(request(adapter, "pad_file", input_path=src, output_path=padded, target_size=target))
        assert_equal(os.path.getsize(padded), target, "1GB target size mismatch")


def test_large_file_stream_roundtrip(adapter, _ctx):
    with tempfile.TemporaryDirectory() as td:
        srcdir = os.path.join(td, "src")
        outdir = os.path.join(td, "out")
        archive = os.path.join(td, "large.sap")
        os.makedirs(srcdir, exist_ok=True)
        large = os.path.join(srcdir, "large.bin")
        create_random_file(large, 16 * 1024 * 1024)

        ensure_ok(request(adapter, "pack_path", input_path=srcdir, output_path=archive))
        ensure_ok(request(adapter, "unpack_path", input_path=archive, output_dir=outdir))

        extracted = os.path.join(outdir, "large.bin")
        assert_equal(sha256_file(large), sha256_file(extracted), "large stream roundtrip hash mismatch")


def build_tests():
    return [
        ("AK3-CO-001", "Ping health check", test_ping, False),
        ("AK3-SP-001", "Single-file round-trip integrity", test_pack_unpack_single_file, False),
        ("AK3-SP-002", "Nested directory round-trip integrity", test_pack_unpack_nested_dir, False),
        ("AK3-SP-003", "Archive inspection deterministic order", test_archive_order_stable, False),
        ("AK3-SP-010", "Missing input path rejected", test_pack_missing_input, False),
        ("AK3-SP-011", "Corrupt archive rejected", test_unpack_corrupt_archive, False),
        ("AK3-SP-012", "Path traversal entry rejected", test_unpack_traversal_entry_rejected, False),
        ("AK3-PAD-001", "Padding accuracy regular target", test_padding_accuracy_small, False),
        ("AK3-PAD-002", "Unpad restores original hash", test_unpad_restores_hash, False),
        ("AK3-PAD-003", "Too-small target rejected", test_padding_target_too_small, False),
        ("AK3-PAD-004", "Zero-length payload support", test_padding_zero_length_payload, False),
        ("AK3-PAD-005", "Corrupt padded container rejected", test_corrupt_padded_rejected, False),
        ("AK3-INT-001", "Truncated partial file handled gracefully", test_truncated_partial_file_handled, False),
        ("AK3-INT-002", "No exceptions on invalid requests", test_no_exceptions_on_invalid, False),
        ("AK3-INT-003", "Interrupted write handling", test_terminated_padding_process_handling, False),
        ("AK3-PAD-010", "Spec-sized padding 1MB -> 1_000_000_000 bytes", test_padding_accuracy_1gb, True),
        ("AK3-SP-020", "Large-file stream round-trip", test_large_file_stream_roundtrip, True),
    ]


def main():
    parser = argparse.ArgumentParser(description="SafeAnar Phase 3 Test Runner")
    parser.add_argument(
        "--adapter",
        default=os.path.join(os.path.dirname(__file__), "adapters", "phase3_stream_ref.py"),
    )
    parser.add_argument("--include-slow", action="store_true")
    parser.add_argument("--list-tests", action="store_true")
    parser.add_argument("--adapter-arg", action="append", default=[])
    args = parser.parse_args()

    tests = build_tests()
    if args.list_tests:
        for tid, desc, _, slow in tests:
            slow_tag = " (slow)" if slow else ""
            print(f"{tid}{slow_tag} - {desc}")
        return 0

    cmd = [sys.executable, args.adapter] if args.adapter.endswith(".py") else [args.adapter]
    cmd.extend(args.adapter_arg)
    ctx = {"adapter_cmd": cmd}

    adapter = AdapterProcess(cmd)
    try:
        passed = 0
        failed = 0
        skipped = 0
        for tid, desc, fn, slow in tests:
            if slow and not args.include_slow:
                skipped += 1
                print(f"SKIP {tid} - {desc}")
                continue
            try:
                fn(adapter, ctx)
                passed += 1
                print(f"PASS {tid} - {desc}")
            except TestFailure as ex:
                failed += 1
                print(f"FAIL {tid} - {desc}")
                print(f"  {ex}")
            except Exception as ex:
                failed += 1
                print(f"ERROR {tid} - {desc}")
                print(f"  {ex}")

        total = passed + failed
        percent = (100.0 * passed / total) if total else 0.0
        print("")
        print(f"Summary: {passed}/{total} passed ({percent:.1f}%). {failed} failed, {skipped} skipped.")
        return 0 if failed == 0 else 1
    finally:
        adapter.close()


if __name__ == "__main__":
    sys.exit(main())

