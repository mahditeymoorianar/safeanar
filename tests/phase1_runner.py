import argparse
import json
import os
import sys
import subprocess
import tempfile
import math

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
DEFAULT_DICT = os.path.join(os.path.dirname(__file__), "fixtures", "test_dictionary_256.txt")

ERROR_INVALID_WORD = "InvalidWord"
ERROR_INVALID_CHAR = "InvalidChar"
ERROR_INVALID_LENGTH = "InvalidLength"
ERROR_INVALID_DICT = "InvalidDictionary"


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

    def request(self, obj):
        line = json.dumps(obj, separators=(",", ":"))
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        resp_line = self.proc.stdout.readline()
        if not resp_line:
            err = self.proc.stderr.read()
            raise RuntimeError(f"adapter closed unexpectedly. stderr={err}")
        return json.loads(resp_line)

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


class TestFailure(Exception):
    pass


def assert_true(cond, msg):
    if not cond:
        raise TestFailure(msg)


def assert_equal(a, b, msg):
    if a != b:
        raise TestFailure(f"{msg}. got={a} expected={b}")


def hex_from_indices(indices):
    return bytes(indices).hex().upper()


def ensure_ok(resp):
    assert_true(resp.get("ok") is True, f"expected ok response, got {resp}")


def ensure_err(resp, code):
    assert_true(resp.get("ok") is False, f"expected error {code}, got ok")
    assert_equal(resp.get("error"), code, "error code mismatch")


def request(adapter, op, **kwargs):
    return adapter.request({"op": op, **kwargs})


def chi_square_critical_approx(df, alpha=0.01):
    # Wilson-Hilferty approximation using z for 1 - alpha
    z_0_99 = 2.3263478740408408
    z = z_0_99 if abs(alpha - 0.01) < 1e-9 else z_0_99
    return df * (1 - 2 / (9 * df) + z * math.sqrt(2 / (9 * df))) ** 3


def test_word_known(adapter, dictionary_path):
    words = [f"w{i:03d}" for i in range(32)]
    expected = hex_from_indices(list(range(32)))
    resp = request(adapter, "derive_words", dictionary_path=dictionary_path, passphrase=" ".join(words))
    ensure_ok(resp)
    assert_equal(resp.get("key_hex"), expected, "key mismatch")


def test_word_noncontiguous(adapter, dictionary_path):
    indices = [255, 128, 127, 0] + list(range(1, 28)) + [64]
    assert_equal(len(indices), 32, "indices length")
    words = [f"w{i:03d}" for i in indices]
    expected = hex_from_indices(indices)
    resp = request(adapter, "derive_words", dictionary_path=dictionary_path, passphrase=" ".join(words))
    ensure_ok(resp)
    assert_equal(resp.get("key_hex"), expected, "key mismatch")


def test_word_duplicate(adapter, dictionary_path):
    indices = list(range(32))
    indices[10] = 5
    words = [f"w{i:03d}" for i in indices]
    expected = hex_from_indices(indices)
    resp = request(adapter, "derive_words", dictionary_path=dictionary_path, passphrase=" ".join(words))
    ensure_ok(resp)
    assert_equal(resp.get("key_hex"), expected, "key mismatch")


def test_word_spaces(adapter, dictionary_path):
    words = [f"w{i:03d}" for i in range(32)]
    passphrase = "  \n\t" + "   ".join(words) + "  \n"
    expected = hex_from_indices(list(range(32)))
    resp = request(adapter, "derive_words", dictionary_path=dictionary_path, passphrase=passphrase)
    ensure_ok(resp)
    assert_equal(resp.get("key_hex"), expected, "key mismatch")


def test_word_case_insensitive(adapter, dictionary_path):
    words = [f"w{i:03d}" for i in range(32)]
    words[0] = words[0].upper()
    words[2] = words[2].upper()
    expected = hex_from_indices(list(range(32)))
    resp = request(adapter, "derive_words", dictionary_path=dictionary_path, passphrase=" ".join(words))
    ensure_ok(resp)
    assert_equal(resp.get("key_hex"), expected, "key mismatch")


def test_word_unknown(adapter, dictionary_path):
    words = [f"w{i:03d}" for i in range(31)] + ["notaword"]
    resp = request(adapter, "derive_words", dictionary_path=dictionary_path, passphrase=" ".join(words))
    ensure_err(resp, ERROR_INVALID_WORD)


def test_word_too_few(adapter, dictionary_path):
    words = [f"w{i:03d}" for i in range(31)]
    resp = request(adapter, "derive_words", dictionary_path=dictionary_path, passphrase=" ".join(words))
    ensure_err(resp, ERROR_INVALID_LENGTH)


def test_word_too_many(adapter, dictionary_path):
    words = [f"w{i:03d}" for i in range(33)]
    resp = request(adapter, "derive_words", dictionary_path=dictionary_path, passphrase=" ".join(words))
    ensure_err(resp, ERROR_INVALID_LENGTH)


def test_word_empty(adapter, dictionary_path):
    resp = request(adapter, "derive_words", dictionary_path=dictionary_path, passphrase="   \n\t")
    ensure_err(resp, ERROR_INVALID_LENGTH)


def test_word_dictionary_length_invalid(adapter, dictionary_path):
    with tempfile.TemporaryDirectory() as td:
        p1 = os.path.join(td, "dict_255.txt")
        with open(p1, "w", encoding="utf-8") as f:
            for i in range(255):
                f.write(f"w{i:03d}\n")
        resp = request(adapter, "derive_words", dictionary_path=p1, passphrase=" ".join(["w000"] * 32))
        ensure_err(resp, ERROR_INVALID_DICT)

        p2 = os.path.join(td, "dict_257.txt")
        with open(p2, "w", encoding="utf-8") as f:
            for i in range(257):
                f.write(f"w{i:03d}\n")
        resp = request(adapter, "derive_words", dictionary_path=p2, passphrase=" ".join(["w000"] * 32))
        ensure_err(resp, ERROR_INVALID_DICT)


def test_word_dictionary_duplicates(adapter, dictionary_path):
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "dict_dup.txt")
        with open(p, "w", encoding="utf-8") as f:
            for i in range(256):
                val = 1 if i == 2 else i
                f.write(f"w{val:03d}\n")
        resp = request(adapter, "derive_words", dictionary_path=p, passphrase=" ".join(["w000"] * 32))
        ensure_err(resp, ERROR_INVALID_DICT)


def test_word_non_ascii(adapter, dictionary_path):
    omega = chr(0x03A9)
    words = [f"w{i:03d}" for i in range(31)] + ["w0" + omega + "1"]
    resp = request(adapter, "derive_words", dictionary_path=dictionary_path, passphrase=" ".join(words))
    ensure_err(resp, ERROR_INVALID_WORD)


def test_word_punctuation(adapter, dictionary_path):
    words = [f"w{i:03d}" for i in range(31)] + ["w001,"]
    resp = request(adapter, "derive_words", dictionary_path=dictionary_path, passphrase=" ".join(words))
    ensure_err(resp, ERROR_INVALID_WORD)


def test_char_known_all_a(adapter):
    passphrase = "A" * 43
    resp = request(adapter, "derive_chars", alphabet=ALPHABET, passphrase=passphrase)
    ensure_ok(resp)
    assert_equal(resp.get("key_hex"), "00" * 32, "key mismatch")


def test_char_known_pattern(adapter):
    passphrase = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
    expected = "00108310518720928B30D38F41149351559761969B71D79F8218A39259A7A29A"
    resp = request(adapter, "derive_chars", alphabet=ALPHABET, passphrase=passphrase)
    ensure_ok(resp)
    assert_equal(resp.get("key_hex"), expected, "key mismatch")


def test_char_valid_chars(adapter):
    passphrase = "A" * 41 + "-_"
    resp = request(adapter, "derive_chars", alphabet=ALPHABET, passphrase=passphrase)
    ensure_ok(resp)
    assert_equal(len(resp.get("key_hex", "")), 64, "key length mismatch")


def test_char_deterministic(adapter):
    passphrase = "B" * 43
    r1 = request(adapter, "derive_chars", alphabet=ALPHABET, passphrase=passphrase)
    r2 = request(adapter, "derive_chars", alphabet=ALPHABET, passphrase=passphrase)
    ensure_ok(r1)
    ensure_ok(r2)
    assert_equal(r1.get("key_hex"), r2.get("key_hex"), "nondeterministic")


def test_char_too_few(adapter):
    passphrase = "A" * 42
    resp = request(adapter, "derive_chars", alphabet=ALPHABET, passphrase=passphrase)
    ensure_err(resp, ERROR_INVALID_LENGTH)


def test_char_too_many(adapter):
    passphrase = "A" * 44
    resp = request(adapter, "derive_chars", alphabet=ALPHABET, passphrase=passphrase)
    ensure_err(resp, ERROR_INVALID_LENGTH)


def test_char_invalid_char(adapter):
    passphrase = "A" * 42 + "@"
    resp = request(adapter, "derive_chars", alphabet=ALPHABET, passphrase=passphrase)
    ensure_err(resp, ERROR_INVALID_CHAR)


def test_char_non_ascii(adapter):
    omega = chr(0x03A9)
    passphrase = "A" * 42 + omega
    resp = request(adapter, "derive_chars", alphabet=ALPHABET, passphrase=passphrase)
    ensure_err(resp, ERROR_INVALID_CHAR)


def test_char_space_significant(adapter):
    passphrase = " " + "A" * 42
    resp = request(adapter, "derive_chars", alphabet=ALPHABET, passphrase=passphrase)
    ensure_err(resp, ERROR_INVALID_CHAR)


def test_common_output_length(adapter, dictionary_path):
    words = [f"w{i:03d}" for i in range(32)]
    resp = request(adapter, "derive_words", dictionary_path=dictionary_path, passphrase=" ".join(words))
    ensure_ok(resp)
    assert_equal(len(resp.get("key_hex", "")), 64, "key length mismatch")


def test_common_no_exceptions(adapter, dictionary_path):
    words = [f"w{i:03d}" for i in range(31)] + ["notaword"]
    resp = request(adapter, "derive_words", dictionary_path=dictionary_path, passphrase=" ".join(words))
    ensure_err(resp, ERROR_INVALID_WORD)


def test_common_deterministic(adapter, dictionary_path):
    words = [f"w{i:03d}" for i in range(32)]
    r1 = request(adapter, "derive_words", dictionary_path=dictionary_path, passphrase=" ".join(words))
    r2 = request(adapter, "derive_words", dictionary_path=dictionary_path, passphrase=" ".join(words))
    ensure_ok(r1)
    ensure_ok(r2)
    assert_equal(r1.get("key_hex"), r2.get("key_hex"), "nondeterministic")


def test_rng_stub(adapter, dictionary_path):
    rng_bytes = bytes(range(256)).hex()
    resp = request(adapter, "gen_words", dictionary_path=dictionary_path, mode="stub", rng_bytes_hex=rng_bytes, count=32)
    ensure_ok(resp)
    words = resp.get("words", [])
    assert_equal(len(words), 32, "word count mismatch")
    expected = [f"w{i:03d}" for i in range(32)]
    assert_equal(words, expected, "rng stub mismatch")


def test_rng_no_collisions(adapter, dictionary_path):
    resp = request(adapter, "gen_keys", dictionary_path=dictionary_path, count=10000, mode="system")
    ensure_ok(resp)
    keys = resp.get("keys_hex", [])
    assert_equal(len(keys), 10000, "key count mismatch")
    assert_equal(len(set(keys)), 10000, "collision detected")


def test_rng_uniformity(adapter, dictionary_path):
    resp = request(adapter, "gen_keys", dictionary_path=dictionary_path, count=10000, mode="system")
    ensure_ok(resp)
    keys = resp.get("keys_hex", [])
    total = 0
    counts = [0] * 256
    for key_hex in keys:
        data = bytes.fromhex(key_hex)
        total += len(data)
        for b in data:
            counts[b] += 1

    expected = total / 256.0
    chi = sum((c - expected) ** 2 / expected for c in counts)
    crit = chi_square_critical_approx(255, 0.01)
    assert_true(chi <= crit, f"chi-square too high: {chi:.2f} > {crit:.2f}")


def build_tests():
    return [
        ("AK-W-001", "Known mapping produces correct 256-bit key", test_word_known, False),
        ("AK-W-002", "Non-contiguous mapping is correct", test_word_noncontiguous, False),
        ("AK-W-003", "Duplicate words allowed and map correctly", test_word_duplicate, False),
        ("AK-W-004", "Leading/trailing/multiple spaces are handled", test_word_spaces, False),
        ("AK-W-005", "Case-insensitive matching", test_word_case_insensitive, False),
        ("AK-W-010", "Unknown word rejected", test_word_unknown, False),
        ("AK-W-011", "Too few words rejected", test_word_too_few, False),
        ("AK-W-012", "Too many words rejected", test_word_too_many, False),
        ("AK-W-013", "Empty input rejected", test_word_empty, False),
        ("AK-W-014", "Dictionary length invalid rejected", test_word_dictionary_length_invalid, False),
        ("AK-W-015", "Dictionary contains duplicates", test_word_dictionary_duplicates, False),
        ("AK-W-016", "Non-ASCII word token rejected", test_word_non_ascii, False),
        ("AK-W-017", "Punctuation in word rejected", test_word_punctuation, False),
        ("AK-C-001", "Known mapping (all A) produces correct 256-bit key", test_char_known_all_a, False),
        ("AK-C-004", "Known mapping (pattern) verifies bit packing", test_char_known_pattern, False),
        ("AK-C-002", "Valid characters accepted", test_char_valid_chars, False),
        ("AK-C-003", "Deterministic output", test_char_deterministic, False),
        ("AK-C-010", "Too few characters rejected", test_char_too_few, False),
        ("AK-C-011", "Too many characters rejected", test_char_too_many, False),
        ("AK-C-012", "Invalid character rejected", test_char_invalid_char, False),
        ("AK-C-013", "Non-ASCII character rejected", test_char_non_ascii, False),
        ("AK-C-014", "Leading/trailing spaces are significant", test_char_space_significant, False),
        ("AK-CO-001", "Output length always 32 bytes", test_common_output_length, False),
        ("AK-CO-002", "No exceptions thrown", test_common_no_exceptions, False),
        ("AK-CO-003", "Deterministic mapping", test_common_deterministic, False),
        ("AK-R-001", "Generator uses RNG (deterministic stub)", test_rng_stub, False),
        ("AK-R-002", "No collisions in 10,000 keys", test_rng_no_collisions, True),
        ("AK-R-003", "Basic uniformity (chi-square)", test_rng_uniformity, True),
    ]


def main():
    parser = argparse.ArgumentParser(description="SafeAnar Phase 1 Test Runner")
    parser.add_argument("--adapter", default=os.path.join(os.path.dirname(__file__), "adapters", "anar_key_ref.py"))
    parser.add_argument("--dictionary", default=DEFAULT_DICT)
    parser.add_argument("--include-slow", action="store_true")
    parser.add_argument("--list-tests", action="store_true")
    parser.add_argument("--adapter-arg", action="append", default=[])
    args = parser.parse_args()

    tests = build_tests()

    if args.list_tests:
        for tid, desc, _, slow in tests:
            flag = "(slow)" if slow else ""
            print(f"{tid} {flag} - {desc}")
        return 0

    adapter_path = args.adapter
    cmd = []
    if adapter_path.endswith(".py"):
        cmd = [sys.executable, adapter_path]
    else:
        cmd = [adapter_path]
    cmd.extend(args.adapter_arg)

    adapter = AdapterProcess(cmd)
    try:
        ping = request(adapter, "ping")
        ensure_ok(ping)

        passed = 0
        failed = 0
        skipped = 0

        for tid, desc, func, slow in tests:
            if slow and not args.include_slow:
                skipped += 1
                print(f"SKIP {tid} - {desc}")
                continue
            try:
                if func.__code__.co_argcount == 2:
                    func(adapter, args.dictionary)
                elif func.__code__.co_argcount == 1:
                    func(adapter)
                else:
                    func(adapter, args.dictionary)
                passed += 1
                print(f"PASS {tid} - {desc}")
            except TestFailure as e:
                failed += 1
                print(f"FAIL {tid} - {desc}")
                print(f"  {e}")
            except Exception as e:
                failed += 1
                print(f"ERROR {tid} - {desc}")
                print(f"  {e}")

        total = passed + failed
        percent = (passed / total * 100.0) if total > 0 else 0.0
        print("")
        print(f"Summary: {passed}/{total} passed ({percent:.1f}%). {failed} failed, {skipped} skipped.")

        return 0 if failed == 0 else 1
    finally:
        adapter.close()


if __name__ == "__main__":
    sys.exit(main())
