import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile


ERROR_INVALID_KEY_LENGTH = "InvalidKeyLength"
ERROR_INVALID_BLOCK_LENGTH = "InvalidBlockLength"
ERROR_BAD_HEX = "BadHex"
ERROR_KEY_TOO_SHORT = "KeyTooShort"
ERROR_FILE_IO = "FileIOError"


AES256_KEY_HEX = (
    "603deb1015ca71be2b73aef0857d7781"
    "1f352c073b6108d72d9810a30914dff4"
)
AES_PLAINTEXT_BLOCKS_HEX = [
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
]
AES_CIPHERTEXT_BLOCKS_HEX = [
    "f3eed1bdb5d2a03c064b5a7e3db181f8",
    "591ccb10d410ed26dc5ba74a31362870",
    "b6ed21b99ca6f4f9f153e7b1beafed1d",
    "23304b7a39f9f3ff067d8d8f9e24ecc7",
]


class TestFailure(Exception):
    pass


class AdapterProcess:
    def __init__(self, command):
        self.proc = subprocess.Popen(
            command,
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


def assert_true(condition, message):
    if not condition:
        raise TestFailure(message)


def assert_equal(actual, expected, message):
    if actual != expected:
        raise TestFailure(f"{message}. got={actual} expected={expected}")


def ensure_ok(response):
    assert_true(response.get("ok") is True, f"expected ok response, got {response}")


def ensure_error(response, expected_code):
    assert_true(response.get("ok") is False, f"expected error response, got {response}")
    assert_equal(response.get("error"), expected_code, "error code mismatch")


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


def test_ping(adapter):
    response = request(adapter, "ping")
    ensure_ok(response)


def test_aes_kat_single_block_encrypt(adapter):
    response = request(
        adapter,
        "aes256_ecb_encrypt",
        key_hex=AES256_KEY_HEX,
        plaintext_hex=AES_PLAINTEXT_BLOCKS_HEX[0],
    )
    ensure_ok(response)
    assert_equal(
        response.get("ciphertext_hex", "").lower(),
        AES_CIPHERTEXT_BLOCKS_HEX[0],
        "single-block ciphertext mismatch",
    )


def test_aes_kat_multi_block_encrypt(adapter):
    plaintext_hex = "".join(AES_PLAINTEXT_BLOCKS_HEX)
    expected_hex = "".join(AES_CIPHERTEXT_BLOCKS_HEX)
    response = request(
        adapter,
        "aes256_ecb_encrypt",
        key_hex=AES256_KEY_HEX,
        plaintext_hex=plaintext_hex,
    )
    ensure_ok(response)
    assert_equal(
        response.get("ciphertext_hex", "").lower(),
        expected_hex,
        "multi-block ciphertext mismatch",
    )


def test_aes_kat_multi_block_decrypt(adapter):
    ciphertext_hex = "".join(AES_CIPHERTEXT_BLOCKS_HEX)
    expected_hex = "".join(AES_PLAINTEXT_BLOCKS_HEX)
    response = request(
        adapter,
        "aes256_ecb_decrypt",
        key_hex=AES256_KEY_HEX,
        ciphertext_hex=ciphertext_hex,
    )
    ensure_ok(response)
    assert_equal(
        response.get("plaintext_hex", "").lower(),
        expected_hex,
        "multi-block plaintext mismatch",
    )


def test_aes_invalid_key_length(adapter):
    short_key = "00" * 31
    response = request(
        adapter,
        "aes256_ecb_encrypt",
        key_hex=short_key,
        plaintext_hex=AES_PLAINTEXT_BLOCKS_HEX[0],
    )
    ensure_error(response, ERROR_INVALID_KEY_LENGTH)


def test_aes_invalid_block_length(adapter):
    response = request(
        adapter,
        "aes256_ecb_encrypt",
        key_hex=AES256_KEY_HEX,
        plaintext_hex="001122",
    )
    ensure_error(response, ERROR_INVALID_BLOCK_LENGTH)


def test_aes_bad_hex(adapter):
    response = request(
        adapter,
        "aes256_ecb_encrypt",
        key_hex=AES256_KEY_HEX,
        plaintext_hex="GG",
    )
    ensure_error(response, ERROR_BAD_HEX)


def test_aes_deterministic(adapter):
    plaintext_hex = "".join(AES_PLAINTEXT_BLOCKS_HEX)
    r1 = request(
        adapter,
        "aes256_ecb_encrypt",
        key_hex=AES256_KEY_HEX,
        plaintext_hex=plaintext_hex,
    )
    r2 = request(
        adapter,
        "aes256_ecb_encrypt",
        key_hex=AES256_KEY_HEX,
        plaintext_hex=plaintext_hex,
    )
    ensure_ok(r1)
    ensure_ok(r2)
    assert_equal(r1.get("ciphertext_hex"), r2.get("ciphertext_hex"), "non-deterministic AES output")


def test_otp_known_vector(adapter):
    response = request(adapter, "otp_xor_bytes", data_hex="00112233", key_hex="FFFFFFFF")
    ensure_ok(response)
    assert_equal(response.get("result_hex", "").lower(), "ffeeddcc", "known XOR vector mismatch")


def test_otp_bytes_symmetry(adapter):
    data = secrets.token_bytes(128).hex()
    key = secrets.token_bytes(128).hex()
    encrypted = request(adapter, "otp_xor_bytes", data_hex=data, key_hex=key)
    ensure_ok(encrypted)
    decrypted = request(adapter, "otp_xor_bytes", data_hex=encrypted["result_hex"], key_hex=key)
    ensure_ok(decrypted)
    assert_equal(decrypted.get("result_hex", "").lower(), data, "OTP bytes symmetry mismatch")


def test_otp_bytes_key_too_short(adapter):
    response = request(adapter, "otp_xor_bytes", data_hex="0011223344", key_hex="AABB")
    ensure_error(response, ERROR_KEY_TOO_SHORT)


def test_otp_bytes_empty(adapter):
    response = request(adapter, "otp_xor_bytes", data_hex="", key_hex="")
    ensure_ok(response)
    assert_equal(response.get("result_hex"), "", "expected empty output")


def test_otp_file_round_trip_hash(adapter):
    with tempfile.TemporaryDirectory() as td:
        plain_path = os.path.join(td, "plain.bin")
        key_path = os.path.join(td, "key.bin")
        enc_path = os.path.join(td, "enc.bin")
        dec_path = os.path.join(td, "dec.bin")

        plain_bytes = secrets.token_bytes(256 * 1024)
        key_bytes = secrets.token_bytes(len(plain_bytes))
        with open(plain_path, "wb") as f:
            f.write(plain_bytes)
        with open(key_path, "wb") as f:
            f.write(key_bytes)

        r1 = request(adapter, "otp_xor_file", input_path=plain_path, key_path=key_path, output_path=enc_path)
        ensure_ok(r1)
        r2 = request(adapter, "otp_xor_file", input_path=enc_path, key_path=key_path, output_path=dec_path)
        ensure_ok(r2)

        assert_equal(sha256_file(plain_path), sha256_file(dec_path), "SHA-256 mismatch after round-trip")


def test_otp_file_key_too_short(adapter):
    with tempfile.TemporaryDirectory() as td:
        plain_path = os.path.join(td, "plain.bin")
        key_path = os.path.join(td, "key.bin")
        out_path = os.path.join(td, "out.bin")

        with open(plain_path, "wb") as f:
            f.write(secrets.token_bytes(1024))
        with open(key_path, "wb") as f:
            f.write(secrets.token_bytes(512))

        response = request(adapter, "otp_xor_file", input_path=plain_path, key_path=key_path, output_path=out_path)
        ensure_error(response, ERROR_KEY_TOO_SHORT)


def test_otp_file_empty_round_trip(adapter):
    with tempfile.TemporaryDirectory() as td:
        plain_path = os.path.join(td, "plain.bin")
        key_path = os.path.join(td, "key.bin")
        out_path = os.path.join(td, "out.bin")
        out2_path = os.path.join(td, "out2.bin")

        with open(plain_path, "wb") as f:
            f.write(b"")
        with open(key_path, "wb") as f:
            f.write(b"")

        r1 = request(adapter, "otp_xor_file", input_path=plain_path, key_path=key_path, output_path=out_path)
        ensure_ok(r1)
        r2 = request(adapter, "otp_xor_file", input_path=out_path, key_path=key_path, output_path=out2_path)
        ensure_ok(r2)

        assert_equal(os.path.getsize(out2_path), 0, "expected empty output file")


def test_otp_file_missing_input(adapter):
    with tempfile.TemporaryDirectory() as td:
        plain_path = os.path.join(td, "does_not_exist.bin")
        key_path = os.path.join(td, "key.bin")
        out_path = os.path.join(td, "out.bin")

        with open(key_path, "wb") as f:
            f.write(secrets.token_bytes(32))
        response = request(adapter, "otp_xor_file", input_path=plain_path, key_path=key_path, output_path=out_path)
        ensure_error(response, ERROR_FILE_IO)


def test_invalid_input_does_not_kill_process(adapter):
    bad = request(adapter, "aes256_ecb_encrypt", key_hex="00", plaintext_hex="00")
    assert_true(bad.get("ok") is False, "invalid input should fail")
    ping = request(adapter, "ping")
    ensure_ok(ping)


def test_otp_file_round_trip_hash_large(adapter):
    with tempfile.TemporaryDirectory() as td:
        plain_path = os.path.join(td, "plain_large.bin")
        key_path = os.path.join(td, "key_large.bin")
        enc_path = os.path.join(td, "enc_large.bin")
        dec_path = os.path.join(td, "dec_large.bin")

        plain_bytes = secrets.token_bytes(2 * 1024 * 1024)
        key_bytes = secrets.token_bytes(len(plain_bytes))
        with open(plain_path, "wb") as f:
            f.write(plain_bytes)
        with open(key_path, "wb") as f:
            f.write(key_bytes)

        r1 = request(adapter, "otp_xor_file", input_path=plain_path, key_path=key_path, output_path=enc_path)
        ensure_ok(r1)
        r2 = request(adapter, "otp_xor_file", input_path=enc_path, key_path=key_path, output_path=dec_path)
        ensure_ok(r2)

        assert_equal(sha256_file(plain_path), sha256_file(dec_path), "large round-trip SHA mismatch")


def build_tests():
    return [
        ("AK2-CO-001", "Ping health check", test_ping, False),
        ("AK2-AES-001", "NIST ECB single-block encrypt", test_aes_kat_single_block_encrypt, False),
        ("AK2-AES-002", "NIST ECB multi-block encrypt", test_aes_kat_multi_block_encrypt, False),
        ("AK2-AES-003", "NIST ECB multi-block decrypt", test_aes_kat_multi_block_decrypt, False),
        ("AK2-AES-010", "Invalid key length rejected", test_aes_invalid_key_length, False),
        ("AK2-AES-011", "Non-block-aligned plaintext rejected", test_aes_invalid_block_length, False),
        ("AK2-AES-012", "Bad hex rejected", test_aes_bad_hex, False),
        ("AK2-AES-013", "Deterministic encryption", test_aes_deterministic, False),
        ("AK2-OTP-001", "Known XOR vector", test_otp_known_vector, False),
        ("AK2-OTP-002", "Symmetry on bytes", test_otp_bytes_symmetry, False),
        ("AK2-OTP-003", "Key too short rejected (bytes)", test_otp_bytes_key_too_short, False),
        ("AK2-OTP-004", "Zero-length bytes input", test_otp_bytes_empty, False),
        ("AK2-OTP-010", "File round-trip hash equality", test_otp_file_round_trip_hash, False),
        ("AK2-OTP-011", "Key file too short rejected", test_otp_file_key_too_short, False),
        ("AK2-OTP-012", "Empty file round-trip", test_otp_file_empty_round_trip, False),
        ("AK2-OTP-013", "Missing file path handled", test_otp_file_missing_input, False),
        ("AK2-CO-002", "No exceptions on invalid input", test_invalid_input_does_not_kill_process, False),
        ("AK2-OTP-020", "Large file round-trip hash equality", test_otp_file_round_trip_hash_large, True),
    ]


def main():
    parser = argparse.ArgumentParser(description="SafeAnar Phase 2 Test Runner")
    parser.add_argument(
        "--adapter",
        default=os.path.join(os.path.dirname(__file__), "adapters", "phase2_crypto_ref.py"),
    )
    parser.add_argument("--include-slow", action="store_true")
    parser.add_argument("--list-tests", action="store_true")
    parser.add_argument("--adapter-arg", action="append", default=[])
    args = parser.parse_args()

    tests = build_tests()
    if args.list_tests:
        for tid, desc, _, slow in tests:
            slow_text = " (slow)" if slow else ""
            print(f"{tid}{slow_text} - {desc}")
        return 0

    command = [sys.executable, args.adapter] if args.adapter.endswith(".py") else [args.adapter]
    command.extend(args.adapter_arg)

    adapter = AdapterProcess(command)
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
                fn(adapter)
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

