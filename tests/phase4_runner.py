import argparse
import hashlib
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile


class TestFailure(Exception):
    pass


def assert_true(condition, message):
    if not condition:
        raise TestFailure(message)


def assert_equal(actual, expected, message):
    if actual != expected:
        raise TestFailure(f"{message}. got={actual} expected={expected}")


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
    out = {}
    for base, _, files in os.walk(root):
        files.sort()
        for name in files:
            full = os.path.join(base, name)
            rel = os.path.relpath(full, root).replace("\\", "/")
            out[rel] = (os.path.getsize(full), sha256_file(full))
    return out


def create_random_file(path, size):
    with open(path, "wb") as f:
        remain = size
        while remain > 0:
            n = 4096 if remain > 4096 else remain
            f.write(secrets.token_bytes(n))
            remain -= n


def run_cli(ctx, args, cwd=None):
    cmd = list(ctx["cli_cmd"])
    cmd.extend(args)
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def ensure_ok(rc):
    if rc.returncode != 0:
        raise TestFailure(
            f"expected success exit code 0, got {rc.returncode}; stderr={rc.stderr.strip()} stdout={rc.stdout.strip()}"
        )


def ensure_fail(rc):
    if rc.returncode == 0:
        raise TestFailure("expected non-zero exit code, got 0")


def build_nested_fixture(root, large=False):
    os.makedirs(os.path.join(root, "a", "b"), exist_ok=True)
    os.makedirs(os.path.join(root, "c"), exist_ok=True)
    with open(os.path.join(root, "root.txt"), "wb") as f:
        f.write(b"safeanar-phase4\n")
    with open(os.path.join(root, "a", "b", "notes.txt"), "wb") as f:
        f.write(b"nested-file\n")
    create_random_file(os.path.join(root, "c", "data.bin"), 4096)
    with open(os.path.join(root, "c", "empty.bin"), "wb") as f:
        f.write(b"")
    if large:
        create_random_file(os.path.join(root, "a", "b", "large.bin"), 16 * 1024 * 1024)


def test_file_roundtrip(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "secret.bin")
        enc = os.path.join(td, "secret.enc")
        dec = os.path.join(td, "secret.dec")
        create_random_file(src, 1024 * 1024)

        r1 = run_cli(ctx, ["--encrypt", "--path", src, "--out", enc, "--key", "phase4-key", "--protocol", "aes"])
        ensure_ok(r1)
        r2 = run_cli(ctx, ["--decrypt", "--path", enc, "--out", dec, "--key", "phase4-key"])
        ensure_ok(r2)
        assert_equal(sha256_file(src), sha256_file(dec), "file roundtrip hash mismatch")


def test_text_roundtrip(ctx):
    with tempfile.TemporaryDirectory() as td:
        enc = os.path.join(td, "text.enc")
        out = os.path.join(td, "text.out")
        message = "SafeAnar Phase 4 text: AES/OTP integration."
        r1 = run_cli(ctx, ["--encrypt", "--text", message, "--out", enc, "--key", "text-key"])
        ensure_ok(r1)
        r2 = run_cli(ctx, ["--decrypt", "--path", enc, "--out", out, "--key", "text-key"])
        ensure_ok(r2)
        with open(out, "rb") as f:
            got = f.read().decode("utf-8")
        assert_equal(got, message, "text roundtrip mismatch")


def test_directory_portability(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src")
        site_b = os.path.join(td, "site_b")
        os.makedirs(src, exist_ok=True)
        os.makedirs(site_b, exist_ok=True)
        build_nested_fixture(src)

        enc = os.path.join(td, "dir.enc")
        moved_enc = os.path.join(site_b, "dir.enc")
        out = os.path.join(site_b, "out")

        ensure_ok(run_cli(ctx, ["--encrypt", "--path", src, "--out", enc, "--key", "dir-key", "--protocol", "aes"]))
        shutil.copy2(enc, moved_enc)
        ensure_ok(run_cli(ctx, ["--decrypt", "--path", moved_enc, "--out", out, "--key", "dir-key"]))
        assert_equal(snapshot_dir(src), snapshot_dir(out), "directory snapshot mismatch after move+decrypt")


def test_default_protocol(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "a.bin")
        enc = os.path.join(td, "a.enc")
        dec = os.path.join(td, "a.dec")
        create_random_file(src, 4096)
        ensure_ok(run_cli(ctx, ["--encrypt", "--path", src, "--out", enc, "--key", "k-default"]))
        ensure_ok(run_cli(ctx, ["--decrypt", "--path", enc, "--out", dec, "--key", "k-default"]))
        assert_equal(sha256_file(src), sha256_file(dec), "default protocol roundtrip mismatch")


def test_pq_protocol_roundtrip(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "pq.bin")
        enc = os.path.join(td, "pq.enc")
        dec = os.path.join(td, "pq.dec")
        create_random_file(src, 32768)
        ensure_ok(run_cli(ctx, ["--encrypt", "--path", src, "--out", enc, "--key", "pq-key", "--protocol", "pq"]))
        ensure_ok(run_cli(ctx, ["--decrypt", "--path", enc, "--out", dec, "--key", "pq-key"]))
        assert_equal(sha256_file(src), sha256_file(dec), "pq protocol roundtrip mismatch")


def test_chacha20poly1305_roundtrip(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "chacha.bin")
        enc = os.path.join(td, "chacha.enc")
        dec = os.path.join(td, "chacha.dec")
        create_random_file(src, 32768)
        ensure_ok(
            run_cli(
                ctx,
                ["--encrypt", "--path", src, "--out", enc, "--key", "chacha-key", "--protocol", "chacha20poly1305"],
            )
        )
        ensure_ok(run_cli(ctx, ["--decrypt", "--path", enc, "--out", dec, "--key", "chacha-key"]))
        assert_equal(sha256_file(src), sha256_file(dec), "chacha20poly1305 roundtrip mismatch")


def test_xchacha20poly1305_roundtrip(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "xchacha.bin")
        enc = os.path.join(td, "xchacha.enc")
        dec = os.path.join(td, "xchacha.dec")
        create_random_file(src, 32768)
        ensure_ok(
            run_cli(
                ctx,
                ["--encrypt", "--path", src, "--out", enc, "--key", "xchacha-key", "--protocol", "xchacha20poly1305"],
            )
        )
        ensure_ok(run_cli(ctx, ["--decrypt", "--path", enc, "--out", dec, "--key", "xchacha-key"]))
        assert_equal(sha256_file(src), sha256_file(dec), "xchacha20poly1305 roundtrip mismatch")


def test_serpent256_roundtrip(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "serpent.bin")
        enc = os.path.join(td, "serpent.enc")
        dec = os.path.join(td, "serpent.dec")
        create_random_file(src, 32768)
        ensure_ok(run_cli(ctx, ["--encrypt", "--path", src, "--out", enc, "--key", "serpent-key", "--protocol", "serpent-256"]))
        ensure_ok(run_cli(ctx, ["--decrypt", "--path", enc, "--out", dec, "--key", "serpent-key"]))
        assert_equal(sha256_file(src), sha256_file(dec), "serpent-256 roundtrip mismatch")


def test_quoted_path_and_out_values(ctx):
    with tempfile.TemporaryDirectory(prefix="safeanar phase4 ") as td:
        src = os.path.join(td, "plain input.bin")
        enc = os.path.join(td, "cipher output.enc")
        dec = os.path.join(td, "restored output.bin")
        create_random_file(src, 2048)

        ensure_ok(
            run_cli(
                ctx,
                [
                    "--encrypt",
                    "--path",
                    f"\"{src}\"",
                    "--out",
                    f"\"{enc}\"",
                    "--key",
                    "quoted-key",
                ],
            )
        )
        ensure_ok(
            run_cli(
                ctx,
                [
                    "--decrypt",
                    "--path",
                    f"\"{enc}\"",
                    "--out",
                    f"\"{dec}\"",
                    "--key",
                    "quoted-key",
                ],
            )
        )
        assert_equal(sha256_file(src), sha256_file(dec), "quoted path/out roundtrip mismatch")


def test_unicode_path_roundtrip(ctx):
    with tempfile.TemporaryDirectory(prefix="safeanar unicode ") as td:
        src = os.path.join(td, "حسن کچل")
        enc = os.path.join(td, "unicode.enc")
        out = os.path.join(td, "خروجی")
        os.makedirs(src, exist_ok=True)
        create_random_file(os.path.join(src, "پرونده.bin"), 8192)
        with open(os.path.join(src, "متن.txt"), "wb") as f:
            f.write("سلام دنیا".encode("utf-8"))

        ensure_ok(run_cli(ctx, ["--encrypt", "--path", f"\"{src}\"", "--out", enc, "--key", "unicode-key"]))
        ensure_ok(run_cli(ctx, ["--decrypt", "--path", enc, "--out", f"\"{out}\"", "--key", "unicode-key"]))
        assert_equal(snapshot_dir(src), snapshot_dir(out), "unicode path roundtrip mismatch")


def test_otp_protocol(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "otp.bin")
        enc = os.path.join(td, "otp.enc")
        dec = os.path.join(td, "otp.dec")
        keyf = os.path.join(td, "otp.key")
        create_random_file(src, 16384)
        create_random_file(keyf, 16384)
        ensure_ok(run_cli(ctx, ["--encrypt", "--path", src, "--out", enc, "--key-file", keyf, "--protocol", "otp"]))
        ensure_ok(run_cli(ctx, ["--decrypt", "--path", enc, "--out", dec, "--key-file", keyf]))
        assert_equal(sha256_file(src), sha256_file(dec), "otp protocol roundtrip mismatch")


def test_otp_with_passphrase_rejected(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "otp.bin")
        enc = os.path.join(td, "otp.enc")
        create_random_file(src, 1024)
        rc = run_cli(ctx, ["--encrypt", "--path", src, "--out", enc, "--key", "k-otp", "--protocol", "otp"])
        ensure_fail(rc)
        assert_true("OTP requires --key-file" in rc.stderr.strip(), f"expected OTP key-file requirement, got stderr={rc.stderr.strip()}")


def test_keyfile_aes_roundtrip(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "plain.bin")
        enc = os.path.join(td, "cipher.enc")
        dec = os.path.join(td, "restored.bin")
        keyf = os.path.join(td, "aes.key")
        create_random_file(src, 32768)
        create_random_file(keyf, 4096)
        ensure_ok(run_cli(ctx, ["--encrypt", "--path", src, "--out", enc, "--key-file", keyf, "--protocol", "aes"]))
        ensure_ok(run_cli(ctx, ["--decrypt", "--path", enc, "--out", dec, "--key-file", keyf]))
        assert_equal(sha256_file(src), sha256_file(dec), "key-file aes roundtrip mismatch")


def test_keyfile_otp_roundtrip(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "otp_plain.bin")
        enc = os.path.join(td, "otp_cipher.enc")
        dec = os.path.join(td, "otp_restored.bin")
        keyf = os.path.join(td, "otp.key")
        create_random_file(src, 16384)
        create_random_file(keyf, 16384)
        ensure_ok(run_cli(ctx, ["--encrypt", "--path", src, "--out", enc, "--key-file", keyf, "--protocol", "otp"]))
        ensure_ok(run_cli(ctx, ["--decrypt", "--path", enc, "--out", dec, "--key-file", keyf]))
        assert_equal(sha256_file(src), sha256_file(dec), "key-file otp roundtrip mismatch")


def test_keyfile_otp_too_short_rejected(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "otp_plain.bin")
        enc = os.path.join(td, "otp_cipher.enc")
        keyf = os.path.join(td, "otp_short.key")
        create_random_file(src, 4096)
        create_random_file(keyf, 1024)
        rc = run_cli(ctx, ["--encrypt", "--path", src, "--out", enc, "--key-file", keyf, "--protocol", "otp"])
        ensure_fail(rc)
        assert_true("KeyTooShort" in rc.stderr.strip(), f"expected KeyTooShort, got stderr={rc.stderr.strip()}")


def test_padding_size_roundtrip_and_exact_size(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "plain.bin")
        enc = os.path.join(td, "padded.enc")
        dec = os.path.join(td, "restored.bin")
        create_random_file(src, 30000)
        ensure_ok(
            run_cli(
                ctx,
                ["--encrypt", "--path", src, "--out", enc, "--key", "pad-key", "--padding-size", "200KB"],
            )
        )
        assert_equal(os.path.getsize(enc), 200000, "padded output size mismatch")
        ensure_ok(run_cli(ctx, ["--decrypt", "--path", enc, "--out", dec, "--key", "pad-key"]))
        assert_equal(sha256_file(src), sha256_file(dec), "padded roundtrip mismatch")


def test_padding_size_too_small_rejected(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "plain.bin")
        enc = os.path.join(td, "padded.enc")
        create_random_file(src, 30000)
        rc = run_cli(ctx, ["--encrypt", "--path", src, "--out", enc, "--key", "k", "--padding-size", "1KB"])
        ensure_fail(rc)


def test_padding_size_with_decrypt_rejected(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "plain.bin")
        enc = os.path.join(td, "cipher.enc")
        create_random_file(src, 1024)
        ensure_ok(run_cli(ctx, ["--encrypt", "--path", src, "--out", enc, "--key", "k"]))
        rc = run_cli(ctx, ["--decrypt", "--path", enc, "--out", os.path.join(td, "x"), "--key", "k", "--padding-size", "2KB"])
        ensure_fail(rc)


def test_key_and_keyfile_mutually_exclusive(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "plain.bin")
        enc = os.path.join(td, "cipher.enc")
        keyf = os.path.join(td, "k.bin")
        create_random_file(src, 1024)
        create_random_file(keyf, 1024)
        rc = run_cli(
            ctx,
            ["--encrypt", "--path", src, "--out", enc, "--key", "k1", "--key-file", keyf, "--protocol", "aes"],
        )
        ensure_fail(rc)


def test_fast_flag_roundtrip(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "plain.bin")
        enc = os.path.join(td, "cipher.enc")
        dec = os.path.join(td, "restored.bin")
        create_random_file(src, 16384)
        ensure_ok(run_cli(ctx, ["--encrypt", "--path", src, "--out", enc, "--key", "k", "--fast"]))
        ensure_ok(run_cli(ctx, ["--decrypt", "--path", enc, "--out", dec, "--key", "k", "--fast"]))
        assert_equal(sha256_file(src), sha256_file(dec), "fast-flag roundtrip mismatch")


def test_missing_mode(ctx):
    rc = run_cli(ctx, [])
    ensure_fail(rc)


def test_both_modes(ctx):
    rc = run_cli(ctx, ["--encrypt", "--decrypt", "--path", "x", "--out", "y", "--key", "k"])
    ensure_fail(rc)


def test_encrypt_missing_path_and_text(ctx):
    rc = run_cli(ctx, ["--encrypt", "--out", "x", "--key", "k"])
    ensure_fail(rc)


def test_encrypt_both_path_and_text(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "a.bin")
        create_random_file(src, 64)
        rc = run_cli(ctx, ["--encrypt", "--path", src, "--text", "abc", "--out", "x", "--key", "k"])
        ensure_fail(rc)


def test_missing_key(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "a.bin")
        enc = os.path.join(td, "a.enc")
        create_random_file(src, 64)
        rc = run_cli(ctx, ["--encrypt", "--path", src, "--out", enc])
        ensure_fail(rc)


def test_invalid_protocol(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "a.bin")
        enc = os.path.join(td, "a.enc")
        create_random_file(src, 64)
        rc = run_cli(ctx, ["--encrypt", "--path", src, "--out", enc, "--key", "k", "--protocol", "badproto"])
        ensure_fail(rc)


def test_decrypt_missing_path(ctx):
    rc = run_cli(ctx, ["--decrypt", "--out", "x", "--key", "k"])
    ensure_fail(rc)


def test_missing_encrypted_file(ctx):
    with tempfile.TemporaryDirectory() as td:
        dec = os.path.join(td, "out.bin")
        rc = run_cli(ctx, ["--decrypt", "--path", os.path.join(td, "missing.enc"), "--out", dec, "--key", "k"])
        ensure_fail(rc)


def test_wrong_key_generic_auth_failure(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "plain.bin")
        enc = os.path.join(td, "cipher.enc")
        dec = os.path.join(td, "out.bin")
        create_random_file(src, 2048)
        ensure_ok(run_cli(ctx, ["--encrypt", "--path", src, "--out", enc, "--key", "correct-key"]))
        rc = run_cli(ctx, ["--decrypt", "--path", enc, "--out", dec, "--key", "wrong-key"])
        ensure_fail(rc)
        stderr = rc.stderr.strip()
        assert_true("Authentication Failed" in stderr, f"expected generic auth failure, got stderr={stderr}")


def test_wrong_key_generic_auth_failure_all_passphrase_protocols(ctx):
    protocols = ["aes", "pq", "chacha20poly1305", "xchacha20poly1305", "serpent-256"]
    with tempfile.TemporaryDirectory() as td:
        for protocol in protocols:
            src = os.path.join(td, f"{protocol}.plain.bin")
            enc = os.path.join(td, f"{protocol}.cipher.enc")
            dec = os.path.join(td, f"{protocol}.out.bin")
            create_random_file(src, 1536)
            ensure_ok(run_cli(ctx, ["--encrypt", "--path", src, "--out", enc, "--key", "correct-key", "--protocol", protocol]))
            rc = run_cli(ctx, ["--decrypt", "--path", enc, "--out", dec, "--key", "wrong-key"])
            ensure_fail(rc)
            stderr = rc.stderr.strip()
            assert_true(
                "Authentication Failed" in stderr,
                f"expected generic auth failure for protocol={protocol}, got stderr={stderr}",
            )


def test_invalid_then_valid_process(ctx):
    bad = run_cli(ctx, ["--encrypt"])
    ensure_fail(bad)
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "ok.bin")
        enc = os.path.join(td, "ok.enc")
        dec = os.path.join(td, "ok.dec")
        create_random_file(src, 512)
        ensure_ok(run_cli(ctx, ["--encrypt", "--path", src, "--out", enc, "--key", "k"]))
        ensure_ok(run_cli(ctx, ["--decrypt", "--path", enc, "--out", dec, "--key", "k"]))
        assert_equal(sha256_file(src), sha256_file(dec), "follow-up valid flow failed after invalid invocation")


def test_large_directory_portability(ctx):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src")
        site_b = os.path.join(td, "site_b")
        os.makedirs(src, exist_ok=True)
        os.makedirs(site_b, exist_ok=True)
        build_nested_fixture(src, large=True)

        enc = os.path.join(td, "large_dir.enc")
        moved_enc = os.path.join(site_b, "large_dir.enc")
        out = os.path.join(site_b, "out")

        ensure_ok(run_cli(ctx, ["--encrypt", "--path", src, "--out", enc, "--key", "big-key", "--protocol", "aes"]))
        shutil.copy2(enc, moved_enc)
        ensure_ok(run_cli(ctx, ["--decrypt", "--path", moved_enc, "--out", out, "--key", "big-key"]))
        assert_equal(snapshot_dir(src), snapshot_dir(out), "large directory snapshot mismatch")


def test_keygen_words_default(ctx):
    rc = run_cli(ctx, ["--gen-key", "words"])
    ensure_ok(rc)
    words = [word for word in rc.stdout.strip().split() if word]
    assert_equal(len(words), 32, "default words key count mismatch")
    for word in words:
        assert_true(word.strip() == word and len(word) > 0, f"invalid word token in output: {word}")


def test_keygen_chars_default(ctx):
    rc = run_cli(ctx, ["--gen-key", "chars"])
    ensure_ok(rc)
    key = rc.stdout.strip()
    assert_equal(len(key), 43, "default chars key length mismatch")
    assert_true(re.match(r"^[a-zA-Z0-9*!]{43}$", key) is not None, "chars key contains invalid character")


def test_keygen_words_custom_count(ctx):
    rc = run_cli(ctx, ["gen-key", "words", "--count", "16"])
    ensure_ok(rc)
    words = [word for word in rc.stdout.strip().split() if word]
    assert_equal(len(words), 16, "custom words key count mismatch")


def test_keygen_chars_custom_length(ctx):
    rc = run_cli(ctx, ["gen-key", "chars", "--length", "64"])
    ensure_ok(rc)
    key = rc.stdout.strip()
    assert_equal(len(key), 64, "custom chars key length mismatch")
    assert_true(re.match(r"^[a-zA-Z0-9*!]{64}$", key) is not None, "custom chars key contains invalid character")


def test_keygen_missing_mode_rejected(ctx):
    rc = run_cli(ctx, ["--gen-key"])
    ensure_fail(rc)


def test_keygen_invalid_mode_option_combo(ctx):
    rc = run_cli(ctx, ["gen-key", "words", "--length", "10"])
    ensure_fail(rc)


def test_delete_file_success(ctx):
    with tempfile.TemporaryDirectory() as td:
        victim = os.path.join(td, "victim.bin")
        create_random_file(victim, 4096)
        rc = run_cli(ctx, ["delete", "--path", victim, "--passes", "3"])
        ensure_ok(rc)
        assert_true(not os.path.exists(victim), "delete command did not remove file")


def test_delete_missing_path_rejected(ctx):
    rc = run_cli(ctx, ["delete"])
    ensure_fail(rc)


def test_delete_invalid_passes_rejected(ctx):
    with tempfile.TemporaryDirectory() as td:
        victim = os.path.join(td, "victim.bin")
        create_random_file(victim, 64)
        rc = run_cli(ctx, ["delete", "--path", victim, "--passes", "0"])
        ensure_fail(rc)


def test_help_lists_core_flags(ctx):
    rc = run_cli(ctx, ["--help"])
    ensure_ok(rc)
    output = rc.stdout
    required = [
        "--encrypt",
        "--decrypt",
        "--path",
        "--text",
        "--out",
        "--key",
        "--key-file",
        "--protocol",
        "--padding-size",
        "--gen-key",
        "--list-protocols",
        "--fast",
        "safeanar delete --path",
    ]
    for token in required:
        assert_true(token in output, f"missing help token: {token}")


def test_list_protocols_command(ctx):
    expected_tokens = [
        "aes",
        "otp",
        "pq",
        "chacha20poly1305",
        "xchacha20poly1305",
        "serpent-256",
    ]
    for args in (["--list-protocols"], ["protocols"]):
        rc = run_cli(ctx, args)
        ensure_ok(rc)
        output = rc.stdout
        for token in expected_tokens:
            assert_true(token in output, f"missing protocol token {token} in output for args={args}")


def build_tests():
    return [
        ("AK4-E2E-001", "File encrypt/decrypt round-trip", test_file_roundtrip, False),
        ("AK4-E2E-002", "Text encrypt/decrypt round-trip", test_text_roundtrip, False),
        ("AK4-E2E-003", "Directory portability workflow", test_directory_portability, False),
        ("AK4-E2E-004", "Default protocol works", test_default_protocol, False),
        ("AK4-E2E-007", "PQ protocol round-trip", test_pq_protocol_roundtrip, False),
        ("AK4-E2E-008", "ChaCha20/Poly1305 round-trip", test_chacha20poly1305_roundtrip, False),
        ("AK4-E2E-009", "XChaCha20/Poly1305 round-trip", test_xchacha20poly1305_roundtrip, False),
        ("AK4-E2E-010", "Serpent-256 round-trip", test_serpent256_roundtrip, False),
        ("AK4-E2E-021", "Quoted --path/--out values with whitespace work", test_quoted_path_and_out_values, False),
        ("AK4-E2E-022", "Unicode paths round-trip", test_unicode_path_roundtrip, False),
        ("AK4-E2E-005", "Explicit OTP protocol with key-file works", test_otp_protocol, False),
        ("AK4-E2E-006", "OTP with passphrase is rejected", test_otp_with_passphrase_rejected, False),
        ("AK4-FLG-001", "Key-file AES round-trip", test_keyfile_aes_roundtrip, False),
        ("AK4-FLG-002", "Key-file OTP round-trip", test_keyfile_otp_roundtrip, False),
        ("AK4-FLG-003", "OTP key-file short rejected", test_keyfile_otp_too_short_rejected, False),
        ("AK4-FLG-004", "Padding-size exact output and round-trip", test_padding_size_roundtrip_and_exact_size, False),
        ("AK4-FLG-005", "Padding-size too small rejected", test_padding_size_too_small_rejected, False),
        ("AK4-FLG-006", "Padding-size decrypt rejected", test_padding_size_with_decrypt_rejected, False),
        ("AK4-FLG-007", "Key and key-file exclusivity enforced", test_key_and_keyfile_mutually_exclusive, False),
        ("AK4-FLG-008", "Fast flag accepted for round-trip", test_fast_flag_roundtrip, False),
        ("AK4-CLI-010", "Missing mode rejected", test_missing_mode, False),
        ("AK4-CLI-011", "Both modes rejected", test_both_modes, False),
        ("AK4-CLI-012", "Encrypt missing --path/--text rejected", test_encrypt_missing_path_and_text, False),
        ("AK4-CLI-013", "Encrypt with both --path and --text rejected", test_encrypt_both_path_and_text, False),
        ("AK4-CLI-014", "Missing key rejected", test_missing_key, False),
        ("AK4-CLI-015", "Invalid protocol rejected", test_invalid_protocol, False),
        ("AK4-CLI-016", "Decrypt missing input path rejected", test_decrypt_missing_path, False),
        ("AK4-CLI-017", "Missing encrypted file rejected", test_missing_encrypted_file, False),
        ("AK4-SEC-001", "Wrong key fails generically", test_wrong_key_generic_auth_failure, False),
        (
            "AK4-SEC-003",
            "Wrong key fails generically for all passphrase protocols",
            test_wrong_key_generic_auth_failure_all_passphrase_protocols,
            False,
        ),
        ("AK4-SEC-002", "Invalid input does not crash follow-up valid flow", test_invalid_then_valid_process, False),
        ("AK4-KEY-001", "Keygen words default count", test_keygen_words_default, False),
        ("AK4-KEY-002", "Keygen chars default length", test_keygen_chars_default, False),
        ("AK4-KEY-003", "Keygen words custom count", test_keygen_words_custom_count, False),
        ("AK4-KEY-004", "Keygen chars custom length", test_keygen_chars_custom_length, False),
        ("AK4-KEY-005", "Keygen missing mode rejected", test_keygen_missing_mode_rejected, False),
        ("AK4-KEY-010", "Keygen invalid option combo rejected", test_keygen_invalid_mode_option_combo, False),
        ("AK4-DEL-001", "Delete command removes target file", test_delete_file_success, False),
        ("AK4-DEL-002", "Delete command missing path rejected", test_delete_missing_path_rejected, False),
        ("AK4-DEL-003", "Delete command invalid passes rejected", test_delete_invalid_passes_rejected, False),
        ("AK4-HLP-001", "Help lists core flags", test_help_lists_core_flags, False),
        ("AK4-HLP-002", "Protocol list command", test_list_protocols_command, False),
        ("AK4-E2E-020", "Large directory portability", test_large_directory_portability, True),
    ]


def main():
    parser = argparse.ArgumentParser(description="SafeAnar Phase 4 CLI Test Runner")
    parser.add_argument(
        "--cli",
        default=os.path.join(os.path.dirname(__file__), "adapters", "phase4_cli_ref.py"),
        help="Path to CLI executable or Python script implementing safeanar CLI",
    )
    parser.add_argument("--cli-arg", action="append", default=[], help="Extra args inserted before command args")
    parser.add_argument("--include-slow", action="store_true")
    parser.add_argument("--list-tests", action="store_true")
    args = parser.parse_args()

    tests = build_tests()
    if args.list_tests:
        for tid, desc, _, slow in tests:
            tag = " (slow)" if slow else ""
            print(f"{tid}{tag} - {desc}")
        return 0

    cli_cmd = [sys.executable, args.cli] if args.cli.endswith(".py") else [args.cli]
    cli_cmd.extend(args.cli_arg)
    ctx = {"cli_cmd": cli_cmd}

    passed = 0
    failed = 0
    skipped = 0

    for tid, desc, fn, slow in tests:
        if slow and not args.include_slow:
            skipped += 1
            print(f"SKIP {tid} - {desc}")
            continue
        try:
            fn(ctx)
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


if __name__ == "__main__":
    sys.exit(main())
