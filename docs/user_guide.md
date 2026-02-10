# SafeAnar User Guide

SafeAnar is a CLI tool for encrypting and decrypting files, directories, and text.

This repository currently contains a Phase 1-4 prototype (see `docs/vision_document.md`). The CLI exists and is tested.

## Quick Start

Build (Windows/MinGW example):

```bash
cmake -S . -B cmake-build-debug
cmake --build cmake-build-debug --config Debug -j
```

Run help:

```bash
cmake-build-debug/safeanar.exe --help
```

## Command Summary

### Encrypt a File

```bash
safeanar --encrypt --path secret.bin --out secret.enc --key "my passphrase" --protocol aes
```

### Decrypt a File

```bash
safeanar --decrypt --path secret.enc --out secret.dec --key "my passphrase"
```

### Encrypt/Decrypt with a Key File

```bash
safeanar --encrypt --path secret.bin --out secret.enc --key-file my.key --protocol otp
safeanar --decrypt --path secret.enc --out secret.dec --key-file my.key
```

For `--protocol otp`, the key file must be at least as large as the input data.

### Encrypt Text

```bash
safeanar --encrypt --text "hello" --out message.enc --key "my passphrase"
```

### Decrypt Text

Decryption always writes to `--out` (a file path). For ciphertext created from `--text`, the output is the original UTF-8 bytes.

```bash
safeanar --decrypt --path message.enc --out message.txt --key "my passphrase"
```

### Encrypt a Directory

```bash
safeanar --encrypt --path my_folder --out folder.enc --key "my passphrase"
```

### Decrypt a Directory

When decrypting a directory ciphertext, `--out` is treated as an output directory.

```bash
safeanar --decrypt --path folder.enc --out restored_folder --key "my passphrase"
```

### Encrypt with Padding Size

```bash
safeanar --encrypt --path secret.bin --out secret.pad.enc --key "my passphrase" --padding-size 100MB
```

`--padding-size` accepts bytes or decimal units: `KB`, `MB`, `GB`, `TB` (for example: `100MB`, `1GB`).

### Secure Delete a File

```bash
safeanar delete --path old_secret.bin
```

Optional overwrite passes:

```bash
safeanar delete --path old_secret.bin --passes 9
```

### Generate a Word-Based Key

```bash
safeanar --gen-key words
```

Optional word count:

```bash
safeanar gen-key words --count 16
```

### Generate a Character-Based Key

```bash
safeanar --gen-key chars
```

Optional length:

```bash
safeanar gen-key chars --length 64
```

## CLI Reference

### Modes
- `--encrypt` Encrypt input (`--path` or `--text`) to `--out`.
- `--decrypt` Decrypt ciphertext from `--path` to `--out`.

Exactly one of `--encrypt` or `--decrypt` is required.

### Delete Subcommand
- `delete --path <file>` Securely delete a regular file with multi-pass overwrite.
- `delete --path <file> --passes <N>` Set overwrite pass count (default: `7`).

`delete` is a subcommand, so it is used as:

```bash
safeanar delete --path file.bin
```

### Key Generation
- `--gen-key words` Generate a random space-separated passphrase with `32` words by default.
- `words` mode uses a fixed built-in 256-word dictionary.
- `--gen-key chars` Generate a random passphrase with `43` characters by default.
- `chars` mode uses this exact alphabet: `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789*!`
- `gen-key words --count <N>` Override the number of generated words.
- `gen-key chars --length <N>` Override the generated character length.

Both invocation styles are supported:

```bash
safeanar --gen-key words
safeanar gen-key words
```

### Inputs
- `--path <path>` Input path (file or directory for encrypt; encrypted file for decrypt).
- `--text <text>` Input text (encrypt only).

For `--encrypt`, exactly one of `--path` or `--text` is required.

### Output
- `--out <path>` Output destination.
  - For `--encrypt`, this is the encrypted file path.
  - For `--decrypt`, this is:
    - a file path if ciphertext contains a file or text
    - a directory path if ciphertext contains a directory

### Key
- `--key <string>` Passphrase string.
- `--key-file <path>` Raw key bytes from a file.

Exactly one of `--key` or `--key-file` is required for encrypt/decrypt.

### Protocol
- `--protocol aes` (default)
- `--protocol otp`

In this prototype build:
- `aes` uses AES-256 in CTR mode.
- `otp` uses direct byte-for-byte XOR and requires `--key-file`.
- For `otp`, key-file size must be at least payload size.
- Integrity tag is `SHA-256(prepared_key || plaintext)` for both modes.

### Padding
- `--padding-size <size>` Sets exact encrypted output size during `--encrypt`.
- Supported suffixes are `B`, `KB`, `MB`, `GB`, `TB` (decimal units).
- `--padding-size` is only valid with `--encrypt`.

### Fast Flag
- `--fast` enables fast-path hinting when available.
- Current prototype behavior is output-compatible with non-fast mode.

## Errors and Exit Codes

SafeAnar returns:
- `0` on success
- non-zero on failure

Common errors:
- `InvalidPath` Input ciphertext or plaintext path does not exist or is invalid.
- `InvalidArchive` Encrypted container or packed directory format is invalid.
- `Authentication Failed` Wrong key for ciphertext (generic failure).
- `FileIOError` File read/write failure.
- `InvalidLength` Invalid numeric input (for example, `--passes 0`).

## Security Notes (Prototype)

This Phase 4 CLI is a test-driven prototype focused on integration and argument parsing.

If you need real cryptographic security, do not treat this prototype encryption scheme as final:
- The current container authentication is a simple SHA-256 tag, not a modern AEAD construction.
- OTP safety depends fully on key-file randomness and strict one-time usage discipline.
- The `--fast` flag is a compatibility hint; no hardware-specific acceleration path is exposed yet.

Secure delete limitations:
- Secure delete is best effort only.
- Filesystem journaling, SSD wear-leveling, snapshots, cloud sync, backups, and OS-level caching can preserve copies that direct overwrite cannot fully control.
- If your threat model is strict forensic recovery resistance, combine this with full-disk encryption and controlled storage lifecycle practices.

## Testing

All phases have executable test runners:

```bash
python tests/phase1_runner.py --adapter cmake-build-debug/anar_key_adapter.exe
python tests/phase2_runner.py --adapter cmake-build-debug/phase2_crypto_adapter.exe
python tests/phase3_runner.py --adapter cmake-build-debug/phase3_stream_adapter.exe
python tests/phase4_runner.py --cli cmake-build-debug/safeanar.exe
```
