# Tests

## Phase 1 Runner

Run:

```bash
python tests/phase1_runner.py
```

Optional flags:
- `--include-slow` runs the statistical RNG tests.
- `--adapter <path>` runs a custom adapter (for the future C++ implementation).
- `--dictionary <path>` uses a different 256-word dictionary file.
- `--list-tests` prints test IDs.

## Adapter Protocol (JSON Lines)

The runner talks to an adapter process over stdin/stdout using one JSON object per line.

Requests:
- `{"op":"ping"}`
- `{"op":"derive_words","dictionary_path":"...","passphrase":"..."}`
- `{"op":"derive_chars","alphabet":"...","passphrase":"..."}`
- `{"op":"gen_words","dictionary_path":"...","mode":"stub"|"system","rng_bytes_hex":"...","count":32}`
- `{"op":"gen_keys","dictionary_path":"...","mode":"system","count":10000}`

Responses:
- Success: `{"ok":true, ...}`
- Error: `{"ok":false,"error":"InvalidWord"|"InvalidChar"|"InvalidLength"|"InvalidDictionary"}`

Notes:
- `derive_chars` must implement 6-bit MSB-first packing and discard the final 2 bits.
- The reference adapter is `tests/adapters/anar_key_ref.py`.

## Phase 2 Runner

Run:

```bash
python tests/phase2_runner.py
```

Optional flags:
- `--include-slow` runs large-file OTP tests.
- `--adapter <path>` runs a custom adapter (for the future C++ crypto engine).
- `--list-tests` prints test IDs.

Reference adapter:
- `tests/adapters/phase2_crypto_ref.py`

Phase 2 Adapter Requests:
- `{"op":"ping"}`
- `{"op":"aes256_ecb_encrypt","key_hex":"...","plaintext_hex":"..."}`
- `{"op":"aes256_ecb_decrypt","key_hex":"...","ciphertext_hex":"..."}`
- `{"op":"otp_xor_bytes","data_hex":"...","key_hex":"..."}`
- `{"op":"otp_xor_file","input_path":"...","key_path":"...","output_path":"..."}`

Phase 2 Adapter Responses:
- Success: `{"ok":true, ...}`
- Error: `{"ok":false,"error":"InvalidKeyLength"|"InvalidBlockLength"|"BadHex"|"KeyTooShort"|"FileIOError"}`

## Phase 3 Runner

Run:

```bash
python tests/phase3_runner.py
```

Optional flags:
- `--include-slow` runs large-file and `1_000_000_000`-byte padding tests.
- `--adapter <path>` runs a custom adapter (for the future C++ StreamPacker).
- `--list-tests` prints test IDs.

Reference adapter:
- `tests/adapters/phase3_stream_ref.py`

Phase 3 Adapter Requests:
- `{"op":"ping"}`
- `{"op":"pack_path","input_path":"...","output_path":"..."}`
- `{"op":"inspect_archive","input_path":"..."}`
- `{"op":"unpack_path","input_path":"...","output_dir":"..."}`
- `{"op":"pad_file","input_path":"...","output_path":"...","target_size":1000000}`
- `{"op":"inspect_padded","input_path":"..."}`
- `{"op":"unpad_file","input_path":"...","output_path":"..."}`

Phase 3 Adapter Responses:
- Success: `{"ok":true, ...}`
- Error: `{"ok":false,"error":"InvalidPath"|"InvalidArchive"|"InvalidPaddingTarget"|"CorruptInput"|"FileIOError"}`

## Phase 4 Runner

Run:

```bash
python tests/phase4_runner.py
```

Optional flags:
- `--include-slow` runs large directory portability test.
- `--cli <path>` points to CLI executable or script under test.
- `--cli-arg <arg>` appends extra args before command args.
- `--list-tests` prints test IDs.

Reference CLI:
- `tests/adapters/phase4_cli_ref.py`

Phase 4 tests execute real CLI invocations (not JSON ops) and validate:
- all core vision flags (`--encrypt`, `--decrypt`, `--path`, `--text`, `--out`, `--key`, `--key-file`, `--protocol`, `--padding-size`, `--fast`, `--gen-key`)
- file/text/directory end-to-end flows
- key generation behavior (words/chars, defaults and custom lengths)
- secure delete subcommand behavior
- cross-location decrypt portability
- generic wrong-key authentication failure behavior
