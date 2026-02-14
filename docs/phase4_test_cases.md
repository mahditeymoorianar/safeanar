# Phase 4 Test Cases - Integration & CLI (TDD Spec)

**Source:** Section 6 and Section 7 (Phase 4) of `docs/vision_document.md`.

This document defines executable CLI tests for integration of library components into the command-line interface.

## Scope
- Argument parsing and validation for all CLI flags from the vision document:
  - `--encrypt`, `--decrypt`
  - `--path`, `--text`, `--out`
  - `--key`, `--key-file`, `--protocol`
  - `--padding-size`, `--fast`
  - `--gen-key` (`words`, `chars`, plus count/length options)
- End-to-end encryption/decryption workflows (file, text, directory)
- Cross-location portability simulation (copy encrypted artifact, decrypt elsewhere)
- Generic authentication failure behavior for wrong keys
- Secure delete subcommand behavior (`safeanar delete --path <file> [--passes N]`)

## CLI Contract Under Test
Commands:
- `safeanar --encrypt --path <input> --out <enc> (--key <k>|--key-file <kf>) [--protocol aes|otp|pq|chacha20poly1305|xchacha20poly1305|serpent-256] [--padding-size <size>] [--fast]`
- `safeanar --encrypt --text <text> --out <enc> (--key <k>|--key-file <kf>) [--protocol aes|otp|pq|chacha20poly1305|xchacha20poly1305|serpent-256] [--padding-size <size>] [--fast]`
- `safeanar --decrypt --path <enc> --out <output> (--key <k>|--key-file <kf>) [--fast]`
- `safeanar --gen-key <words|chars> [--count N|--length N]`
- `safeanar gen-key <words|chars> [--count N|--length N]`
- `safeanar --list-protocols`
- `safeanar protocols`
- `safeanar delete --path <file> [--passes N]`

General behavior:
- Exactly one of `--encrypt` / `--decrypt` must be set.
- `--protocol` defaults to `aes` if omitted.
- For `--encrypt`, exactly one of `--path` / `--text` is required.
- For `--decrypt`, `--path` is required and `--text` is invalid.
- Exactly one of `--key` / `--key-file` is required for encrypt/decrypt.
- For `--protocol otp`, `--key-file` is mandatory.
- Error messages should not leak sensitive details.

## Test Cases

### E2E Integration
| ID | Description | Input | Expected |
| --- | --- | --- | --- |
| AK4-E2E-001 | File encrypt/decrypt round-trip | Encrypt file with `--path`, decrypt to file | SHA-256(original) == SHA-256(decrypted) |
| AK4-E2E-002 | Text encrypt/decrypt round-trip | Encrypt with `--text`, decrypt to output text file | UTF-8 content matches original text |
| AK4-E2E-003 | Directory portability workflow | Encrypt directory, copy ciphertext to second location, decrypt there | Full directory snapshot matches |
| AK4-E2E-004 | Default protocol works | Omit `--protocol` on encrypt/decrypt | Successful round-trip |
| AK4-E2E-005 | Explicit OTP protocol works | Use `--protocol otp` with `--key-file` | Successful round-trip |
| AK4-E2E-006 | OTP passphrase rejected | Use `--protocol otp` with `--key` | Non-zero exit, generic requirement error |
| AK4-E2E-007 | Explicit PQ protocol works | Use `--protocol pq` with passphrase key | Successful round-trip |
| AK4-E2E-008 | ChaCha20/Poly1305 round-trip | Use `--protocol chacha20poly1305` | Successful round-trip |
| AK4-E2E-009 | XChaCha20/Poly1305 round-trip | Use `--protocol xchacha20poly1305` | Successful round-trip |
| AK4-E2E-010 | Serpent-256 round-trip | Use `--protocol serpent-256` | Successful round-trip |

### Flags and Parsing
| ID | Description | Input | Expected |
| --- | --- | --- | --- |
| AK4-FLG-001 | Key-file AES round-trip | `--key-file` with `--protocol aes` | Successful round-trip |
| AK4-FLG-002 | Key-file OTP round-trip | `--key-file` with `--protocol otp` | Successful round-trip |
| AK4-FLG-003 | OTP key-file short rejected | Key-file shorter than plaintext | Non-zero exit (`KeyTooShort`) |
| AK4-FLG-004 | Padding-size exact output and round-trip | `--padding-size 200KB` | Output size exact and decrypts correctly |
| AK4-FLG-005 | Padding-size too small rejected | Target below required minimum | Non-zero exit |
| AK4-FLG-006 | Padding-size decrypt rejected | `--padding-size` with `--decrypt` | Non-zero exit |
| AK4-FLG-007 | Key and key-file exclusivity | `--key` and `--key-file` together | Non-zero exit |
| AK4-FLG-008 | Fast flag accepted | `--fast` for encrypt/decrypt | Successful round-trip |

### CLI Validation
| ID | Description | Input | Expected |
| --- | --- | --- | --- |
| AK4-CLI-010 | Missing mode rejected | No `--encrypt`/`--decrypt` | Non-zero exit |
| AK4-CLI-011 | Both modes rejected | `--encrypt --decrypt` | Non-zero exit |
| AK4-CLI-012 | Encrypt missing `--path/--text` | `--encrypt` without both | Non-zero exit |
| AK4-CLI-013 | Encrypt with both `--path` and `--text` | Both provided | Non-zero exit |
| AK4-CLI-014 | Missing key material rejected | Encrypt/decrypt without key or key-file | Non-zero exit |
| AK4-CLI-015 | Invalid protocol rejected | `--protocol bad` | Non-zero exit |
| AK4-CLI-016 | Decrypt missing input path rejected | `--decrypt` without `--path` | Non-zero exit |
| AK4-CLI-017 | Missing encrypted file rejected | `--decrypt --path` non-existing | Non-zero exit |

### Security/Error Behavior
| ID | Description | Input | Expected |
| --- | --- | --- | --- |
| AK4-SEC-001 | Wrong key fails generically | Decrypt valid ciphertext with wrong key | Non-zero exit; message contains `Authentication Failed` |
| AK4-SEC-003 | Wrong key fails generically across passphrase protocols | Repeat wrong-key decrypt for `aes`, `pq`, `chacha20poly1305`, `xchacha20poly1305`, `serpent-256` | Non-zero exit; message contains `Authentication Failed` for each |
| AK4-SEC-002 | Invalid invocation recovery | Invalid CLI invocation then valid one | Process remains stable; valid invocation succeeds |

### Key Generation
| ID | Description | Input | Expected |
| --- | --- | --- | --- |
| AK4-KEY-001 | Keygen words default count | `--gen-key words` | 32 words |
| AK4-KEY-002 | Keygen chars default length | `--gen-key chars` | 43 chars from `[a-zA-Z0-9*!]` |
| AK4-KEY-003 | Keygen words custom count | `gen-key words --count 16` | 16 words |
| AK4-KEY-004 | Keygen chars custom length | `gen-key chars --length 64` | 64 valid chars |
| AK4-KEY-005 | Keygen missing mode rejected | `--gen-key` | Non-zero exit |
| AK4-KEY-010 | Keygen invalid mode-option combo | `gen-key words --length 10` | Non-zero exit |

### Delete Command
| ID | Description | Input | Expected |
| --- | --- | --- | --- |
| AK4-DEL-001 | Delete command removes file | `delete --path <file> --passes 3` | Exit 0, target removed |
| AK4-DEL-002 | Delete command missing path rejected | `delete` | Non-zero exit |
| AK4-DEL-003 | Delete command invalid passes rejected | `delete --path <file> --passes 0` | Non-zero exit |

### Help Surface
| ID | Description | Input | Expected |
| --- | --- | --- | --- |
| AK4-HLP-001 | Help lists core flags | `--help` | Output includes all core vision flags and delete usage |
| AK4-HLP-002 | Protocol list command | `--list-protocols` and `protocols` | Output includes all supported protocol names |

### Slow / Nightly
| ID | Description | Input | Expected |
| --- | --- | --- | --- |
| AK4-E2E-020 | Large directory portability | Directory containing >=16 MiB binary file | Snapshot matches after cross-location decrypt |

## Notes
- `AK4-E2E-020` runs under `--include-slow`.
- "Different OS/filesystem" is simulated locally by decrypting in a different root directory after copying the encrypted artifact.
