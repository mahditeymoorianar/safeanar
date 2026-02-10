# Phase 2 Test Cases - Crypto Engine (TDD Spec)

**Source:** Section 7 (Phase 2) of `docs/vision_document.md`.

This document defines executable test cases for AES-256 and OTP before production implementation.

## Scope
- AES-256 correctness via Known Answer Tests (KAT)
- OTP XOR behavior (bytes and file flow)
- Input validation and edge-cases
- Determinism and error-code behavior

## Adapter Contract
Phase 2 tests use a JSON-lines adapter process over stdin/stdout.

Requests:
- `{"op":"ping"}`
- `{"op":"aes256_ecb_encrypt","key_hex":"...","plaintext_hex":"..."}`
- `{"op":"aes256_ecb_decrypt","key_hex":"...","ciphertext_hex":"..."}`
- `{"op":"otp_xor_bytes","data_hex":"...","key_hex":"..."}`
- `{"op":"otp_xor_file","input_path":"...","key_path":"...","output_path":"..."}`

Success responses:
- `{"ok":true}`
- `{"ok":true,"ciphertext_hex":"..."}`
- `{"ok":true,"plaintext_hex":"..."}`
- `{"ok":true,"result_hex":"..."}`
- `{"ok":true,"bytes_processed":123}`

Error response:
- `{"ok":false,"error":"<ErrorCode>"}`

## Error Codes Expected By Tests
- `InvalidKeyLength`
- `InvalidBlockLength`
- `BadHex`
- `KeyTooShort`
- `FileIOError`

## AES KAT Fixture
- NIST SP 800-38A, F.1 (AES-256 ECB)
- Key:
  - `603deb1015ca71be2b73aef0857d7781`
  - `1f352c073b6108d72d9810a30914dff4`
- Plaintext blocks:
  - `6bc1bee22e409f96e93d7e117393172a`
  - `ae2d8a571e03ac9c9eb76fac45af8e51`
  - `30c81c46a35ce411e5fbc1191a0a52ef`
  - `f69f2445df4f9b17ad2b417be66c3710`
- Ciphertext blocks:
  - `f3eed1bdb5d2a03c064b5a7e3db181f8`
  - `591ccb10d410ed26dc5ba74a31362870`
  - `b6ed21b99ca6f4f9f153e7b1beafed1d`
  - `23304b7a39f9f3ff067d8d8f9e24ecc7`

## Test Cases

### AES-256 KAT
| ID | Description | Input | Expected |
| --- | --- | --- | --- |
| AK2-AES-001 | NIST ECB single-block encrypt | Key + first plaintext block | First ciphertext block |
| AK2-AES-002 | NIST ECB multi-block encrypt | Key + all four plaintext blocks | Four ciphertext blocks concatenated |
| AK2-AES-003 | NIST ECB multi-block decrypt | Key + four ciphertext blocks | Four plaintext blocks concatenated |

### AES Validation / Edge Cases
| ID | Description | Input | Expected |
| --- | --- | --- | --- |
| AK2-AES-010 | Invalid key length rejected | 31-byte or 33-byte key | `InvalidKeyLength` |
| AK2-AES-011 | Non-block-aligned plaintext rejected | Plaintext length not multiple of 16 bytes | `InvalidBlockLength` |
| AK2-AES-012 | Bad hex rejected | Non-hex character in key or payload | `BadHex` |
| AK2-AES-013 | Deterministic encryption | Same key/plaintext twice | Same ciphertext |

### OTP Core Behavior
| ID | Description | Input | Expected |
| --- | --- | --- | --- |
| AK2-OTP-001 | Known XOR vector | `data=00112233`, `key=FFFFFFFF` | `result=FFEEDDCC` |
| AK2-OTP-002 | Symmetry on bytes | Encrypt with key, then XOR again with same key | Restored original bytes |
| AK2-OTP-003 | Key too short rejected (bytes) | Data longer than key | `KeyTooShort` |
| AK2-OTP-004 | Zero-length bytes input | Empty data/key | Success, empty output |

### OTP File Symmetry
| ID | Description | Input | Expected |
| --- | --- | --- | --- |
| AK2-OTP-010 | File round-trip hash equality | Random file + random key file (equal size), encrypt then decrypt | `SHA-256(original) == SHA-256(decrypted)` |
| AK2-OTP-011 | Key file too short rejected | Key file smaller than input file | `KeyTooShort` |
| AK2-OTP-012 | Empty file round-trip | Empty input + empty key | Success; output size 0 |
| AK2-OTP-013 | Missing file path handled | Non-existing input or key path | `FileIOError` |

### Common API Behavior
| ID | Description | Input | Expected |
| --- | --- | --- | --- |
| AK2-CO-001 | Ping health check | `{"op":"ping"}` | `{"ok":true}` |
| AK2-CO-002 | No exceptions on invalid input | Any invalid request above | Error response, process remains alive |

## Notes
- The runner marks large-file OTP tests as `slow` by default.
- KAT tests are strict byte-for-byte checks.
- Error messages should remain generic and avoid leaking sensitive internals.
