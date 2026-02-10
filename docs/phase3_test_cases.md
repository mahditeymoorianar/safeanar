# Phase 3 Test Cases - StreamPacker & Padding (TDD Spec)

**Source:** Section 7 (Phase 3) of `docs/vision_document.md`.

This document defines executable test cases for stream packing (tar-like archive) and padding/obfuscation behavior.

## Scope
- Folder/file serialization into a deterministic stream archive
- Stream extraction back to filesystem with integrity checks
- Padding container creation/unpadding with exact-size requirements
- Corruption and partial-write fault tolerance

## Adapter Contract
Phase 3 tests use a JSON-lines adapter process over stdin/stdout.

Requests:
- `{"op":"ping"}`
- `{"op":"pack_path","input_path":"...","output_path":"..."}`
- `{"op":"inspect_archive","input_path":"..."}`
- `{"op":"unpack_path","input_path":"...","output_dir":"..."}`
- `{"op":"pad_file","input_path":"...","output_path":"...","target_size":1000000}`
- `{"op":"inspect_padded","input_path":"..."}`
- `{"op":"unpad_file","input_path":"...","output_path":"..."}`

Success response examples:
- `{"ok":true}`
- `{"ok":true,"entry_count":3,"bytes_written":12345}`
- `{"ok":true,"entries":[{"path":"a.txt","size":10}]}`
- `{"ok":true,"real_size":1048576,"total_size":1000000}`
- `{"ok":true,"bytes_written":1048576}`

Error response:
- `{"ok":false,"error":"<ErrorCode>"}`

## Error Codes Expected By Tests
- `InvalidPath`
- `InvalidArchive`
- `InvalidPaddingTarget`
- `CorruptInput`
- `FileIOError`

## Test Cases

### Stream Packing / Unpacking
| ID | Description | Input | Expected |
| --- | --- | --- | --- |
| AK3-SP-001 | Single-file round-trip integrity | Pack file, unpack to dir | Hash and size match original |
| AK3-SP-002 | Nested directory round-trip integrity | Pack nested dir (text+binary+empty files), unpack | Full tree snapshot matches |
| AK3-SP-003 | Archive inspection deterministic order | Pack directory twice | `inspect_archive.entries` stable lexical order |

### Stream Validation / Edge Cases
| ID | Description | Input | Expected |
| --- | --- | --- | --- |
| AK3-SP-010 | Missing input path rejected | `pack_path` on non-existing path | `InvalidPath` |
| AK3-SP-011 | Corrupt archive rejected | Random bytes as archive | `InvalidArchive` or `CorruptInput` |
| AK3-SP-012 | Path traversal entry rejected on unpack | Archive entry like `../evil.txt` | `InvalidArchive` or `CorruptInput`; no traversal write |

### Padding Accuracy & Integrity
| ID | Description | Input | Expected |
| --- | --- | --- | --- |
| AK3-PAD-001 | Padding accuracy (regular) | Pad 1 MiB file to 10 MiB | Output size exactly target |
| AK3-PAD-002 | Unpad restores original bytes | Unpad padded container | SHA-256 matches original file |
| AK3-PAD-003 | Too-small target rejected | `target_size < payload` | `InvalidPaddingTarget` |
| AK3-PAD-004 | Zero-length payload support | Empty file with non-zero target | Success; unpadded output size 0 |
| AK3-PAD-005 | Corrupt padded container rejected | Mutated header/magic | `InvalidArchive` or `CorruptInput` |

### Integrity / Partial Write Fault Tolerance
| ID | Description | Input | Expected |
| --- | --- | --- | --- |
| AK3-INT-001 | Truncated padded file handled gracefully | Truncate padded file, then unpad | `CorruptInput`/`InvalidArchive`/`FileIOError`, process remains alive |
| AK3-INT-002 | No exceptions on invalid requests | Invalid archive/padding input | Error response, adapter still responds to `ping` |
| AK3-INT-003 | Interrupted write handling | Terminate adapter during long `pad_file` | Partial output does not crash follow-up parsing; returns handled error or valid complete output |

### Slow / Nightly
| ID | Description | Input | Expected |
| --- | --- | --- | --- |
| AK3-PAD-010 | Spec-sized padding accuracy | Pad 1 MiB file to exactly `1_000_000_000` bytes | Output size exactly `1_000_000_000` |
| AK3-SP-020 | Large-file stream round-trip | Pack/unpack large binary file (>=16 MiB) | Hash and size match |

## Notes
- `AK3-PAD-010` and `AK3-SP-020` should run under `--include-slow`.
- Corruption/partial-write tests focus on graceful failure and process survivability (no crash, no undefined behavior).
