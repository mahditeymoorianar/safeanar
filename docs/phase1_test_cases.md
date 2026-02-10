# Phase 1 Test Cases - AnarKey (TDD Spec)

**Source:** Section 7 (Phase 1) of `docs/vision_document.md`.

This document defines the required test cases for Phase 1 (AnarKey). It is written as a TDD spec: code must be implemented to satisfy these tests.

## Scope
These tests cover:
- Word-based mapping (256-word dictionary -> 32-byte key)
- Character-based mapping (64-char alphabet -> 32-byte key)
- Input validation and edge-cases
- Random key generation sanity (collision/pattern checks)

## Assumptions (Make These Concrete in Code)
- Word mode requires exactly 32 words and returns exactly 32 bytes.
- Character mode requires exactly 43 characters and returns exactly 32 bytes.
- Word tokens are separated by ASCII whitespace. Leading/trailing whitespace is ignored.
- Word matching is case-insensitive (normalize to lowercase before lookup).
- Character mode does NOT trim or normalize; every character is significant.
- Character mapping uses 6-bit indices concatenated MSB-first into a bitstream; the first 256 bits form the key (extra 2 bits are discarded).
- Invalid inputs return an error status (no exceptions thrown in core).

If any assumption is incorrect, update both tests and implementation together.

## Test Fixtures
- Dictionary fixture: `test_dictionary_256.txt` contains 256 unique tokens `w000`..`w255` in ascending order.
  - Index equals numeric value. Example: `w000 -> 0x00`, `w255 -> 0xFF`.
- Character alphabet fixture (64 chars):
  - `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_` (Base64 URL-safe order)
  - Index equals position in this string.
- Deterministic RNG stub for generator tests: returns bytes 0x00..0xFF repeating.

## Test Cases

### Word-Based Mapping
| ID | Description | Input | Expected Result |
| --- | --- | --- | --- |
| AK-W-001 | Known mapping produces correct 256-bit key | 32 words: `w000 w001 ... w031` | 32 bytes `00 01 02 ... 1F` |
| AK-W-002 | Non-contiguous mapping is correct | 32 words: `w255 w128 w127 w000 ...` (mixed order) | Bytes match indices in order (first byte `FF`, second `80`, third `7F`, fourth `00`, ...) |
| AK-W-003 | Duplicate words allowed and map correctly | 32 words where `w005` repeats | Output contains repeated `0x05` at corresponding positions |
| AK-W-004 | Leading/trailing/multiple spaces are handled | Input with extra spaces/tabs/newlines between tokens | Same output as normalized single-space input |
| AK-W-005 | Case-insensitive matching | `W010 w011 W012 ...` | Same bytes as lowercase input |

### Word-Based Validation / Edge Cases
| ID | Description | Input | Expected Result |
| --- | --- | --- | --- |
| AK-W-010 | Unknown word rejected | Includes `w999` or `notaword` | Error status `InvalidWord` (no index leakage in message) |
| AK-W-011 | Too few words rejected | 31 words | Error status `InvalidLength` |
| AK-W-012 | Too many words rejected | 33 words | Error status `InvalidLength` |
| AK-W-013 | Empty input rejected | Empty string or whitespace only | Error status `InvalidLength` |
| AK-W-014 | Dictionary length not 256 rejected | Dictionary file has 255 or 257 entries | Error status `InvalidDictionary` |
| AK-W-015 | Dictionary contains duplicates | Duplicate token in dictionary | Error status `InvalidDictionary` |
| AK-W-016 | Non-ASCII word token rejected | Word with Unicode (e.g., contains `\\u03A9`) | Error status `InvalidWord` |
| AK-W-017 | Punctuation in word rejected | `w001,` or `w002.` | Error status `InvalidWord` |

### Character-Based Mapping
| ID | Description | Input | Expected Result |
| --- | --- | --- | --- |
| AK-C-001 | Known mapping produces correct 256-bit key | 43 chars: `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` | 32 bytes all `00` |
| AK-C-004 | Known mapping verifies bit packing | 43 chars: `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq` | Hex key `00108310518720928B30D38F41149351559761969B71D79F8218A39259A7A29A` |
| AK-C-002 | Valid characters accepted | Passphrase containing `-` and `_` | Success, key length 32 bytes |
| AK-C-003 | Deterministic output | Same 43-char input twice | Identical 32-byte outputs |

### Character-Based Validation / Edge Cases
| ID | Description | Input | Expected Result |
| --- | --- | --- | --- |
| AK-C-010 | Too few characters rejected | 42 chars | Error status `InvalidLength` |
| AK-C-011 | Too many characters rejected | 44 chars | Error status `InvalidLength` |
| AK-C-012 | Invalid character rejected | Input contains space or `@` | Error status `InvalidChar` |
| AK-C-013 | Non-ASCII character rejected | Input contains Unicode (e.g., `\\u03A9`) | Error status `InvalidChar` |
| AK-C-014 | Leading/trailing spaces are significant | Input contains leading space | Error status `InvalidChar` |

### Common / API Behavior
| ID | Description | Input | Expected Result |
| --- | --- | --- | --- |
| AK-CO-001 | Output length always 32 bytes | Any valid input | Output length `32` |
| AK-CO-002 | No exceptions thrown | Invalid input (word/char) | Function returns error status, no throw |
| AK-CO-003 | Deterministic mapping | Same valid input across runs | Same output bytes |

### Random Key Generation (Sanity)
| ID | Description | Input | Expected Result |
| --- | --- | --- | --- |
| AK-R-001 | Generator uses RNG (deterministic stub) | RNG stub returns 0x00..0xFF repeating | Generated word list maps to bytes `00..1F` (first 32 bytes) |
| AK-R-002 | No collisions in 10,000 keys | Generate 10,000 keys | Zero duplicate 32-byte keys |
| AK-R-003 | Basic uniformity (slow test) | 10,000 generated keys | Per-byte frequency roughly uniform; chi-square p-value > 0.01 |

## Notes
- `AK-R-002` and `AK-R-003` are statistical tests and should be marked as `slow` or `nightly` to avoid flakiness in quick CI runs.
- Error messages must be generic and must not reveal which word/character failed (see Section 9 of the vision document).
