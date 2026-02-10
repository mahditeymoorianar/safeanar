# SafeAnar: Design Document & Architecture Specification

**Version:** 1.0.0-draft  
**Status:** Planning Phase  
**Language:** C++ (Standard C++17/20)  
**Target:** Desktop (Linux/Windows) via CLI

---

## 1. Project Overview

**SafeAnar** is a high-security, zero-trust file encryption utility designed for the paranoid user. Unlike standard tools that rely on opaque system libraries (like OpenSSL), SafeAnar implements its core logic from scratch or uses auditable, minimal implementations.

### Core Philosophy
1.  **Zero Trust:** We do not trust the OS crypto libraries. We do not trust closed-source compilers. We verify everything.
2.  **Modularity:** The core logic is a header-only library (`libsafeanar`) usable by other projects.
3.  **Obfuscation:** Encryption alone is not enough; metadata and file size must be obscured to prevent traffic analysis.
4.  **Simplicity:** The CLI must be intuitive, but the internal engine must be robust.

---

## 2. Technical Architecture

The project is divided into two distinct components:

1.  **`libsafeanar` (The Core):** A set of C++ headers containing the logic for key generation, stream processing, and encryption protocols.
2.  **`safeanar-cli` (The Interface):** A command-line wrapper that handles user input and invokes the core library.

### 2.1. Class Structure (The Core)

* **`AnarKey`**: Responsible for parsing user passphrases, generating keys, and mapping words/characters to raw bytes.
* **`StreamPacker`**: Handles File I/O. It converts folders into a linear stream (tar-like) and handles the injection of random padding (garbage data).
* **`ICryptoProtocol` (Interface)**: An abstract base class defining the contract for encryption strategies.
* **`ProtocolFactory`**: Instantiates the correct protocol (AES, OTP, etc.) based on user input.

---

## 3. Key Management System (`AnarKey`)

To support high-entropy keys without forcing users to memorize hex strings, `AnarKey` implements two specific mapping modes to generate a **256-bit (32-byte) binary key**.

### 3.1. Word-Based Mode (Recommended)
* **Concept:** Uses a fixed dictionary of 256 unique English words.
* **Mapping:** Word Index $0 \to 255$ corresponds to Byte $0x00 \to 0xFF$.
* **Requirement:** User provides ~32 words to achieve full 256-bit entropy.
* **Example:** `apple banana ...` $\rightarrow$ `[0x05, 0x1A, ...]`

### 3.2. Character-Based Mode
* **Concept:** Uses a custom mapping of 64 characters (a-z, A-Z, 0-9, special chars).
* **Mapping:** Each character represents 6 bits of entropy.
* **Requirement:** A passphrase of ~43 characters is needed for 256-bit security.

---

## 4. Supported Protocols

### 4.1. AES-256 (Default)
* **Implementation:** A minimal, clean, audit-friendly C++ port of AES (e.g., based on `tiny-AES`).
* **Mode:** CBC or CTR (Counter Mode) preferred for stream capability.
* **Zero Trust:** No linking against system `libcrypto`.

### 4.2. OTP (One-Time Pad)
* **Mechanism:** Pure XOR operation.
* **Requirement:** The key file MUST be equal to or larger than the input file size.
* **Security:** Mathematically unbreakable if the key is truly random and used only once.

### 4.3. Custom Protocol (Future Expansion)
* **Architecture:** The Strategy Pattern allows plugging in a custom "Special Absolutism" algorithm later (e.g., a combination of compression + permutation).

---

## 5. File Processing & Obfuscation

### 5.1. Tar-Like Streaming (Virtual Archive)
Since encryption algorithms work on byte streams, folders must be serialized.
* **Format:** `[Header: FilePath | Size] [Data] [Header: FilePath | Size] [Data] ...`
* **Implementation:** We implement a lightweight archiver within `StreamPacker` to avoid dependency on system `tar`.

### 5.2. Padding (Obfuscation)
To prevent side-channel attacks based on file size, users can inject garbage data.
* **Structure:**
    1.  **Encrypted Metadata Header:** Stores the *real* size of the data.
    2.  **Encrypted Payload:** The actual file/archive.
    3.  **Encrypted Garbage:** Random bytes added to reach the target size.
* **Benefit:** A 1KB text file and a 10KB image can both be padded to exactly 10MB, making them indistinguishable.

---

## 6. Command Line Interface Specification

```bash
# Basic Encryption (File)
safeanar --encrypt --path "./secret.txt" --key "my secret phrase"

# Encryption with Padding (Obfuscation)
safeanar --encrypt --path "./secret.txt" --out "data.enc" --padding-size "100MB" --key-file "./my.key"

# Folder Encryption (Auto-archives)
safeanar --encrypt --path "./my_folder" --out "archive.sa"

# Decryption
safeanar --decrypt --path "archive.sa" --key-file "./my.key"

# Key Generation (Helper)
safeanar --gen-key words  # Outputs 32 random words
safeanar --gen-key chars  # Outputs 43 random characters
```

## 7. Implementation Phases & Testing Plan

The development of SafeAnar is structured into five iterative phases to ensure each component is battle-tested before integration.

### Phase 1: The Foundation (`AnarKey`)
* **Goal:** Implement the logic for mapping Word-lists (256 words) and Character-sets (64 chars) to binary keys.
* **Task:** Create the `AnarKey` class with a focus on entropy and mapping accuracy.
* **Testing Strategy:**
    * **Unit Test:** Input a known sequence of 32 words; verify the output matches the expected 256-bit hex key.
    * **Boundary Test:** Ensure the parser rejects words not present in the 256-word dictionary.
    * **Randomness Test:** Generate 10,000 keys and check for collisions or patterns.

### Phase 2: The Crypto Engine (AES & OTP)
* **Goal:** Implement the core encryption logic using the Strategy Pattern.
* **Task:** Port a minimal AES-256 implementation and write the OTP XOR logic.
* **Testing Strategy:**
    * **KAT (Known Answer Tests):** Use NIST standard vectors to verify that the AES implementation is mathematically perfect.
    * **OTP Symmetry Test:** Encrypt a file with a random key-file, then decrypt it. The hash (SHA-256) of the original and the result must be identical.

### Phase 3: The Stream & Padding (`StreamPacker`)
* **Goal:** Manage File I/O, folder serialization (Tar-like), and garbage data injection.
* **Task:** Implement the `StreamPacker` to handle large files in chunks (e.g., 4KB buffers) to keep memory usage low.
* **Testing Strategy:**
    * **Padding Accuracy:** Use `--padding-size 1GB` on a 1MB file. Verify the output file size is exactly $1 \times 10^9$ bytes.
    * **Integrity Test:** Randomly terminate the process during encryption to ensure the program handles file corruption or partial writes gracefully.

### Phase 4: Integration & CLI
* **Goal:** Connect the library to the command-line interface.
* **Task:** Implement argument parsing for `--path`, `--text`, `--key`, and `--protocol`.
* **Testing Strategy:**
    * **End-to-End (E2E):** A script that encrypts a directory, moves it to a different OS/filesystem, and decrypts it successfully.

---

## 8. Security Requirements (The Paranoid Checklist)

To uphold the "Zero Trust" philosophy, the following rules are mandatory:

1.  **Memory Sanitization:** All sensitive buffers (keys, IVs, unencrypted chunks) must be explicitly wiped from RAM using `secure_memset` or `volatile`-guaranteed loops before the objects are destroyed.
2.  **Constant-Time Logic:** The key-comparison and word-mapping logic must avoid branching (`if/else`) based on the content of the key to prevent **Timing Attacks**.
3.  **No Temporary Files:** All operations (like folder serialization) should happen in-stream or in memory-mapped buffers. If a temporary file is strictly necessary, it must be encrypted.
4.  **Static Linking:** The final binary should be statically linked to avoid "DLL Hijacking" or "Shared Object Injection" on the host system.

---

## 9. Error Handling & Fault Tolerance

SafeAnar does not use standard C++ exceptions in the core logic to prevent stack-trace leaks and unpredictable exit states.

* **Error Codes:** Every function returns a `Result<T>` or a custom `AnarStatus` enum.
* **Graceful Failure:** In case of a wrong key, the program should not indicate *where* the key was wrong (e.g., "Word 5 is incorrect"). It should simply return a generic `Authentication Failed` after a random delay (to thwart brute-force timing).
* **Validation:** Before starting a 100GB encryption task, SafeAnar must check for available disk space and write permissions.

---

## 10. Performance & Memory Management

Even with a focus on security, the program must be efficient:

* **Chunked Processing:** Files are read in $N$ sized chunks.
  $$\text{Memory Usage} \approx \text{Buffer Size} \times \text{Threads}$$
* **Zero-Copy:** Use `std::string_view` and pointer arithmetic to move data between the `StreamPacker` and the `CryptoEngine` without redundant copying.
* **SIMD Optimization:** While avoiding external libraries, we may use compiler intrinsics (like AES-NI) for hardware acceleration, provided the user explicitly enables it with a `--fast` flag.

---

## 11. Integration with MLSTC (The Sandwich Layer)

The user's proprietary `MLSTC` component will be integrated as a "Pre-Processor":

1.  **Step 1:** `MLSTC` compresses the input text/stream, reducing size and increasing entropy (removing language patterns).
2.  **Step 2:** The engine applies the chosen protocol (AES/OTP).
3.  **Step 3:** A final permutation layer (Custom Shuffle) is applied based on the secondary key bits.

---

## 12. Future Scope & Extensibility

* **GUI Wrapper:** A Qt or Compose-based desktop app that uses `libsafeanar` as its backend.
* **Network Stream:** Encrypting data directly over a socket (SSH-like) for secure file transfer.
* **Hardware Tokens:** Support for reading keys from physical USB tokens or smart cards.