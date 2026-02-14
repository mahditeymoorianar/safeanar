# Security Audit Report

**Date:** 2024-05-22
**Auditor:** Jules (AI Assistant)
**Target:** SafeAnar Project

## Executive Summary

A security review of the SafeAnar codebase identified several critical vulnerabilities in the cryptographic implementation. These include the use of weak random number generators, insufficient key derivation, and non-standard message authentication code (MAC) construction.

This report details the findings and the remediation plan.

## Findings

### 1. Weak Random Number Generation (Critical)
**Description:** The application uses `std::mt19937` (Mersenne Twister) and `std::mt19937_64` for cryptographic operations, including key generation, padding, and nonce generation.
**Impact:** `std::mt19937` is not a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG). Its internal state can be recovered after observing a sufficient number of outputs (624 for 32-bit), allowing an attacker to predict future outputs (keys, nonces).
**Remediation:** Replace all usages of `std::mt19937` with `CryptoPP::AutoSeededRandomPool` (which uses OS-specific CSPRNGs like `/dev/urandom` or `RtlGenRandom`).

### 2. Weak Key Derivation Function (Critical)
**Description:** The application derives encryption keys from passphrases using a single round of SHA-256 (`Sha256(raw_key_bytes)`).
**Impact:** This construction is highly vulnerable to brute-force and dictionary attacks. The lack of a salt allows for pre-computation (Rainbow Tables), and the lack of iteration count makes testing candidates extremely fast (millions per second on consumer hardware).
**Remediation:** Implement PBKDF2-HMAC-SHA256 with a random 16-byte salt and a high iteration count (e.g., 600,000). Store the salt in the container header.

### 3. Insecure Message Authentication Code (High)
**Description:** The application uses an "Encrypt-and-MAC" construction where the authentication tag is calculated as `SHA-256(Key || Plaintext)`.
**Impact:**
*   **Weak Construction:** `H(K || M)` is susceptible to length extension attacks (though SHA-256 is somewhat resistant, HMAC is the standard).
*   **Encrypt-and-MAC:** Authenticating the plaintext rather than the ciphertext can leak information about the plaintext in some scenarios and does not protect the decryption process from chosen-ciphertext attacks (CCA) as effectively as Encrypt-then-MAC.
**Remediation:** Switch to an Encrypt-then-MAC scheme using HMAC-SHA256 over the ciphertext and header.

### 4. Insecure Memory Wiping (Medium)
**Description:** The `SecureWipe*` functions rely on `volatile` pointers and loops to zero out memory.
**Impact:** Compilers may optimize away these writes if they determine the memory is not accessed afterwards, or the `volatile` keyword may not be sufficient to prevent optimization or ensure immediate erasure in all contexts/architectures.
**Remediation:** Use `CryptoPP::memset_z` or platform-specific secure zeroing functions that guarantee the writes are not optimized away.

### 5. Use of AES-ECB (Low/Informational)
**Description:** `Aes256EcbEncryptHex` is present in `CryptoEngine`.
**Impact:** AES-ECB is insecure for general purpose encryption as it reveals patterns in the plaintext. While it appears unused in the main encryption flow, its presence is a risk if misused.
**Remediation:** Ensure it is only used for testing component compliance and not for data protection.

## Remediation Plan

The following changes will be implemented:

1.  **RNG:** Replace `std::mt19937` with `CryptoPP::AutoSeededRandomPool` in `KeyGenerator`, `SecureDelete`, `StreamPacker`, and `main.cpp`.
2.  **KDF:** Update container format (v4) to include a 16-byte salt. Use `CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256>` for key derivation.
3.  **MAC:** Update container format (v4) to use HMAC-SHA256 over the header and ciphertext (Encrypt-then-MAC).
4.  **Memory:** Replace manual `volatile` wipes with `CryptoPP::memset_z`.

## Future Recommendations

*   **Argon2:** Consider upgrading to Argon2id for memory-hard key derivation.
*   **AEAD:** Standardize on AEAD modes (like ChaCha20-Poly1305 or AES-GCM) instead of manual Encrypt-then-MAC composition for AES/Serpent/etc.
*   **Code Signing:** Sign the release binaries.
