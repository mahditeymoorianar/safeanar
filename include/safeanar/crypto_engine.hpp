#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "safeanar/anar_status.hpp"

namespace safeanar {

class CryptoEngine {
public:
    // Warning: AES-ECB is insecure. Only for testing component compliance.
    [[deprecated("Insecure mode. Use only for testing.")]]
    static AnarStatus Aes256EcbEncryptHex(
        std::string_view key_hex,
        std::string_view plaintext_hex,
        std::string& out_ciphertext_hex);

    [[deprecated("Insecure mode. Use only for testing.")]]
    static AnarStatus Aes256EcbDecryptHex(
        std::string_view key_hex,
        std::string_view ciphertext_hex,
        std::string& out_plaintext_hex);

    static AnarStatus OtpXorBytesHex(
        std::string_view data_hex,
        std::string_view key_hex,
        std::string& out_result_hex);

    static AnarStatus OtpXorFile(
        const std::string& input_path,
        const std::string& key_path,
        const std::string& output_path,
        std::size_t& out_bytes_processed);

    static AnarStatus Aes256CtrXor(
        const std::array<std::uint8_t, 32>& key_bytes,
        const std::array<std::uint8_t, 16>& nonce,
        const std::vector<std::uint8_t>& input,
        std::vector<std::uint8_t>& output,
        const std::function<void(std::size_t, std::size_t)>& progress = {});

    static AnarStatus PqSha256StreamXor(
        const std::array<std::uint8_t, 32>& key_bytes,
        const std::array<std::uint8_t, 16>& nonce,
        const std::vector<std::uint8_t>& input,
        std::vector<std::uint8_t>& output,
        const std::function<void(std::size_t, std::size_t)>& progress = {});

    static AnarStatus ChaCha20Poly1305Encrypt(
        const std::array<std::uint8_t, 32>& key_bytes,
        const std::array<std::uint8_t, 24>& nonce,
        const std::vector<std::uint8_t>& plaintext,
        std::vector<std::uint8_t>& out_ciphertext,
        std::array<std::uint8_t, 16>& out_tag,
        const std::function<void(std::size_t, std::size_t)>& progress = {});

    static AnarStatus ChaCha20Poly1305DecryptVerify(
        const std::array<std::uint8_t, 32>& key_bytes,
        const std::array<std::uint8_t, 24>& nonce,
        const std::vector<std::uint8_t>& ciphertext,
        const std::array<std::uint8_t, 16>& tag,
        std::vector<std::uint8_t>& out_plaintext,
        bool& out_auth_ok,
        const std::function<void(std::size_t, std::size_t)>& progress = {});

    static AnarStatus XChaCha20Poly1305Encrypt(
        const std::array<std::uint8_t, 32>& key_bytes,
        const std::array<std::uint8_t, 24>& nonce,
        const std::vector<std::uint8_t>& plaintext,
        std::vector<std::uint8_t>& out_ciphertext,
        std::array<std::uint8_t, 16>& out_tag,
        const std::function<void(std::size_t, std::size_t)>& progress = {});

    static AnarStatus XChaCha20Poly1305DecryptVerify(
        const std::array<std::uint8_t, 32>& key_bytes,
        const std::array<std::uint8_t, 24>& nonce,
        const std::vector<std::uint8_t>& ciphertext,
        const std::array<std::uint8_t, 16>& tag,
        std::vector<std::uint8_t>& out_plaintext,
        bool& out_auth_ok,
        const std::function<void(std::size_t, std::size_t)>& progress = {});

    static AnarStatus Serpent256CtrXor(
        const std::array<std::uint8_t, 32>& key_bytes,
        const std::array<std::uint8_t, 16>& nonce,
        const std::vector<std::uint8_t>& input,
        std::vector<std::uint8_t>& output,
        const std::function<void(std::size_t, std::size_t)>& progress = {});

    static AnarStatus OtpXorBytes(
        const std::vector<std::uint8_t>& input,
        const std::vector<std::uint8_t>& key_bytes,
        std::vector<std::uint8_t>& output,
        const std::function<void(std::size_t, std::size_t)>& progress = {});

    static void SecureWipe(void* data, std::size_t len);

private:
    static AnarStatus ParseHex(std::string_view hex, std::vector<std::uint8_t>& out_bytes);
    static std::string ToHex(const std::vector<std::uint8_t>& data);
};

}  // namespace safeanar
