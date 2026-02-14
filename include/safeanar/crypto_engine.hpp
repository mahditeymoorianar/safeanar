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
    static AnarStatus Aes256EcbEncryptHex(
        std::string_view key_hex,
        std::string_view plaintext_hex,
        std::string& out_ciphertext_hex);

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

    static AnarStatus OtpXorBytes(
        const std::vector<std::uint8_t>& input,
        const std::vector<std::uint8_t>& key_bytes,
        std::vector<std::uint8_t>& output,
        const std::function<void(std::size_t, std::size_t)>& progress = {});

private:
    static AnarStatus ParseHex(std::string_view hex, std::vector<std::uint8_t>& out_bytes);
    static std::string ToHex(const std::vector<std::uint8_t>& data);
};

}  // namespace safeanar
