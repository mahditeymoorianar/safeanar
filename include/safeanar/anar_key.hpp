#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "safeanar/anar_status.hpp"

namespace safeanar {

constexpr std::size_t kWordKeyWordCount = 32;
constexpr std::size_t kCharKeyCharCount = 43;
constexpr std::size_t kKeyByteCount = 32;
constexpr std::size_t kAlphabetSize = 64;
constexpr std::size_t kDictionarySize = 256;

using KeyBytes = std::array<std::uint8_t, kKeyByteCount>;

struct DictionaryData {
    std::unordered_map<std::string, std::uint8_t> word_to_byte;
    std::array<std::string, kDictionarySize> byte_to_word{};
};

class AnarKey {
public:
    static AnarStatus LoadDictionary(const std::string& dictionary_path, DictionaryData& out_dictionary);

    static AnarStatus DeriveFromWords(
        const std::string& dictionary_path,
        std::string_view passphrase,
        KeyBytes& out_key);

    static AnarStatus DeriveFromChars(
        std::string_view alphabet,
        std::string_view passphrase,
        KeyBytes& out_key);

    static AnarStatus GenerateWords(
        const std::string& dictionary_path,
        std::size_t count,
        const std::vector<std::uint8_t>* stub_bytes,
        std::vector<std::string>& out_words);

    static AnarStatus GenerateKeys(std::size_t count, std::vector<KeyBytes>& out_keys);

    static std::string ToHex(const KeyBytes& key);

    static void SecureWipe(KeyBytes& key);

private:
    static std::vector<std::string> SplitAsciiWhitespace(std::string_view input);
    static std::string NormalizeAsciiLower(std::string_view input, bool& ascii_ok);
};

}  // namespace safeanar

