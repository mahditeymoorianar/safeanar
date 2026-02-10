#include "safeanar/anar_key.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <fstream>
#include <limits>
#include <random>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace safeanar {

namespace {

std::string TrimAsciiWhitespace(const std::string_view input) {
    std::size_t start = 0;
    std::size_t end = input.size();
    while (start < end && std::isspace(static_cast<unsigned char>(input[start])) != 0) {
        ++start;
    }
    while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1])) != 0) {
        --end;
    }
    return std::string(input.substr(start, end - start));
}

std::uint64_t SeedFromEntropy() {
    std::random_device rd;
    const auto now_ns = static_cast<std::uint64_t>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count());
    std::uint64_t seed = now_ns ^ 0x9E3779B97F4A7C15ULL;
    seed ^= (static_cast<std::uint64_t>(rd()) << 32U);
    seed ^= static_cast<std::uint64_t>(rd());
    return seed;
}

std::string BinaryKeyString(const KeyBytes& key) {
    return std::string(reinterpret_cast<const char*>(key.data()), key.size());
}

std::uint8_t ConstantTimeAsciiEqual(const std::string_view lhs, const std::string_view rhs) {
    const std::size_t max_len = lhs.size() > rhs.size() ? lhs.size() : rhs.size();
    std::size_t diff = lhs.size() ^ rhs.size();
    for (std::size_t i = 0; i < max_len; ++i) {
        const unsigned char left = i < lhs.size() ? static_cast<unsigned char>(lhs[i]) : 0U;
        const unsigned char right = i < rhs.size() ? static_cast<unsigned char>(rhs[i]) : 0U;
        diff |= static_cast<std::size_t>(left ^ right);
    }
    return static_cast<std::uint8_t>(diff == 0U ? 1U : 0U);
}

void ConstantTimeLookupWordByte(
    const std::array<std::string, kDictionarySize>& dictionary,
    const std::string_view word,
    std::uint8_t& out_byte,
    std::uint8_t& out_found) {
    std::uint8_t selected_byte = 0U;
    std::uint8_t found = 0U;
    for (std::size_t index = 0; index < dictionary.size(); ++index) {
        const std::uint8_t match = ConstantTimeAsciiEqual(dictionary[index], word);
        const std::uint8_t mask = static_cast<std::uint8_t>(0U - match);
        selected_byte = static_cast<std::uint8_t>((selected_byte & static_cast<std::uint8_t>(~mask)) |
            (static_cast<std::uint8_t>(index) & mask));
        found = static_cast<std::uint8_t>(found | match);
    }
    out_byte = selected_byte;
    out_found = found;
}

}  // namespace

AnarStatus AnarKey::LoadDictionary(const std::string& dictionary_path, DictionaryData& out_dictionary) {
    std::ifstream file(dictionary_path);
    if (!file.is_open()) {
        return AnarStatus::InvalidDictionary;
    }

    std::vector<std::string> entries;
    entries.reserve(kDictionarySize);
    std::unordered_set<std::string> seen;
    seen.reserve(kDictionarySize);

    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        const std::string token = TrimAsciiWhitespace(line);
        if (token.empty()) {
            return AnarStatus::InvalidDictionary;
        }

        bool ascii_ok = true;
        std::string normalized = NormalizeAsciiLower(token, ascii_ok);
        if (!ascii_ok) {
            return AnarStatus::InvalidDictionary;
        }
        if (!seen.insert(normalized).second) {
            return AnarStatus::InvalidDictionary;
        }
        entries.push_back(std::move(normalized));
    }

    if (entries.size() != kDictionarySize) {
        return AnarStatus::InvalidDictionary;
    }

    DictionaryData dictionary;
    dictionary.word_to_byte.reserve(kDictionarySize);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        dictionary.word_to_byte.emplace(entries[i], static_cast<std::uint8_t>(i));
        dictionary.byte_to_word[i] = entries[i];
    }
    out_dictionary = std::move(dictionary);
    return AnarStatus::Ok;
}

AnarStatus AnarKey::DeriveFromWords(
    const std::string& dictionary_path,
    const std::string_view passphrase,
    KeyBytes& out_key) {
    DictionaryData dictionary;
    const AnarStatus dict_status = LoadDictionary(dictionary_path, dictionary);
    if (dict_status != AnarStatus::Ok) {
        return dict_status;
    }

    const std::vector<std::string> words = SplitAsciiWhitespace(passphrase);
    if (words.size() != kWordKeyWordCount) {
        return AnarStatus::InvalidLength;
    }

    out_key.fill(0);
    std::uint8_t invalid_mask = 0U;
    for (std::size_t i = 0; i < words.size(); ++i) {
        bool ascii_ok = true;
        const std::string normalized = NormalizeAsciiLower(words[i], ascii_ok);
        std::uint8_t mapped_value = 0U;
        std::uint8_t found = 0U;
        if (ascii_ok) {
            ConstantTimeLookupWordByte(dictionary.byte_to_word, normalized, mapped_value, found);
        } else {
            ConstantTimeLookupWordByte(dictionary.byte_to_word, std::string_view{}, mapped_value, found);
        }
        out_key[i] = mapped_value;
        invalid_mask = static_cast<std::uint8_t>(invalid_mask | static_cast<std::uint8_t>(!ascii_ok));
        invalid_mask = static_cast<std::uint8_t>(invalid_mask | static_cast<std::uint8_t>(found == 0U));
    }

    if (invalid_mask != 0U) {
        out_key.fill(0U);
        return AnarStatus::InvalidWord;
    }

    return AnarStatus::Ok;
}

AnarStatus AnarKey::DeriveFromChars(
    const std::string_view alphabet,
    const std::string_view passphrase,
    KeyBytes& out_key) {
    if (alphabet.size() != kAlphabetSize) {
        return AnarStatus::InvalidDictionary;
    }
    if (passphrase.size() != kCharKeyCharCount) {
        return AnarStatus::InvalidLength;
    }

    std::array<int, 256> char_to_index{};
    char_to_index.fill(-1);
    std::array<bool, 256> seen{};
    seen.fill(false);

    for (std::size_t i = 0; i < alphabet.size(); ++i) {
        const unsigned char value = static_cast<unsigned char>(alphabet[i]);
        if (value >= 128U) {
            return AnarStatus::InvalidDictionary;
        }
        if (seen[value]) {
            return AnarStatus::InvalidDictionary;
        }
        seen[value] = true;
        char_to_index[value] = static_cast<int>(i);
    }

    out_key.fill(0);
    std::size_t bit_position = 0;
    for (const char ch : passphrase) {
        const unsigned char value = static_cast<unsigned char>(ch);
        if (value >= 128U) {
            return AnarStatus::InvalidChar;
        }
        const int six_bit_value = char_to_index[value];
        if (six_bit_value < 0) {
            return AnarStatus::InvalidChar;
        }

        for (int bit = 5; bit >= 0; --bit) {
            if (bit_position >= kKeyByteCount * 8) {
                break;
            }
            const bool bit_set = ((six_bit_value >> bit) & 0x01) != 0;
            if (bit_set) {
                out_key[bit_position / 8] |= static_cast<std::uint8_t>(1U << (7U - (bit_position % 8U)));
            }
            ++bit_position;
        }
    }

    return AnarStatus::Ok;
}

AnarStatus AnarKey::GenerateWords(
    const std::string& dictionary_path,
    const std::size_t count,
    const std::vector<std::uint8_t>* stub_bytes,
    std::vector<std::string>& out_words) {
    DictionaryData dictionary;
    const AnarStatus dict_status = LoadDictionary(dictionary_path, dictionary);
    if (dict_status != AnarStatus::Ok) {
        return dict_status;
    }
    if (count == 0) {
        return AnarStatus::InvalidLength;
    }

    out_words.clear();
    out_words.reserve(count);

    if (stub_bytes != nullptr) {
        if (stub_bytes->size() < count) {
            return AnarStatus::InsufficientRngBytes;
        }
        for (std::size_t i = 0; i < count; ++i) {
            out_words.push_back(dictionary.byte_to_word[(*stub_bytes)[i]]);
        }
        return AnarStatus::Ok;
    }

    std::mt19937_64 engine(SeedFromEntropy());
    std::uniform_int_distribution<int> dist(0, 255);
    for (std::size_t i = 0; i < count; ++i) {
        const auto byte_value = static_cast<std::uint8_t>(dist(engine));
        out_words.push_back(dictionary.byte_to_word[byte_value]);
    }

    return AnarStatus::Ok;
}

AnarStatus AnarKey::GenerateKeys(const std::size_t count, std::vector<KeyBytes>& out_keys) {
    if (count == 0) {
        return AnarStatus::InvalidLength;
    }
    if (count > (std::numeric_limits<std::size_t>::max() / kKeyByteCount)) {
        return AnarStatus::InvalidLength;
    }

    const std::size_t total_bytes = count * kKeyByteCount;
    std::vector<std::uint8_t> byte_pool(total_bytes);
    for (std::size_t i = 0; i < total_bytes; ++i) {
        byte_pool[i] = static_cast<std::uint8_t>(i & 0xFFU);
    }

    std::mt19937_64 engine(SeedFromEntropy());

    for (int attempt = 0; attempt < 8; ++attempt) {
        std::shuffle(byte_pool.begin(), byte_pool.end(), engine);

        out_keys.clear();
        out_keys.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            KeyBytes key{};
            const std::size_t base = i * kKeyByteCount;
            for (std::size_t j = 0; j < kKeyByteCount; ++j) {
                key[j] = byte_pool[base + j];
            }
            out_keys.push_back(key);
        }

        std::unordered_set<std::string> seen;
        seen.reserve(count * 2);
        bool has_collision = false;
        for (const auto& key : out_keys) {
            if (!seen.insert(BinaryKeyString(key)).second) {
                has_collision = true;
                break;
            }
        }
        if (!has_collision) {
            return AnarStatus::Ok;
        }
    }

    // Collision fallback (rare): use seeded PRNG stream per key.
    out_keys.clear();
    out_keys.reserve(count);
    std::mt19937_64 fallback_engine(SeedFromEntropy() ^ 0xD1342543DE82EF95ULL);
    std::uniform_int_distribution<int> dist(0, 255);
    for (std::size_t i = 0; i < count; ++i) {
        KeyBytes key{};
        for (std::size_t j = 0; j < key.size(); ++j) {
            key[j] = static_cast<std::uint8_t>(dist(fallback_engine));
        }
        out_keys.push_back(key);
    }

    return AnarStatus::Ok;
}

std::string AnarKey::ToHex(const KeyBytes& key) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string output;
    output.reserve(key.size() * 2);
    for (const std::uint8_t byte : key) {
        output.push_back(kHex[(byte >> 4U) & 0x0FU]);
        output.push_back(kHex[byte & 0x0FU]);
    }
    return output;
}

void AnarKey::SecureWipe(KeyBytes& key) {
    volatile std::uint8_t* ptr = key.data();
    for (std::size_t i = 0; i < key.size(); ++i) {
        ptr[i] = 0U;
    }
}

std::vector<std::string> AnarKey::SplitAsciiWhitespace(const std::string_view input) {
    std::vector<std::string> tokens;
    std::size_t i = 0;
    while (i < input.size()) {
        while (i < input.size() && std::isspace(static_cast<unsigned char>(input[i])) != 0) {
            ++i;
        }
        const std::size_t start = i;
        while (i < input.size() && std::isspace(static_cast<unsigned char>(input[i])) == 0) {
            ++i;
        }
        if (start < i) {
            tokens.emplace_back(input.substr(start, i - start));
        }
    }
    return tokens;
}

std::string AnarKey::NormalizeAsciiLower(const std::string_view input, bool& ascii_ok) {
    ascii_ok = true;
    std::string output;
    output.reserve(input.size());
    for (const char ch : input) {
        const unsigned char value = static_cast<unsigned char>(ch);
        if (value >= 128U) {
            ascii_ok = false;
            return {};
        }
        output.push_back(static_cast<char>(std::tolower(value)));
    }
    return output;
}

}  // namespace safeanar
