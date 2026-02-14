#include "safeanar/key_generator.hpp"

#include <array>
#include <cstdint>
#include <limits>
#include <random>
#include <string_view>
#include "misc.h"

namespace safeanar {

namespace {

const std::array<std::string, 256>& BuiltInDictionary() {
    static const std::array<std::string, 256> dictionary = {

        "anar",
        "apple",
        "ali",
        "azad",
        "banana",
        "beach",
        "bitcoin",
        "bread",
        "break",
        "bellow",
        "borrow",
        "bring",
        "bear",
        "boy",
        "byte",
        "buy",
        "candy",
        "candidate",
        "create",
        "call",
        "card",
        "chocolate",
        "cake",
        "cup",
        "coffee",
        "coin",
        "concern",
        "corner",
        "clown",
        "clone",
        "crowd",
        "cute",
        "cat",
        "center",
        "circle",
        "chemistry",
        "crown",
        "color",
        "cold",
        "coast",
        "costume",
        "consume",
        "commit",
        "christ",
        "convert",
        "crypto",
        "cipher",
        "decrypt",
        "encrypt",
        "decode",
        "decentralized",
        "dolphin",
        "donkey",
        "doll",
        "encode",
        "ethereum",
        "electron",
        "election",
        "effective",
        "fedora",
        "female",
        "file",
        "finish",
        "fish",
        "free",
        "fire",
        "fresh",
        "go",
        "god",
        "get",
        "give",
        "glass",
        "green",
        "girl",
        "glue",
        "gold",
        "hash",
        "has",
        "have",
        "hesitate",
        "here",
        "him",
        "her",
        "history",
        "heel",
        "health",
        "hello",
        "house",
        "home",
        "iran",
        "islam",
        "irregular",
        "impossible",
        "internet",
        "interface",
        "independence",
        "interpretation",
        "intelligence",
        "intellectual",
        "incompatible",
        "imam",
        "jesus",
        "joker",
        "jump",
        "job",
        "jabbar",
        "jenab",
        "jet",
        "king",
        "kitten",
        "kitchen",
        "knight",
        "knife",
        "knowledge",
        "kebab",
        "korea",
        "light",
        "lie",
        "liar",
        "lite",
        "less",
        "low",
        "level",
        "lack",
        "lose",
        "last",
        "late",
        "lambda",
        "like",
        "love",
        "lake",
        "loud",
        "lot",
        "left",
        "leave",
        "life",
        "live",
        "laptop",
        "lab",
        "lord",
        "monday",
        "money",
        "mahdi",
        "monero",
        "monospace",
        "monopoly",
        "monotonic",
        "monster",
        "monkey",
        "moan",
        "manner",
        "man",
        "men",
        "mosque",
        "moscow",
        "map",
        "male",
        "more",
        "most",
        "mask",
        "masculine",
        "mustache",
        "none",
        "naughty",
        "noise",
        "nose",
        "never",
        "nowhere",
        "now",
        "near",
        "nurse",
        "nature",
        "nothing",
        "nobody",
        "nested",
        "neck",
        "national",
        "narrative",
        "negotiation",
        "need",
        "novel",
        "narrow",
        "notebook",
        "night",
        "nine",
        "nail",
        "operation",
        "omega",
        "object",
        "onion",
        "orbit",
        "open",
        "orange",
        "order",
        "offset",
        "office",
        "on",
        "online",
        "offline",
        "off",
        "party",
        "practice",
        "pray",
        "pay",
        "pass",
        "police",
        "politics",
        "privacy",
        "public",
        "private",
        "property",
        "present",
        "prize",
        "quarter",
        "query",
        "question",
        "regular",
        "routing",
        "rabbit",
        "right",
        "row",
        "ruler",
        "register",
        "restore",
        "retry",
        "refresh",
        "reload",
        "restart",
        "start",
        "secret",
        "sacred",
        "script",
        "snake",
        "stack",
        "sudo",
        "say",
        "said",
        "soft",
        "soap",
        "slow",
        "smart",
        "try",
        "tree",
        "traffic",
        "three",
        "tax",
        "trade",
        "threat",
        "thread",
        "union",
        "variety",
        "word",
        "xmr",
        "yellow",
        "zero",
        "zebra",
    };
    return dictionary;
}

AnarStatus FillRandomBytes(std::uint8_t* out, const std::size_t length) {
    if (length == 0) {
        return AnarStatus::Ok;
    }

    try {
        std::random_device rd;
        if (std::numeric_limits<std::random_device::result_type>::max() == 0) {
            return AnarStatus::MissingRngBytes;
        }

        std::size_t written = 0;
        while (written < length) {
            const auto value = rd();
            for (std::size_t i = 0; i < sizeof(value) && written < length; ++i) {
                out[written++] = static_cast<std::uint8_t>((value >> (i * 8U)) & 0xFFU);
            }
        }
        return AnarStatus::Ok;
    } catch (...) {
        return AnarStatus::MissingRngBytes;
    }
}

void SecureWipeBytes(std::vector<std::uint8_t>& bytes) {
    if (!bytes.empty()) {
        CryptoPP::memset_z(bytes.data(), 0, bytes.size());
    }
    bytes.clear();
}

}  // namespace

AnarStatus KeyGenerator::GenerateWords(const std::size_t count, std::vector<std::string>& out_words) {
    if (count == 0) {
        return AnarStatus::InvalidLength;
    }

    const auto& dictionary = BuiltInDictionary();
    std::vector<std::uint8_t> random_bytes(count, 0U);
    const AnarStatus random_status = FillRandomBytes(random_bytes.data(), random_bytes.size());
    if (random_status != AnarStatus::Ok) {
        return random_status;
    }

    out_words.clear();
    out_words.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        out_words.push_back(dictionary[random_bytes[i]]);
    }
    SecureWipeBytes(random_bytes);
    return AnarStatus::Ok;
}

AnarStatus KeyGenerator::GenerateChars(const std::size_t length, std::string& out_chars) {
    if (length == 0) {
        return AnarStatus::InvalidLength;
    }

    const std::string& alphabet = CharacterAlphabet();
    std::vector<std::uint8_t> random_bytes(length, 0U);
    const AnarStatus random_status = FillRandomBytes(random_bytes.data(), random_bytes.size());
    if (random_status != AnarStatus::Ok) {
        return random_status;
    }

    out_chars.clear();
    out_chars.reserve(length);
    for (std::size_t i = 0; i < length; ++i) {
        out_chars.push_back(alphabet[random_bytes[i] & 0x3FU]);
    }
    SecureWipeBytes(random_bytes);
    return AnarStatus::Ok;
}

std::string KeyGenerator::JoinWords(const std::vector<std::string>& words) {
    std::string out;
    if (words.empty()) {
        return out;
    }
    std::size_t total = 0;
    for (const auto& word : words) {
        total += word.size();
    }
    total += words.size() - 1;
    out.reserve(total);

    for (std::size_t i = 0; i < words.size(); ++i) {
        if (i > 0) {
            out.push_back(' ');
        }
        out += words[i];
    }
    return out;
}

const std::string& KeyGenerator::CharacterAlphabet() {
    static const std::string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789*!";
    return alphabet;
}

}  // namespace safeanar

