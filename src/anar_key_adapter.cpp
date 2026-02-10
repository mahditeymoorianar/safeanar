#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "safeanar/anar_key.hpp"
#include "safeanar/anar_status.hpp"

namespace {

using safeanar::AnarStatus;

struct JsonValue {
    enum class Type {
        Null,
        Bool,
        Number,
        String,
        Object
    };

    Type type = Type::Null;
    bool bool_value = false;
    long long number_value = 0;
    std::string string_value;
    std::unordered_map<std::string, JsonValue> object_value;
};

class JsonParser {
public:
    explicit JsonParser(std::string_view input) : input_(input) {}

    bool ParseRootObject(JsonValue& out_value) {
        SkipWhitespace();
        if (!ParseObject(out_value)) {
            return false;
        }
        SkipWhitespace();
        return position_ == input_.size();
    }

private:
    bool ParseValue(JsonValue& out_value) {
        SkipWhitespace();
        if (End()) {
            return false;
        }
        const char ch = input_[position_];
        if (ch == '{') {
            return ParseObject(out_value);
        }
        if (ch == '"') {
            out_value.type = JsonValue::Type::String;
            return ParseString(out_value.string_value);
        }
        if (ch == 't') {
            if (!ConsumeLiteral("true")) {
                return false;
            }
            out_value.type = JsonValue::Type::Bool;
            out_value.bool_value = true;
            return true;
        }
        if (ch == 'f') {
            if (!ConsumeLiteral("false")) {
                return false;
            }
            out_value.type = JsonValue::Type::Bool;
            out_value.bool_value = false;
            return true;
        }
        if (ch == 'n') {
            if (!ConsumeLiteral("null")) {
                return false;
            }
            out_value.type = JsonValue::Type::Null;
            return true;
        }
        if (ch == '-' || std::isdigit(static_cast<unsigned char>(ch)) != 0) {
            out_value.type = JsonValue::Type::Number;
            return ParseNumber(out_value.number_value);
        }
        return false;
    }

    bool ParseObject(JsonValue& out_value) {
        if (!ConsumeChar('{')) {
            return false;
        }

        out_value.type = JsonValue::Type::Object;
        out_value.object_value.clear();

        SkipWhitespace();
        if (ConsumeChar('}')) {
            return true;
        }

        while (true) {
            SkipWhitespace();
            std::string key;
            if (!ParseString(key)) {
                return false;
            }

            SkipWhitespace();
            if (!ConsumeChar(':')) {
                return false;
            }

            JsonValue value;
            if (!ParseValue(value)) {
                return false;
            }
            out_value.object_value.emplace(std::move(key), std::move(value));

            SkipWhitespace();
            if (ConsumeChar('}')) {
                return true;
            }
            if (!ConsumeChar(',')) {
                return false;
            }
        }
    }

    bool ParseString(std::string& out_text) {
        if (!ConsumeChar('"')) {
            return false;
        }
        out_text.clear();

        while (!End()) {
            const char ch = input_[position_++];
            if (ch == '"') {
                return true;
            }
            if (ch == '\\') {
                if (End()) {
                    return false;
                }
                const char esc = input_[position_++];
                switch (esc) {
                    case '"':
                        out_text.push_back('"');
                        break;
                    case '\\':
                        out_text.push_back('\\');
                        break;
                    case '/':
                        out_text.push_back('/');
                        break;
                    case 'b':
                        out_text.push_back('\b');
                        break;
                    case 'f':
                        out_text.push_back('\f');
                        break;
                    case 'n':
                        out_text.push_back('\n');
                        break;
                    case 'r':
                        out_text.push_back('\r');
                        break;
                    case 't':
                        out_text.push_back('\t');
                        break;
                    case 'u': {
                        std::uint32_t codepoint = 0;
                        if (!ParseHex4(codepoint)) {
                            return false;
                        }
                        // Preserve character count semantics for tests:
                        // ASCII maps to itself; non-ASCII maps to one sentinel byte.
                        if (codepoint <= 0x7FU) {
                            out_text.push_back(static_cast<char>(codepoint));
                        } else {
                            out_text.push_back(static_cast<char>(0x80));
                        }
                        break;
                    }
                    default:
                        return false;
                }
                continue;
            }

            if (static_cast<unsigned char>(ch) < 0x20U) {
                return false;
            }
            out_text.push_back(ch);
        }

        return false;
    }

    bool ParseHex4(std::uint32_t& out_value) {
        if (position_ + 4 > input_.size()) {
            return false;
        }
        out_value = 0;
        for (int i = 0; i < 4; ++i) {
            const char ch = input_[position_++];
            int digit = 0;
            if (ch >= '0' && ch <= '9') {
                digit = ch - '0';
            } else if (ch >= 'a' && ch <= 'f') {
                digit = 10 + (ch - 'a');
            } else if (ch >= 'A' && ch <= 'F') {
                digit = 10 + (ch - 'A');
            } else {
                return false;
            }
            out_value = (out_value << 4U) | static_cast<std::uint32_t>(digit);
        }
        return true;
    }

    bool ParseNumber(long long& out_number) {
        const std::size_t start = position_;
        if (input_[position_] == '-') {
            ++position_;
            if (End()) {
                return false;
            }
        }
        if (std::isdigit(static_cast<unsigned char>(input_[position_])) == 0) {
            return false;
        }
        while (!End() && std::isdigit(static_cast<unsigned char>(input_[position_])) != 0) {
            ++position_;
        }
        const std::string text(input_.substr(start, position_ - start));
        char* end_ptr = nullptr;
        const long long value = std::strtoll(text.c_str(), &end_ptr, 10);
        if (end_ptr == nullptr || *end_ptr != '\0') {
            return false;
        }
        out_number = value;
        return true;
    }

    bool ConsumeLiteral(const std::string_view literal) {
        if (position_ + literal.size() > input_.size()) {
            return false;
        }
        if (input_.substr(position_, literal.size()) != literal) {
            return false;
        }
        position_ += literal.size();
        return true;
    }

    bool ConsumeChar(const char expected) {
        if (!End() && input_[position_] == expected) {
            ++position_;
            return true;
        }
        return false;
    }

    void SkipWhitespace() {
        while (!End() && std::isspace(static_cast<unsigned char>(input_[position_])) != 0) {
            ++position_;
        }
    }

    bool End() const {
        return position_ >= input_.size();
    }

    std::string_view input_;
    std::size_t position_ = 0;
};

const JsonValue* FindObjectMember(const JsonValue& object, const std::string_view key) {
    if (object.type != JsonValue::Type::Object) {
        return nullptr;
    }
    const auto it = object.object_value.find(std::string(key));
    if (it == object.object_value.end()) {
        return nullptr;
    }
    return &it->second;
}

std::string GetString(const JsonValue& object, const std::string_view key, const std::string& fallback = "") {
    const JsonValue* value = FindObjectMember(object, key);
    if (value == nullptr || value->type != JsonValue::Type::String) {
        return fallback;
    }
    return value->string_value;
}

long long GetNumber(const JsonValue& object, const std::string_view key, const long long fallback) {
    const JsonValue* value = FindObjectMember(object, key);
    if (value == nullptr || value->type != JsonValue::Type::Number) {
        return fallback;
    }
    return value->number_value;
}

bool HasKey(const JsonValue& object, const std::string_view key) {
    return FindObjectMember(object, key) != nullptr;
}

std::string EscapeJson(const std::string_view input) {
    std::string output;
    output.reserve(input.size() + 8);
    for (const char ch : input) {
        switch (ch) {
            case '"':
                output += "\\\"";
                break;
            case '\\':
                output += "\\\\";
                break;
            case '\b':
                output += "\\b";
                break;
            case '\f':
                output += "\\f";
                break;
            case '\n':
                output += "\\n";
                break;
            case '\r':
                output += "\\r";
                break;
            case '\t':
                output += "\\t";
                break;
            default: {
                const unsigned char byte = static_cast<unsigned char>(ch);
                if (byte < 0x20U) {
                    static constexpr char kHex[] = "0123456789ABCDEF";
                    output += "\\u00";
                    output.push_back(kHex[(byte >> 4U) & 0x0FU]);
                    output.push_back(kHex[byte & 0x0FU]);
                } else {
                    output.push_back(ch);
                }
                break;
            }
        }
    }
    return output;
}

std::optional<std::vector<std::uint8_t>> ParseHexBytes(const std::string_view input) {
    if ((input.size() % 2U) != 0U) {
        return std::nullopt;
    }
    auto from_hex = [](const char ch) -> int {
        if (ch >= '0' && ch <= '9') {
            return ch - '0';
        }
        if (ch >= 'a' && ch <= 'f') {
            return 10 + (ch - 'a');
        }
        if (ch >= 'A' && ch <= 'F') {
            return 10 + (ch - 'A');
        }
        return -1;
    };

    std::vector<std::uint8_t> output;
    output.reserve(input.size() / 2U);
    for (std::size_t i = 0; i < input.size(); i += 2U) {
        const int high = from_hex(input[i]);
        const int low = from_hex(input[i + 1U]);
        if (high < 0 || low < 0) {
            return std::nullopt;
        }
        output.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }
    return output;
}

void WriteError(const std::string_view error) {
    std::cout << "{\"ok\":false,\"error\":\"" << EscapeJson(error) << "\"}\n";
}

void WriteOkSimple() {
    std::cout << "{\"ok\":true}\n";
}

void WriteOkKeyHex(const safeanar::KeyBytes& key) {
    std::cout << "{\"ok\":true,\"key_hex\":\"" << safeanar::AnarKey::ToHex(key) << "\"}\n";
}

void WriteOkWords(const std::vector<std::string>& words) {
    std::cout << "{\"ok\":true,\"words\":[";
    for (std::size_t i = 0; i < words.size(); ++i) {
        if (i > 0) {
            std::cout << ",";
        }
        std::cout << "\"" << EscapeJson(words[i]) << "\"";
    }
    std::cout << "]}\n";
}

void WriteOkKeysHex(const std::vector<safeanar::KeyBytes>& keys) {
    std::cout << "{\"ok\":true,\"keys_hex\":[";
    for (std::size_t i = 0; i < keys.size(); ++i) {
        if (i > 0) {
            std::cout << ",";
        }
        std::cout << "\"" << safeanar::AnarKey::ToHex(keys[i]) << "\"";
    }
    std::cout << "]}\n";
}

void WriteStatusError(const AnarStatus status) {
    WriteError(safeanar::ToString(status));
}

}  // namespace

int main() {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) {
            continue;
        }

        JsonValue request;
        JsonParser parser(line);
        if (!parser.ParseRootObject(request)) {
            WriteError(safeanar::ToString(AnarStatus::BadJson));
            std::cout.flush();
            continue;
        }

        const std::string op = GetString(request, "op");
        if (op == "ping") {
            WriteOkSimple();
            std::cout.flush();
            continue;
        }

        if (op == "derive_words") {
            const std::string dictionary_path = GetString(request, "dictionary_path");
            const std::string passphrase = GetString(request, "passphrase");

            safeanar::KeyBytes key{};
            const AnarStatus status = safeanar::AnarKey::DeriveFromWords(dictionary_path, passphrase, key);
            if (status != AnarStatus::Ok) {
                WriteStatusError(status);
            } else {
                WriteOkKeyHex(key);
                safeanar::AnarKey::SecureWipe(key);
            }
            std::cout.flush();
            continue;
        }

        if (op == "derive_chars") {
            const std::string alphabet = GetString(request, "alphabet");
            const std::string passphrase = GetString(request, "passphrase");

            safeanar::KeyBytes key{};
            const AnarStatus status = safeanar::AnarKey::DeriveFromChars(alphabet, passphrase, key);
            if (status != AnarStatus::Ok) {
                WriteStatusError(status);
            } else {
                WriteOkKeyHex(key);
                safeanar::AnarKey::SecureWipe(key);
            }
            std::cout.flush();
            continue;
        }

        if (op == "gen_words") {
            const std::string dictionary_path = GetString(request, "dictionary_path");
            const std::string mode = GetString(request, "mode", "system");
            const long long count_number = GetNumber(request, "count", 32);
            if (count_number <= 0) {
                WriteStatusError(AnarStatus::InvalidLength);
                std::cout.flush();
                continue;
            }

            std::optional<std::vector<std::uint8_t>> stub_bytes;
            if (mode == "stub") {
                if (!HasKey(request, "rng_bytes_hex")) {
                    WriteStatusError(AnarStatus::MissingRngBytes);
                    std::cout.flush();
                    continue;
                }
                const std::string stub_hex = GetString(request, "rng_bytes_hex");
                stub_bytes = ParseHexBytes(stub_hex);
                if (!stub_bytes.has_value()) {
                    WriteStatusError(AnarStatus::InvalidLength);
                    std::cout.flush();
                    continue;
                }
            }

            std::vector<std::string> words;
            const AnarStatus status = safeanar::AnarKey::GenerateWords(
                dictionary_path,
                static_cast<std::size_t>(count_number),
                stub_bytes.has_value() ? &stub_bytes.value() : nullptr,
                words);

            if (status != AnarStatus::Ok) {
                WriteStatusError(status);
            } else {
                WriteOkWords(words);
            }
            std::cout.flush();
            continue;
        }

        if (op == "gen_keys") {
            const std::string dictionary_path = GetString(request, "dictionary_path");
            const long long count_number = GetNumber(request, "count", 100);
            if (count_number <= 0) {
                WriteStatusError(AnarStatus::InvalidLength);
                std::cout.flush();
                continue;
            }

            safeanar::DictionaryData dictionary;
            const AnarStatus dict_status = safeanar::AnarKey::LoadDictionary(dictionary_path, dictionary);
            if (dict_status != AnarStatus::Ok) {
                WriteStatusError(dict_status);
                std::cout.flush();
                continue;
            }

            std::vector<safeanar::KeyBytes> keys;
            const AnarStatus status = safeanar::AnarKey::GenerateKeys(static_cast<std::size_t>(count_number), keys);
            if (status != AnarStatus::Ok) {
                WriteStatusError(status);
            } else {
                WriteOkKeysHex(keys);
                for (auto& key : keys) {
                    safeanar::AnarKey::SecureWipe(key);
                }
            }
            std::cout.flush();
            continue;
        }

        WriteStatusError(AnarStatus::UnknownOp);
        std::cout.flush();
    }

    return 0;
}

