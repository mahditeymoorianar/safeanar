#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
#include <unordered_map>

#include "safeanar/anar_status.hpp"
#include "safeanar/crypto_engine.hpp"

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
    explicit JsonParser(const std::string_view input) : input_(input) {}

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
                        std::uint32_t cp = 0;
                        if (!ParseHex4(cp)) {
                            return false;
                        }
                        if (cp <= 0x7FU) {
                            out_text.push_back(static_cast<char>(cp));
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

void WriteError(const std::string_view error) {
    std::cout << "{\"ok\":false,\"error\":\"" << EscapeJson(error) << "\"}\n";
}

void WriteStatus(const AnarStatus status) {
    WriteError(safeanar::ToString(status));
}

void WriteOkSimple() {
    std::cout << "{\"ok\":true}\n";
}

void WriteOkHex(const std::string_view key, const std::string_view value) {
    std::cout << "{\"ok\":true,\"" << key << "\":\"" << EscapeJson(value) << "\"}\n";
}

void WriteOkBytesProcessed(const std::size_t bytes_processed) {
    std::cout << "{\"ok\":true,\"bytes_processed\":" << bytes_processed << "}\n";
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
            WriteStatus(AnarStatus::BadJson);
            std::cout.flush();
            continue;
        }

        const std::string op = GetString(request, "op");
        if (op == "ping") {
            WriteOkSimple();
            std::cout.flush();
            continue;
        }

        if (op == "aes256_ecb_encrypt") {
            const std::string key_hex = GetString(request, "key_hex");
            const std::string plaintext_hex = GetString(request, "plaintext_hex");
            std::string ciphertext_hex;
            const AnarStatus status = safeanar::CryptoEngine::Aes256EcbEncryptHex(key_hex, plaintext_hex, ciphertext_hex);
            if (status != AnarStatus::Ok) {
                WriteStatus(status);
            } else {
                WriteOkHex("ciphertext_hex", ciphertext_hex);
            }
            std::cout.flush();
            continue;
        }

        if (op == "aes256_ecb_decrypt") {
            const std::string key_hex = GetString(request, "key_hex");
            const std::string ciphertext_hex = GetString(request, "ciphertext_hex");
            std::string plaintext_hex;
            const AnarStatus status = safeanar::CryptoEngine::Aes256EcbDecryptHex(key_hex, ciphertext_hex, plaintext_hex);
            if (status != AnarStatus::Ok) {
                WriteStatus(status);
            } else {
                WriteOkHex("plaintext_hex", plaintext_hex);
            }
            std::cout.flush();
            continue;
        }

        if (op == "otp_xor_bytes") {
            const std::string data_hex = GetString(request, "data_hex");
            const std::string key_hex = GetString(request, "key_hex");
            std::string result_hex;
            const AnarStatus status = safeanar::CryptoEngine::OtpXorBytesHex(data_hex, key_hex, result_hex);
            if (status != AnarStatus::Ok) {
                WriteStatus(status);
            } else {
                WriteOkHex("result_hex", result_hex);
            }
            std::cout.flush();
            continue;
        }

        if (op == "otp_xor_file") {
            const std::string input_path = GetString(request, "input_path");
            const std::string key_path = GetString(request, "key_path");
            const std::string output_path = GetString(request, "output_path");
            std::size_t bytes_processed = 0;
            const AnarStatus status =
                safeanar::CryptoEngine::OtpXorFile(input_path, key_path, output_path, bytes_processed);
            if (status != AnarStatus::Ok) {
                WriteStatus(status);
            } else {
                WriteOkBytesProcessed(bytes_processed);
            }
            std::cout.flush();
            continue;
        }

        WriteStatus(AnarStatus::UnknownOp);
        std::cout.flush();
    }

    return 0;
}

