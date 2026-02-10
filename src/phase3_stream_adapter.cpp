#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "safeanar/anar_status.hpp"
#include "safeanar/stream_packer.hpp"

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
                        std::uint32_t codepoint = 0;
                        if (!ParseHex4(codepoint)) {
                            return false;
                        }
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

long long GetNumber(const JsonValue& object, const std::string_view key, const long long fallback = 0) {
    const JsonValue* value = FindObjectMember(object, key);
    if (value == nullptr || value->type != JsonValue::Type::Number) {
        return fallback;
    }
    return value->number_value;
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

void WriteOkEntryCountBytes(const std::size_t entry_count, const std::size_t bytes_written) {
    std::cout << "{\"ok\":true,\"entry_count\":" << entry_count
              << ",\"bytes_written\":" << bytes_written << "}\n";
}

void WriteOkEntries(const std::vector<safeanar::ArchiveEntry>& entries) {
    std::cout << "{\"ok\":true,\"entries\":[";
    for (std::size_t i = 0; i < entries.size(); ++i) {
        if (i > 0) {
            std::cout << ",";
        }
        std::cout << "{\"path\":\"" << EscapeJson(entries[i].path) << "\",\"size\":" << entries[i].size << "}";
    }
    std::cout << "],\"entry_count\":" << entries.size() << "}\n";
}

void WriteOkExtracted(const std::size_t extracted_count) {
    std::cout << "{\"ok\":true,\"extracted_count\":" << extracted_count << "}\n";
}

void WriteOkPadded(const std::size_t bytes_written, const std::uint64_t real_size) {
    std::cout << "{\"ok\":true,\"bytes_written\":" << bytes_written
              << ",\"real_size\":" << real_size << "}\n";
}

void WriteOkInspectPadded(const std::uint64_t real_size, const std::uint64_t total_size) {
    std::cout << "{\"ok\":true,\"real_size\":" << real_size
              << ",\"total_size\":" << total_size << "}\n";
}

void WriteOkBytesWritten(const std::size_t bytes_written) {
    std::cout << "{\"ok\":true,\"bytes_written\":" << bytes_written << "}\n";
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

        if (op == "pack_path") {
            const std::string input_path = GetString(request, "input_path");
            const std::string output_path = GetString(request, "output_path");
            std::size_t entry_count = 0;
            std::size_t bytes_written = 0;
            const AnarStatus status = safeanar::StreamPacker::PackPath(
                input_path, output_path, entry_count, bytes_written);
            if (status != AnarStatus::Ok) {
                WriteStatus(status);
            } else {
                WriteOkEntryCountBytes(entry_count, bytes_written);
            }
            std::cout.flush();
            continue;
        }

        if (op == "inspect_archive") {
            const std::string input_path = GetString(request, "input_path");
            std::vector<safeanar::ArchiveEntry> entries;
            const AnarStatus status = safeanar::StreamPacker::InspectArchive(input_path, entries);
            if (status != AnarStatus::Ok) {
                WriteStatus(status);
            } else {
                WriteOkEntries(entries);
            }
            std::cout.flush();
            continue;
        }

        if (op == "unpack_path") {
            const std::string input_path = GetString(request, "input_path");
            const std::string output_dir = GetString(request, "output_dir");
            std::size_t extracted_count = 0;
            const AnarStatus status = safeanar::StreamPacker::UnpackPath(input_path, output_dir, extracted_count);
            if (status != AnarStatus::Ok) {
                WriteStatus(status);
            } else {
                WriteOkExtracted(extracted_count);
            }
            std::cout.flush();
            continue;
        }

        if (op == "pad_file") {
            const std::string input_path = GetString(request, "input_path");
            const std::string output_path = GetString(request, "output_path");
            const long long target_number = GetNumber(request, "target_size", -1);
            if (target_number < 0) {
                WriteStatus(AnarStatus::InvalidPaddingTarget);
                std::cout.flush();
                continue;
            }
            std::size_t bytes_written = 0;
            std::uint64_t real_size = 0;
            const AnarStatus status = safeanar::StreamPacker::PadFile(
                input_path,
                output_path,
                static_cast<std::uint64_t>(target_number),
                real_size,
                bytes_written);
            if (status != AnarStatus::Ok) {
                WriteStatus(status);
            } else {
                WriteOkPadded(bytes_written, real_size);
            }
            std::cout.flush();
            continue;
        }

        if (op == "inspect_padded") {
            const std::string input_path = GetString(request, "input_path");
            std::uint64_t real_size = 0;
            std::uint64_t total_size = 0;
            const AnarStatus status = safeanar::StreamPacker::InspectPadded(input_path, real_size, total_size);
            if (status != AnarStatus::Ok) {
                WriteStatus(status);
            } else {
                WriteOkInspectPadded(real_size, total_size);
            }
            std::cout.flush();
            continue;
        }

        if (op == "unpad_file") {
            const std::string input_path = GetString(request, "input_path");
            const std::string output_path = GetString(request, "output_path");
            std::size_t bytes_written = 0;
            const AnarStatus status = safeanar::StreamPacker::UnpadFile(input_path, output_path, bytes_written);
            if (status != AnarStatus::Ok) {
                WriteStatus(status);
            } else {
                WriteOkBytesWritten(bytes_written);
            }
            std::cout.flush();
            continue;
        }

        WriteStatus(AnarStatus::UnknownOp);
        std::cout.flush();
    }

    return 0;
}

