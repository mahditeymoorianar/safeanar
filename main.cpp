#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#ifdef DeleteFile
#undef DeleteFile
#endif
#endif

#include "safeanar/anar_status.hpp"
#include "safeanar/crypto_protocol.hpp"
#include "safeanar/key_generator.hpp"
#include "safeanar/protocol_factory.hpp"
#include "safeanar/secure_delete.hpp"
#include "safeanar/stream_packer.hpp"

namespace {

constexpr std::array<char, 6> kContainerMagic = {'S', 'C', 'L', 'I', '1', '\0'};
constexpr std::uint8_t kContainerVersion = 2;
constexpr std::uint8_t kProtoAes = 0;
constexpr std::uint8_t kProtoOtp = 1;
constexpr std::uint8_t kKindFile = 0;
constexpr std::uint8_t kKindDir = 1;
constexpr std::uint8_t kKindText = 2;
constexpr std::size_t kContainerNonceSize = 16;

struct CliOptions {
    bool encrypt = false;
    bool decrypt = false;
    bool help = false;
    bool fast = false;
    bool log = false;
    std::optional<std::string> path;
    std::optional<std::string> text;
    std::optional<std::string> out;
    std::optional<std::string> key;
    std::optional<std::string> key_file;
    std::optional<std::uint64_t> padding_size_bytes;
    std::string protocol = "aes";
};

struct DeleteOptions {
    bool help = false;
    std::optional<std::string> path;
    std::size_t passes = 7;
};

struct KeygenOptions {
    bool help = false;
    std::optional<std::string> mode;
    std::size_t word_count = safeanar::kDefaultGeneratedWordCount;
    std::size_t char_length = safeanar::kDefaultGeneratedCharCount;
    bool saw_count = false;
    bool saw_length = false;
};

struct ContainerData {
    std::uint8_t version = 0;
    std::uint8_t protocol_id = 0;
    std::uint8_t kind_id = 0;
    std::string name;
    std::array<std::uint8_t, kContainerNonceSize> nonce{};
    std::array<std::uint8_t, 32> auth_tag{};
    std::vector<std::uint8_t> ciphertext;
};

std::uint32_t RotRight32(const std::uint32_t v, const std::uint32_t n) {
    return (v >> n) | (v << (32U - n));
}

std::array<std::uint8_t, 32> Sha256(const std::vector<std::uint8_t>& data) {
    static constexpr std::array<std::uint32_t, 64> k = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

    std::array<std::uint32_t, 8> h = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};

    std::vector<std::uint8_t> msg = data;
    const std::uint64_t bit_len = static_cast<std::uint64_t>(msg.size()) * 8ULL;
    msg.push_back(0x80U);
    while ((msg.size() % 64U) != 56U) {
        msg.push_back(0U);
    }
    for (int i = 7; i >= 0; --i) {
        msg.push_back(static_cast<std::uint8_t>((bit_len >> (i * 8)) & 0xFFU));
    }

    std::array<std::uint32_t, 64> w{};
    for (std::size_t chunk = 0; chunk < msg.size(); chunk += 64U) {
        for (int i = 0; i < 16; ++i) {
            const std::size_t idx = chunk + static_cast<std::size_t>(i * 4);
            w[i] =
                (static_cast<std::uint32_t>(msg[idx]) << 24U) |
                (static_cast<std::uint32_t>(msg[idx + 1]) << 16U) |
                (static_cast<std::uint32_t>(msg[idx + 2]) << 8U) |
                static_cast<std::uint32_t>(msg[idx + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            const std::uint32_t s0 = RotRight32(w[i - 15], 7) ^ RotRight32(w[i - 15], 18) ^ (w[i - 15] >> 3U);
            const std::uint32_t s1 = RotRight32(w[i - 2], 17) ^ RotRight32(w[i - 2], 19) ^ (w[i - 2] >> 10U);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        std::uint32_t a = h[0];
        std::uint32_t b = h[1];
        std::uint32_t c = h[2];
        std::uint32_t d = h[3];
        std::uint32_t e = h[4];
        std::uint32_t f = h[5];
        std::uint32_t g = h[6];
        std::uint32_t hh = h[7];

        for (int i = 0; i < 64; ++i) {
            const std::uint32_t s1 = RotRight32(e, 6) ^ RotRight32(e, 11) ^ RotRight32(e, 25);
            const std::uint32_t ch = (e & f) ^ ((~e) & g);
            const std::uint32_t temp1 = hh + s1 + ch + k[i] + w[i];
            const std::uint32_t s0 = RotRight32(a, 2) ^ RotRight32(a, 13) ^ RotRight32(a, 22);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t temp2 = s0 + maj;

            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    std::array<std::uint8_t, 32> out{};
    for (int i = 0; i < 8; ++i) {
        out[static_cast<std::size_t>(i * 4)] = static_cast<std::uint8_t>((h[i] >> 24U) & 0xFFU);
        out[static_cast<std::size_t>(i * 4 + 1)] = static_cast<std::uint8_t>((h[i] >> 16U) & 0xFFU);
        out[static_cast<std::size_t>(i * 4 + 2)] = static_cast<std::uint8_t>((h[i] >> 8U) & 0xFFU);
        out[static_cast<std::size_t>(i * 4 + 3)] = static_cast<std::uint8_t>(h[i] & 0xFFU);
    }
    return out;
}

std::array<std::uint8_t, 8> ToLittle64(const std::uint64_t value) {
    return {
        static_cast<std::uint8_t>(value & 0xFFU),
        static_cast<std::uint8_t>((value >> 8U) & 0xFFU),
        static_cast<std::uint8_t>((value >> 16U) & 0xFFU),
        static_cast<std::uint8_t>((value >> 24U) & 0xFFU),
        static_cast<std::uint8_t>((value >> 32U) & 0xFFU),
        static_cast<std::uint8_t>((value >> 40U) & 0xFFU),
        static_cast<std::uint8_t>((value >> 48U) & 0xFFU),
        static_cast<std::uint8_t>((value >> 56U) & 0xFFU)};
}

std::uint16_t ReadLittle16(const std::vector<std::uint8_t>& bytes, const std::size_t pos) {
    return static_cast<std::uint16_t>(bytes[pos] | (static_cast<std::uint16_t>(bytes[pos + 1]) << 8U));
}

std::uint64_t ReadLittle64(const std::vector<std::uint8_t>& bytes, const std::size_t pos) {
    return
        static_cast<std::uint64_t>(bytes[pos]) |
        (static_cast<std::uint64_t>(bytes[pos + 1]) << 8U) |
        (static_cast<std::uint64_t>(bytes[pos + 2]) << 16U) |
        (static_cast<std::uint64_t>(bytes[pos + 3]) << 24U) |
        (static_cast<std::uint64_t>(bytes[pos + 4]) << 32U) |
        (static_cast<std::uint64_t>(bytes[pos + 5]) << 40U) |
        (static_cast<std::uint64_t>(bytes[pos + 6]) << 48U) |
        (static_cast<std::uint64_t>(bytes[pos + 7]) << 56U);
}

bool ParseByteSize(const std::string& text, std::uint64_t& out_bytes) {
    if (text.empty()) {
        return false;
    }

    std::size_t split = 0;
    while (split < text.size() && std::isdigit(static_cast<unsigned char>(text[split])) != 0) {
        ++split;
    }
    if (split == 0) {
        return false;
    }

    std::size_t parsed_chars = 0;
    unsigned long long magnitude = 0;
    try {
        magnitude = std::stoull(text.substr(0, split), &parsed_chars);
    } catch (...) {
        return false;
    }
    if (parsed_chars != split || magnitude == 0) {
        return false;
    }

    std::string suffix = text.substr(split);
    std::transform(suffix.begin(), suffix.end(), suffix.begin(), [](const unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });

    std::uint64_t multiplier = 1;
    if (suffix.empty() || suffix == "B") {
        multiplier = 1;
    } else if (suffix == "KB") {
        multiplier = 1000ULL;
    } else if (suffix == "MB") {
        multiplier = 1000ULL * 1000ULL;
    } else if (suffix == "GB") {
        multiplier = 1000ULL * 1000ULL * 1000ULL;
    } else if (suffix == "TB") {
        multiplier = 1000ULL * 1000ULL * 1000ULL * 1000ULL;
    } else {
        return false;
    }

    const auto max_u64 = std::numeric_limits<std::uint64_t>::max();
    if (magnitude > max_u64 / multiplier) {
        return false;
    }
    out_bytes = static_cast<std::uint64_t>(magnitude) * multiplier;
    return out_bytes > 0;
}

std::string UnquotePathArg(std::string value) {
    if (value.size() < 2) {
        return value;
    }
    const char first = value.front();
    const char last = value.back();
    if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
        return value.substr(1, value.size() - 2);
    }
    return value;
}

std::filesystem::path PathFromUtf8(const std::string& value) {
#ifdef _WIN32
    const auto* begin = reinterpret_cast<const char8_t*>(value.data());
    const auto* end = begin + value.size();
    return std::filesystem::path(std::u8string(begin, end));
#else
    return std::filesystem::path(value);
#endif
}

std::string Utf8FromPath(const std::filesystem::path& value) {
#ifdef _WIN32
    const std::u8string u8 = value.generic_u8string();
    return std::string(reinterpret_cast<const char*>(u8.data()), u8.size());
#else
    return value.generic_string();
#endif
}

#ifdef _WIN32
bool WideToUtf8(const wchar_t* input, std::string& out) {
    out.clear();
    if (input == nullptr) {
        return false;
    }
    const int required = WideCharToMultiByte(CP_UTF8, 0, input, -1, nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return false;
    }
    std::vector<char> converted(static_cast<std::size_t>(required), '\0');
    const int written = WideCharToMultiByte(CP_UTF8, 0, input, -1, converted.data(), required, nullptr, nullptr);
    if (written <= 0) {
        return false;
    }
    out.assign(converted.data(), static_cast<std::size_t>(written - 1));
    return true;
}

bool BuildUtf8ArgsFromCommandLine(std::vector<std::string>& out_args) {
    out_args.clear();
    int wide_argc = 0;
    LPWSTR* wide_argv = CommandLineToArgvW(GetCommandLineW(), &wide_argc);
    if (wide_argv == nullptr || wide_argc <= 0) {
        return false;
    }

    out_args.reserve(static_cast<std::size_t>(wide_argc));
    bool ok = true;
    for (int i = 0; i < wide_argc; ++i) {
        std::string converted;
        if (!WideToUtf8(wide_argv[i], converted)) {
            ok = false;
            break;
        }
        out_args.push_back(std::move(converted));
    }
    LocalFree(wide_argv);
    return ok;
}
#endif

void CliLog(const CliOptions& opts, const std::string& message) {
    if (!opts.log) {
        return;
    }
    std::cerr << "[log] " << message << "\n";
}

void SecureWipeBytes(std::vector<std::uint8_t>& bytes) {
    volatile std::uint8_t* ptr = bytes.data();
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        ptr[i] = 0U;
    }
    bytes.clear();
}

void SecureWipeString(std::string& value) {
    volatile char* ptr = value.data();
    for (std::size_t i = 0; i < value.size(); ++i) {
        ptr[i] = '\0';
    }
    value.clear();
}

template <std::size_t N>
void SecureWipeArray(std::array<std::uint8_t, N>& bytes) {
    volatile std::uint8_t* ptr = bytes.data();
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        ptr[i] = 0U;
    }
}

bool ConstantTimeEqual(const std::array<std::uint8_t, 32>& lhs, const std::array<std::uint8_t, 32>& rhs) {
    std::uint8_t diff = 0U;
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        diff = static_cast<std::uint8_t>(diff | static_cast<std::uint8_t>(lhs[i] ^ rhs[i]));
    }
    return diff == 0U;
}

void RandomAuthFailureDelay() {
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> delay_ms(35, 140);
    std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms(rng)));
}

std::array<std::uint8_t, kContainerNonceSize> RandomNonce() {
    std::array<std::uint8_t, kContainerNonceSize> nonce{};
    std::random_device rd;
    for (std::size_t i = 0; i < nonce.size(); ++i) {
        nonce[i] = static_cast<std::uint8_t>(rd() & 0xFFU);
    }
    return nonce;
}

bool FillRandomBytes(std::uint8_t* out, const std::size_t length) {
    if (length == 0 || out == nullptr) {
        return true;
    }
    try {
        std::random_device rd;
        std::size_t written = 0;
        while (written < length) {
            const auto value = rd();
            for (std::size_t i = 0; i < sizeof(value) && written < length; ++i) {
                out[written++] = static_cast<std::uint8_t>((value >> (i * 8U)) & 0xFFU);
            }
        }
        return true;
    } catch (...) {
        return false;
    }
}

bool ReadFileBytes(const std::string& path, std::vector<std::uint8_t>& out) {
    const std::filesystem::path p = PathFromUtf8(path);
    std::ifstream in(p, std::ios::binary);
    if (!in.is_open()) {
        return false;
    }
    in.seekg(0, std::ios::end);
    const std::streamoff size_off = in.tellg();
    if (size_off < 0) {
        return false;
    }
    const auto size = static_cast<std::size_t>(size_off);
    in.seekg(0, std::ios::beg);
    out.resize(size);
    if (size > 0) {
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(size));
        if (static_cast<std::size_t>(in.gcount()) != size) {
            return false;
        }
    }
    return true;
}

bool WriteFileBytes(const std::string& path, const std::vector<std::uint8_t>& bytes) {
    std::error_code ec;
    const std::filesystem::path p = PathFromUtf8(path);
    const auto parent = p.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return false;
        }
    }
    std::ofstream out(p, std::ios::binary);
    if (!out.is_open()) {
        return false;
    }
    if (!bytes.empty()) {
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    return out.good();
}

std::string MakeTempPath(const std::string_view prefix) {
    std::error_code ec;
    std::filesystem::path dir = std::filesystem::temp_directory_path(ec);
    if (ec) {
        dir = std::filesystem::current_path(ec);
        if (ec) {
            dir = ".";
        }
    }

    std::mt19937_64 rng(std::random_device{}());
    std::uint64_t r = rng();
    std::string name(prefix);
    name += "_";
    static constexpr char hex[] = "0123456789abcdef";
    for (int i = 0; i < 16; ++i) {
        name.push_back(hex[(r >> ((15 - i) * 4U)) & 0x0FU]);
    }
    name += ".tmp";

    return Utf8FromPath(dir / name);
}

bool HasSufficientOutputSpace(const std::string& output_path, const std::uint64_t required_bytes) {
    std::error_code ec;
    const std::filesystem::path out = PathFromUtf8(output_path);
    std::filesystem::path parent = out.parent_path();
    if (parent.empty()) {
        parent = ".";
    }
    std::filesystem::create_directories(parent, ec);
    if (ec) {
        return false;
    }

    std::uint64_t existing_size = 0;
    if (std::filesystem::is_regular_file(out, ec) && !ec) {
        existing_size = static_cast<std::uint64_t>(std::filesystem::file_size(out, ec));
        if (ec) {
            existing_size = 0;
            ec.clear();
        }
    }

    const auto info = std::filesystem::space(parent, ec);
    if (ec) {
        return true;
    }
    const std::uint64_t available = info.available;
    if (available >= required_bytes) {
        return true;
    }
    if (existing_size > std::numeric_limits<std::uint64_t>::max() - available) {
        return true;
    }
    return (available + existing_size) >= required_bytes;
}

std::vector<std::uint8_t> ToBytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

std::vector<std::uint8_t> Concat(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b) {
    std::vector<std::uint8_t> out;
    out.reserve(a.size() + b.size());
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

void XorWithKeyStream(
    const std::vector<std::uint8_t>& key_bytes,
    const std::uint8_t protocol_id,
    const std::vector<std::uint8_t>& input,
    std::vector<std::uint8_t>& output) {
    output.resize(input.size());
    std::uint64_t counter = 0;
    std::size_t offset = 0;
    while (offset < input.size()) {
        std::vector<std::uint8_t> seed;
        seed.reserve(key_bytes.size() + 1 + 8);
        seed.insert(seed.end(), key_bytes.begin(), key_bytes.end());
        seed.push_back(protocol_id);
        const auto ctr = ToLittle64(counter);
        seed.insert(seed.end(), ctr.begin(), ctr.end());
        const auto block = Sha256(seed);
        const std::size_t n = std::min<std::size_t>(block.size(), input.size() - offset);
        for (std::size_t i = 0; i < n; ++i) {
            output[offset + i] = static_cast<std::uint8_t>(input[offset + i] ^ block[i]);
        }
        offset += n;
        ++counter;
    }
}

safeanar::AnarStatus LegacyApplyCipher(
    const std::uint8_t protocol_id,
    const std::vector<std::uint8_t>& key_bytes,
    const bool use_raw_otp_key_bytes,
    const std::vector<std::uint8_t>& input,
    std::vector<std::uint8_t>& output) {
    if (protocol_id == kProtoOtp && use_raw_otp_key_bytes) {
        if (key_bytes.size() < input.size()) {
            return safeanar::AnarStatus::KeyTooShort;
        }
        output.resize(input.size());
        for (std::size_t i = 0; i < input.size(); ++i) {
            output[i] = static_cast<std::uint8_t>(input[i] ^ key_bytes[i]);
        }
        return safeanar::AnarStatus::Ok;
    }

    XorWithKeyStream(key_bytes, protocol_id, input, output);
    return safeanar::AnarStatus::Ok;
}

safeanar::AnarStatus ResolveKeyBytes(const CliOptions& opts, std::vector<std::uint8_t>& out_key_bytes) {
    out_key_bytes.clear();
    if (opts.key.has_value()) {
        out_key_bytes = ToBytes(*opts.key);
        return safeanar::AnarStatus::Ok;
    }
    if (!opts.key_file.has_value()) {
        return safeanar::AnarStatus::InvalidLength;
    }
    if (!ReadFileBytes(*opts.key_file, out_key_bytes)) {
        return safeanar::AnarStatus::FileIOError;
    }
    return safeanar::AnarStatus::Ok;
}

std::vector<std::uint8_t> BuildContainer(
    const std::uint8_t protocol_id,
    const std::uint8_t kind_id,
    const std::string& name,
    const std::array<std::uint8_t, kContainerNonceSize>& nonce,
    const std::array<std::uint8_t, 32>& auth_tag,
    const std::vector<std::uint8_t>& ciphertext) {
    const auto name_bytes = ToBytes(name);
    const std::uint16_t name_len = static_cast<std::uint16_t>(name_bytes.size());
    const auto payload_size = static_cast<std::uint64_t>(ciphertext.size());

    std::vector<std::uint8_t> out;
    out.reserve(
        kContainerMagic.size() + 3 + 2 + 8 + kContainerNonceSize + 32 +
        name_bytes.size() + ciphertext.size());

    out.insert(out.end(), kContainerMagic.begin(), kContainerMagic.end());
    out.push_back(kContainerVersion);
    out.push_back(protocol_id);
    out.push_back(kind_id);
    out.push_back(static_cast<std::uint8_t>(name_len & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((name_len >> 8U) & 0xFFU));
    const auto payload_le = ToLittle64(payload_size);
    out.insert(out.end(), payload_le.begin(), payload_le.end());
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), auth_tag.begin(), auth_tag.end());
    out.insert(out.end(), name_bytes.begin(), name_bytes.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    return out;
}

bool ParseContainer(const std::vector<std::uint8_t>& bytes, ContainerData& out_data) {
    const std::size_t min_size_v1 = kContainerMagic.size() + 3 + 2 + 8 + 32;
    const std::size_t min_size_v2 = min_size_v1 + kContainerNonceSize;
    if (bytes.size() < min_size_v1) {
        return false;
    }
    std::size_t pos = 0;
    if (!std::equal(kContainerMagic.begin(), kContainerMagic.end(), bytes.begin())) {
        return false;
    }
    pos += kContainerMagic.size();

    out_data.version = bytes[pos++];
    out_data.protocol_id = bytes[pos++];
    out_data.kind_id = bytes[pos++];
    if (out_data.version != 1 && out_data.version != kContainerVersion) {
        return false;
    }
    if (out_data.version == kContainerVersion && bytes.size() < min_size_v2) {
        return false;
    }
    if (out_data.protocol_id != kProtoAes && out_data.protocol_id != kProtoOtp) {
        return false;
    }
    if (out_data.kind_id != kKindFile && out_data.kind_id != kKindDir && out_data.kind_id != kKindText) {
        return false;
    }

    const std::uint16_t name_len = ReadLittle16(bytes, pos);
    pos += 2;
    const std::uint64_t payload_size = ReadLittle64(bytes, pos);
    pos += 8;

    out_data.nonce.fill(0U);
    if (out_data.version == kContainerVersion) {
        if (pos + kContainerNonceSize > bytes.size()) {
            return false;
        }
        std::copy(
            bytes.begin() + static_cast<std::ptrdiff_t>(pos),
            bytes.begin() + static_cast<std::ptrdiff_t>(pos + kContainerNonceSize),
            out_data.nonce.begin());
        pos += kContainerNonceSize;
    }

    if (pos + out_data.auth_tag.size() > bytes.size()) {
        return false;
    }
    std::copy(
        bytes.begin() + static_cast<std::ptrdiff_t>(pos),
        bytes.begin() + static_cast<std::ptrdiff_t>(pos + out_data.auth_tag.size()),
        out_data.auth_tag.begin());
    pos += out_data.auth_tag.size();

    if (pos + name_len > bytes.size()) {
        return false;
    }
    out_data.name.assign(
        reinterpret_cast<const char*>(bytes.data() + pos),
        reinterpret_cast<const char*>(bytes.data() + pos + name_len));
    pos += name_len;

    if (payload_size > static_cast<std::uint64_t>(bytes.size() - pos)) {
        return false;
    }
    if (payload_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max() - pos)) {
        return false;
    }
    const std::size_t payload_end = pos + static_cast<std::size_t>(payload_size);

    out_data.ciphertext.assign(
        bytes.begin() + static_cast<std::ptrdiff_t>(pos),
        bytes.begin() + static_cast<std::ptrdiff_t>(payload_end));
    return true;
}

safeanar::AnarStatus WriteContainerOutput(const std::vector<std::uint8_t>& container, const CliOptions& opts) {
    const std::uint64_t required_output_size = opts.padding_size_bytes.has_value() ?
        *opts.padding_size_bytes :
        static_cast<std::uint64_t>(container.size());
    if (required_output_size < container.size()) {
        return safeanar::AnarStatus::InvalidPaddingTarget;
    }
    if (!HasSufficientOutputSpace(*opts.out, required_output_size)) {
        return safeanar::AnarStatus::FileIOError;
    }

    if (!opts.padding_size_bytes.has_value()) {
        if (!WriteFileBytes(*opts.out, container)) {
            return safeanar::AnarStatus::FileIOError;
        }
        return safeanar::AnarStatus::Ok;
    }

    std::error_code ec;
    const std::filesystem::path out_path = PathFromUtf8(*opts.out);
    const auto parent = out_path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return safeanar::AnarStatus::FileIOError;
        }
    }

    std::ofstream out(out_path, std::ios::binary);
    if (!out.is_open()) {
        return safeanar::AnarStatus::FileIOError;
    }

    if (!container.empty()) {
        out.write(reinterpret_cast<const char*>(container.data()), static_cast<std::streamsize>(container.size()));
        if (!out.good()) {
            return safeanar::AnarStatus::FileIOError;
        }
    }

    std::uint64_t remaining = *opts.padding_size_bytes - static_cast<std::uint64_t>(container.size());
    std::vector<std::uint8_t> random_chunk(8192, 0U);
    while (remaining > 0) {
        const std::size_t chunk = remaining > random_chunk.size() ? random_chunk.size() : static_cast<std::size_t>(remaining);
        if (!FillRandomBytes(random_chunk.data(), chunk)) {
            SecureWipeBytes(random_chunk);
            return safeanar::AnarStatus::MissingRngBytes;
        }
        out.write(reinterpret_cast<const char*>(random_chunk.data()), static_cast<std::streamsize>(chunk));
        if (!out.good()) {
            SecureWipeBytes(random_chunk);
            return safeanar::AnarStatus::FileIOError;
        }
        remaining -= static_cast<std::uint64_t>(chunk);
    }
    SecureWipeBytes(random_chunk);
    return safeanar::AnarStatus::Ok;
}

safeanar::AnarStatus LoadCipherInputBytes(const CliOptions& opts, std::vector<std::uint8_t>& out_bytes) {
    std::vector<std::uint8_t> file_bytes;
    if (!ReadFileBytes(*opts.path, file_bytes)) {
        return safeanar::AnarStatus::FileIOError;
    }

    std::uint64_t real_size = 0;
    std::uint64_t total_size = 0;
    const safeanar::AnarStatus inspect_status =
        safeanar::StreamPacker::InspectPaddedBytes(file_bytes, real_size, total_size);
    if (inspect_status == safeanar::AnarStatus::Ok) {
        const safeanar::AnarStatus unpad_status = safeanar::StreamPacker::UnpadBytes(file_bytes, out_bytes);
        SecureWipeBytes(file_bytes);
        return unpad_status;
    }
    if (inspect_status == safeanar::AnarStatus::InvalidArchive) {
        out_bytes = std::move(file_bytes);
        return safeanar::AnarStatus::Ok;
    }

    SecureWipeBytes(file_bytes);
    return inspect_status;
}

safeanar::AnarStatus CreateProtocolByName(
    const std::string& protocol_name,
    const CliOptions& opts,
    std::unique_ptr<safeanar::ICryptoProtocol>& out_protocol) {
    safeanar::ProtocolFactoryOptions options;
    options.fast = opts.fast;
    safeanar::AnarStatus status = safeanar::AnarStatus::UnknownOp;
    out_protocol = safeanar::ProtocolFactory::Create(protocol_name, options, status);
    return status;
}

safeanar::AnarStatus CreateProtocolById(
    const std::uint8_t protocol_id,
    const CliOptions& opts,
    std::unique_ptr<safeanar::ICryptoProtocol>& out_protocol) {
    if (protocol_id == kProtoAes) {
        return CreateProtocolByName("aes", opts, out_protocol);
    }
    if (protocol_id == kProtoOtp) {
        return CreateProtocolByName("otp", opts, out_protocol);
    }
    return safeanar::AnarStatus::UnknownOp;
}

safeanar::AnarStatus PrepareProtocolKey(
    const std::uint8_t protocol_id,
    const std::vector<std::uint8_t>& raw_key_bytes,
    std::vector<std::uint8_t>& out_key_bytes) {
    out_key_bytes.clear();
    if (protocol_id == kProtoAes) {
        const auto digest = Sha256(raw_key_bytes);
        out_key_bytes.assign(digest.begin(), digest.end());
        return safeanar::AnarStatus::Ok;
    }
    if (protocol_id == kProtoOtp) {
        out_key_bytes = raw_key_bytes;
        return safeanar::AnarStatus::Ok;
    }
    return safeanar::AnarStatus::UnknownOp;
}

safeanar::AnarStatus EncryptPayload(
    const CliOptions& opts,
    const std::uint8_t protocol_id,
    const std::vector<std::uint8_t>& raw_key_bytes,
    const std::array<std::uint8_t, kContainerNonceSize>& nonce,
    const std::vector<std::uint8_t>& plaintext,
    std::vector<std::uint8_t>& out_ciphertext,
    std::vector<std::uint8_t>& out_protocol_key,
    const std::function<void(std::size_t, std::size_t)>& progress) {
    out_ciphertext.clear();
    out_protocol_key.clear();

    const safeanar::AnarStatus key_status = PrepareProtocolKey(protocol_id, raw_key_bytes, out_protocol_key);
    if (key_status != safeanar::AnarStatus::Ok) {
        return key_status;
    }

    std::unique_ptr<safeanar::ICryptoProtocol> protocol;
    const safeanar::AnarStatus create_status = CreateProtocolById(protocol_id, opts, protocol);
    if (create_status != safeanar::AnarStatus::Ok || protocol == nullptr) {
        return safeanar::AnarStatus::UnknownOp;
    }
    if (protocol->RequiresKeyFile() && !opts.key_file.has_value()) {
        return safeanar::AnarStatus::InvalidKeyLength;
    }
    return protocol->Transform(plaintext, out_protocol_key, nonce, out_ciphertext, progress);
}

safeanar::AnarStatus DecryptPayload(
    const CliOptions& opts,
    const ContainerData& container,
    const std::vector<std::uint8_t>& raw_key_bytes,
    std::vector<std::uint8_t>& out_plaintext,
    std::vector<std::uint8_t>& out_protocol_key,
    const std::function<void(std::size_t, std::size_t)>& progress) {
    out_plaintext.clear();
    out_protocol_key.clear();

    if (container.version == 1) {
        out_protocol_key = raw_key_bytes;
        const bool use_raw_otp_key_bytes = container.protocol_id == kProtoOtp && opts.key_file.has_value();
        return LegacyApplyCipher(
            container.protocol_id,
            raw_key_bytes,
            use_raw_otp_key_bytes,
            container.ciphertext,
            out_plaintext);
    }

    const safeanar::AnarStatus key_status = PrepareProtocolKey(container.protocol_id, raw_key_bytes, out_protocol_key);
    if (key_status != safeanar::AnarStatus::Ok) {
        return key_status;
    }

    std::unique_ptr<safeanar::ICryptoProtocol> protocol;
    const safeanar::AnarStatus create_status = CreateProtocolById(container.protocol_id, opts, protocol);
    if (create_status != safeanar::AnarStatus::Ok || protocol == nullptr) {
        return safeanar::AnarStatus::UnknownOp;
    }
    if (protocol->RequiresKeyFile() && !opts.key_file.has_value()) {
        return safeanar::AnarStatus::InvalidKeyLength;
    }
    return protocol->Transform(container.ciphertext, out_protocol_key, container.nonce, out_plaintext, progress);
}

bool ParseArgs(const int argc, char* argv[], CliOptions& opts, std::string& error) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        auto require_value = [&](std::string& dst) -> bool {
            if (i + 1 >= argc) {
                error = "Missing value for " + arg;
                return false;
            }
            dst = argv[++i];
            return true;
        };

        if (arg == "--encrypt") {
            opts.encrypt = true;
        } else if (arg == "--decrypt") {
            opts.decrypt = true;
        } else if (arg == "--fast") {
            opts.fast = true;
        } else if (arg == "--log") {
            opts.log = true;
        } else if (arg == "--help" || arg == "-h") {
            opts.help = true;
        } else if (arg == "--path") {
            std::string v;
            if (!require_value(v)) {
                return false;
            }
            opts.path = UnquotePathArg(std::move(v));
        } else if (arg == "--text") {
            std::string v;
            if (!require_value(v)) {
                return false;
            }
            opts.text = std::move(v);
        } else if (arg == "--out") {
            std::string v;
            if (!require_value(v)) {
                return false;
            }
            opts.out = UnquotePathArg(std::move(v));
        } else if (arg == "--key") {
            std::string v;
            if (!require_value(v)) {
                return false;
            }
            opts.key = std::move(v);
        } else if (arg == "--key-file") {
            std::string v;
            if (!require_value(v)) {
                return false;
            }
            opts.key_file = UnquotePathArg(std::move(v));
        } else if (arg == "--padding-size") {
            std::string v;
            if (!require_value(v)) {
                return false;
            }
            std::uint64_t parsed = 0;
            if (!ParseByteSize(v, parsed)) {
                error = "Invalid value for --padding-size";
                return false;
            }
            opts.padding_size_bytes = parsed;
        } else if (arg == "--protocol") {
            if (!require_value(opts.protocol)) {
                return false;
            }
        } else {
            error = "Unknown argument: " + arg;
            return false;
        }
    }

    if (opts.help) {
        return true;
    }

    if (opts.encrypt == opts.decrypt) {
        error = "Specify exactly one of --encrypt or --decrypt";
        return false;
    }

    std::transform(opts.protocol.begin(), opts.protocol.end(), opts.protocol.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    const bool has_key = opts.key.has_value();
    const bool has_key_file = opts.key_file.has_value();

    if (opts.encrypt) {
        const bool has_path = opts.path.has_value();
        const bool has_text = opts.text.has_value();
        if (has_path == has_text) {
            error = "Provide exactly one of --path or --text with --encrypt";
            return false;
        }
        if (has_key == has_key_file) {
            error = "Provide exactly one of --key or --key-file";
            return false;
        }
        if (!opts.out.has_value()) {
            error = "Missing required argument --out";
            return false;
        }
        if (opts.protocol != "aes" && opts.protocol != "otp") {
            error = "Invalid protocol";
            return false;
        }
        if (opts.protocol == "otp" && !has_key_file) {
            error = "OTP requires --key-file";
            return false;
        }
        return true;
    }

    if (opts.text.has_value()) {
        error = "--text is not valid with --decrypt";
        return false;
    }
    if (opts.padding_size_bytes.has_value()) {
        error = "--padding-size is only valid with --encrypt";
        return false;
    }
    if (!opts.path.has_value()) {
        error = "Missing required argument --path";
        return false;
    }
    if (has_key == has_key_file) {
        error = "Provide exactly one of --key or --key-file";
        return false;
    }
    if (!opts.out.has_value()) {
        error = "Missing required argument --out";
        return false;
    }
    return true;
}

bool ParseDeleteArgs(const int argc, char* argv[], DeleteOptions& opts, std::string& error) {
    for (int i = 2; i < argc; ++i) {
        const std::string arg(argv[i]);
        auto require_value = [&](std::string& dst) -> bool {
            if (i + 1 >= argc) {
                error = "Missing value for " + arg;
                return false;
            }
            dst = argv[++i];
            return true;
        };

        if (arg == "--help" || arg == "-h") {
            opts.help = true;
        } else if (arg == "--path") {
            std::string value;
            if (!require_value(value)) {
                return false;
            }
            opts.path = UnquotePathArg(std::move(value));
        } else if (arg == "--passes") {
            std::string value;
            if (!require_value(value)) {
                return false;
            }
            std::size_t idx = 0;
            try {
                const unsigned long long parsed = std::stoull(value, &idx);
                if (idx != value.size() ||
                    parsed == 0 ||
                    parsed > static_cast<unsigned long long>(std::numeric_limits<std::size_t>::max())) {
                    error = "Invalid value for --passes";
                    return false;
                }
                opts.passes = static_cast<std::size_t>(parsed);
            } catch (...) {
                error = "Invalid value for --passes";
                return false;
            }
        } else {
            error = "Unknown argument: " + arg;
            return false;
        }
    }

    if (opts.help) {
        return true;
    }
    if (!opts.path.has_value()) {
        error = "Missing required argument --path";
        return false;
    }
    return true;
}

bool ParseKeygenArgs(const int argc, char* argv[], const int start_index, KeygenOptions& opts, std::string& error) {
    for (int i = start_index; i < argc; ++i) {
        const std::string arg(argv[i]);
        auto require_value = [&](std::string& dst) -> bool {
            if (i + 1 >= argc) {
                error = "Missing value for " + arg;
                return false;
            }
            dst = argv[++i];
            return true;
        };
        auto parse_positive_size = [&](const std::string& value, const std::string& flag, std::size_t& out) -> bool {
            std::size_t idx = 0;
            try {
                const unsigned long long parsed = std::stoull(value, &idx);
                if (idx != value.size() ||
                    parsed == 0 ||
                    parsed > static_cast<unsigned long long>(std::numeric_limits<std::size_t>::max())) {
                    error = "Invalid value for " + flag;
                    return false;
                }
                out = static_cast<std::size_t>(parsed);
                return true;
            } catch (...) {
                error = "Invalid value for " + flag;
                return false;
            }
        };

        if (arg == "--help" || arg == "-h") {
            opts.help = true;
        } else if (arg == "--count") {
            std::string value;
            if (!require_value(value) || !parse_positive_size(value, "--count", opts.word_count)) {
                return false;
            }
            opts.saw_count = true;
        } else if (arg == "--length") {
            std::string value;
            if (!require_value(value) || !parse_positive_size(value, "--length", opts.char_length)) {
                return false;
            }
            opts.saw_length = true;
        } else {
            std::string normalized = arg;
            std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](const unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            if (normalized == "words" || normalized == "chars") {
                if (opts.mode.has_value()) {
                    error = "Specify exactly one key mode: words or chars";
                    return false;
                }
                opts.mode = std::move(normalized);
            } else {
                error = "Unknown argument: " + arg;
                return false;
            }
        }
    }

    if (opts.help) {
        return true;
    }
    if (!opts.mode.has_value()) {
        error = "Missing key mode: words or chars";
        return false;
    }
    if (*opts.mode == "words" && opts.saw_length) {
        error = "--length is only valid with chars mode";
        return false;
    }
    if (*opts.mode == "chars" && opts.saw_count) {
        error = "--count is only valid with words mode";
        return false;
    }
    return true;
}

void PrintHelp(std::ostream& out) {
    out << "SafeAnar (prototype) - file/directory/text encryption utility\n\n";
    out << "Usage:\n";
    out << "  safeanar --encrypt --path <file|dir> --out <enc_file> (--key <passphrase>|--key-file <path>)\n";
    out << "           [--protocol aes|otp] [--padding-size <size>] [--fast] [--log]\n";
    out << "  safeanar --encrypt --text <text>     --out <enc_file> (--key <passphrase>|--key-file <path>)\n";
    out << "           [--protocol aes|otp] [--padding-size <size>] [--fast] [--log]\n";
    out << "  safeanar --decrypt --path <enc_file> --out <out_path> (--key <passphrase>|--key-file <path>) [--fast] [--log]\n";
    out << "  safeanar --gen-key <words|chars> [--count N|--length N]\n";
    out << "  safeanar gen-key <words|chars> [--count N|--length N]\n\n";
    out << "  safeanar delete --path <file> [--passes N]\n\n";

    out << "Options:\n";
    out << "  --encrypt            Encrypt input to --out\n";
    out << "  --decrypt            Decrypt --path to --out\n";
    out << "  --gen-key <mode>     Generate random passphrase (modes: words, chars)\n";
    out << "  --count <N>          Word count for key generation (default 32)\n";
    out << "  --length <N>         Char length for key generation (default 43)\n";
    out << "  --path <path>        Input path (encrypt: file/dir, decrypt: encrypted file)\n";
    out << "  --text <text>        Input text (encrypt only)\n";
    out << "  --out <path>         Output (encrypt: encrypted file, decrypt: file or directory)\n";
    out << "  --key <string>       Passphrase (UTF-8 string)\n";
    out << "  --key-file <path>    Key bytes file (required size >= data for otp mode)\n";
    out << "  --protocol <name>    aes (default) or otp\n";
    out << "  --padding-size <N>   Encrypt output to exact size (e.g. 100MB, 1GB)\n";
    out << "  --fast               Enable fast path hint (if available)\n";
    out << "  --log                Show minimal runtime logs/progress\n";
    out << "  --help, -h           Show this help\n\n";

    out << "Examples:\n";
    out << "  safeanar --encrypt --path secret.bin --out secret.enc --key \"my passphrase\"\n";
    out << "  safeanar --decrypt --path secret.enc --out secret.dec --key \"my passphrase\"\n";
    out << "  safeanar --encrypt --path secret.bin --out secret.pad.enc --key \"k\" --padding-size 100MB\n";
    out << "  safeanar --encrypt --path secret.bin --out secret.enc --key-file one_time.key --protocol otp\n";
    out << "  safeanar --decrypt --path secret.enc --out secret.dec --key-file one_time.key\n";
    out << "  safeanar --encrypt --text \"hello\" --out msg.enc --key-file one_time.key --protocol otp\n";
    out << "  safeanar --encrypt --path my_folder --out folder.enc --key \"k\"\n";
    out << "  safeanar --decrypt --path folder.enc --out restored_folder --key \"k\" --fast\n";
    out << "  safeanar --gen-key words\n";
    out << "  safeanar --gen-key chars\n";
    out << "  safeanar gen-key words --count 16\n";
    out << "  safeanar gen-key chars --length 64\n\n";
    out << "  safeanar delete --path old_secret.bin\n";
    out << "  safeanar delete --path old_secret.bin --passes 9\n\n";

    out << "Notes:\n";
    out << "  - This build is a Phase 1-4 prototype implementation.\n";
    out << "  - Path flags accept both plain and quoted values (e.g. C:/data/in.bin or \"C:/data/in.bin\").\n";
    out << "  - Wrong keys fail with a generic: Authentication Failed\n";
    out << "  - Secure delete is best effort; modern filesystems/SSDs may retain traces outside file control.\n";
    out << "  - For more details, see docs/user_guide.md\n";
}

void PrintDeleteHelp(std::ostream& out) {
    out << "SafeAnar delete - secure file deletion (best effort)\n\n";
    out << "Usage:\n";
    out << "  safeanar delete --path <file> [--passes N]\n\n";
    out << "Options:\n";
    out << "  --path <file>        Target regular file to securely delete\n";
    out << "  --passes <N>         Overwrite passes (default 7)\n";
    out << "  --help, -h           Show this help\n\n";
    out << "Warning:\n";
    out << "  - This is best effort. Journaling filesystems, wear leveling SSDs, snapshots, and backups\n";
    out << "    can retain data outside direct file overwrite control.\n";
}

void PrintKeygenHelp(std::ostream& out) {
    out << "SafeAnar key generation\n\n";
    out << "Usage:\n";
    out << "  safeanar --gen-key <words|chars> [--count N|--length N]\n";
    out << "  safeanar gen-key <words|chars> [--count N|--length N]\n\n";
    out << "Modes:\n";
    out << "  words               Output space-separated random words from the built-in 256-word list (default count: 32)\n";
    out << "  chars               Output random characters from [a-zA-Z0-9*!] (default length: 43)\n\n";
    out << "Options:\n";
    out << "  --count <N>         Use with words mode\n";
    out << "  --length <N>        Use with chars mode\n";
    out << "  --help, -h          Show this help\n";
}

int EncryptFlow(const CliOptions& opts) {
    const std::uint8_t protocol_id = opts.protocol == "otp" ? kProtoOtp : kProtoAes;

    std::uint8_t kind_id = kKindText;
    std::string name;
    std::vector<std::uint8_t> plaintext;
    std::vector<std::uint8_t> raw_key_bytes;
    std::vector<std::uint8_t> protocol_key_bytes;
    std::vector<std::uint8_t> ciphertext;
    std::vector<std::uint8_t> container_bytes;
    std::array<std::uint8_t, kContainerNonceSize> nonce{};
    auto cleanup = [&]() {
        SecureWipeBytes(plaintext);
        SecureWipeBytes(raw_key_bytes);
        SecureWipeBytes(protocol_key_bytes);
        SecureWipeBytes(ciphertext);
        SecureWipeBytes(container_bytes);
        SecureWipeArray(nonce);
        SecureWipeString(name);
    };
    CliLog(opts, "Starting encryption");

    if (opts.text.has_value()) {
        kind_id = kKindText;
        name = "";
        plaintext = ToBytes(*opts.text);
        CliLog(opts, "Prepared text input (" + std::to_string(plaintext.size()) + " bytes)");
    } else {
        const std::filesystem::path p = PathFromUtf8(*opts.path);
        std::error_code ec;
        if (std::filesystem::is_regular_file(p, ec) && !ec) {
            kind_id = kKindFile;
            name = Utf8FromPath(p.filename());
            CliLog(opts, "Reading file input: " + *opts.path);
            if (!ReadFileBytes(*opts.path, plaintext)) {
                std::cerr << "FileIOError\n";
                cleanup();
                return 1;
            }
            CliLog(opts, "Read file bytes: " + std::to_string(plaintext.size()));
        } else if (std::filesystem::is_directory(p, ec) && !ec) {
            kind_id = kKindDir;
            name = Utf8FromPath(std::filesystem::absolute(p, ec).filename());
            if (ec || name.empty()) {
                name = Utf8FromPath(p.filename());
            }

            CliLog(opts, "Packing directory into archive bytes (tar-like stream): " + *opts.path);
            std::size_t entry_count = 0;
            const safeanar::AnarStatus status =
                safeanar::StreamPacker::PackPathToBytes(*opts.path, plaintext, entry_count);
            if (status != safeanar::AnarStatus::Ok) {
                std::cerr << safeanar::ToString(status) << "\n";
                cleanup();
                return 1;
            }
            CliLog(
                opts,
                "Packed entries: " + std::to_string(entry_count) +
                    ", bytes: " + std::to_string(plaintext.size()));
        } else {
            std::cerr << "InvalidPath\n";
            cleanup();
            return 1;
        }
    }

    const safeanar::AnarStatus key_status = ResolveKeyBytes(opts, raw_key_bytes);
    if (key_status != safeanar::AnarStatus::Ok) {
        std::cerr << safeanar::ToString(key_status) << "\n";
        cleanup();
        return 1;
    }
    if (protocol_id == kProtoOtp && opts.key_file.has_value() && raw_key_bytes.size() < plaintext.size()) {
        std::cerr << safeanar::ToString(safeanar::AnarStatus::KeyTooShort) << "\n";
        cleanup();
        return 1;
    }

    nonce = RandomNonce();
    int encrypt_percent = -1;
    std::function<void(std::size_t, std::size_t)> encrypt_progress;
    if (opts.log) {
        encrypt_progress = [&](const std::size_t done, const std::size_t total) {
            const std::size_t clamped_done = std::min(done, total);
            const int percent = total == 0 ? 100 : static_cast<int>((clamped_done * 100U) / total);
            if (percent == encrypt_percent) {
                return;
            }
            encrypt_percent = percent;
            std::cerr << "\r[log] Encrypting: " << percent << "%" << std::flush;
            if (percent >= 100) {
                std::cerr << "\n";
            }
        };
    }
    const safeanar::AnarStatus cipher_status = EncryptPayload(
        opts,
        protocol_id,
        raw_key_bytes,
        nonce,
        plaintext,
        ciphertext,
        protocol_key_bytes,
        encrypt_progress);
    if (opts.log && encrypt_percent >= 0 && encrypt_percent < 100) {
        std::cerr << "\n";
    }
    if (cipher_status != safeanar::AnarStatus::Ok) {
        std::cerr << safeanar::ToString(cipher_status) << "\n";
        cleanup();
        return 1;
    }
    CliLog(opts, "Encryption complete");

    const auto auth_tag = Sha256(Concat(protocol_key_bytes, plaintext));
    container_bytes = BuildContainer(protocol_id, kind_id, name, nonce, auth_tag, ciphertext);
    if (container_bytes.empty()) {
        std::cerr << safeanar::ToString(safeanar::AnarStatus::FileIOError) << "\n";
        cleanup();
        return 1;
    }
    CliLog(opts, "Writing output: " + *opts.out);
    const safeanar::AnarStatus write_status = WriteContainerOutput(container_bytes, opts);
    if (write_status != safeanar::AnarStatus::Ok) {
        std::cerr << safeanar::ToString(write_status) << "\n";
        cleanup();
        return 1;
    }
    CliLog(opts, "Done");
    cleanup();
    return 0;
}

int DecryptFlow(const CliOptions& opts) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(PathFromUtf8(*opts.path), ec) || ec) {
        std::cerr << "InvalidPath\n";
        return 1;
    }
    CliLog(opts, "Starting decryption");

    std::vector<std::uint8_t> input_bytes;
    std::vector<std::uint8_t> raw_key_bytes;
    std::vector<std::uint8_t> protocol_key_bytes;
    std::vector<std::uint8_t> plaintext;
    ContainerData container;
    auto cleanup = [&]() {
        SecureWipeBytes(input_bytes);
        SecureWipeBytes(raw_key_bytes);
        SecureWipeBytes(protocol_key_bytes);
        SecureWipeBytes(plaintext);
        SecureWipeBytes(container.ciphertext);
        SecureWipeString(container.name);
        SecureWipeArray(container.nonce);
        SecureWipeArray(container.auth_tag);
    };

    CliLog(opts, "Reading encrypted input: " + *opts.path);
    const safeanar::AnarStatus input_status = LoadCipherInputBytes(opts, input_bytes);
    if (input_status != safeanar::AnarStatus::Ok) {
        std::cerr << safeanar::ToString(input_status) << "\n";
        cleanup();
        return 1;
    }

    if (!ParseContainer(input_bytes, container)) {
        std::cerr << "InvalidArchive\n";
        cleanup();
        return 1;
    }

    const safeanar::AnarStatus key_status = ResolveKeyBytes(opts, raw_key_bytes);
    if (key_status != safeanar::AnarStatus::Ok) {
        std::cerr << safeanar::ToString(key_status) << "\n";
        cleanup();
        return 1;
    }

    if (container.protocol_id == kProtoOtp && !opts.key_file.has_value()) {
        std::cerr << "OTP requires --key-file\n";
        cleanup();
        return 1;
    }

    int decrypt_percent = -1;
    std::function<void(std::size_t, std::size_t)> decrypt_progress;
    if (opts.log) {
        decrypt_progress = [&](const std::size_t done, const std::size_t total) {
            const std::size_t clamped_done = std::min(done, total);
            const int percent = total == 0 ? 100 : static_cast<int>((clamped_done * 100U) / total);
            if (percent == decrypt_percent) {
                return;
            }
            decrypt_percent = percent;
            std::cerr << "\r[log] Decrypting: " << percent << "%" << std::flush;
            if (percent >= 100) {
                std::cerr << "\n";
            }
        };
    }
    const safeanar::AnarStatus cipher_status = DecryptPayload(
        opts,
        container,
        raw_key_bytes,
        plaintext,
        protocol_key_bytes,
        decrypt_progress);
    if (opts.log && decrypt_percent >= 0 && decrypt_percent < 100) {
        std::cerr << "\n";
    }
    if (cipher_status != safeanar::AnarStatus::Ok) {
        std::cerr << safeanar::ToString(cipher_status) << "\n";
        cleanup();
        return 1;
    }
    CliLog(opts, "Decryption complete");

    auto expected_tag = Sha256(Concat(protocol_key_bytes, plaintext));
    const bool auth_ok = ConstantTimeEqual(expected_tag, container.auth_tag);
    SecureWipeArray(expected_tag);
    if (!auth_ok) {
        RandomAuthFailureDelay();
        std::cerr << "Authentication Failed\n";
        cleanup();
        return 1;
    }

    if (container.kind_id == kKindText || container.kind_id == kKindFile) {
        CliLog(opts, "Writing output: " + *opts.out);
        if (!WriteFileBytes(*opts.out, plaintext)) {
            std::cerr << "FileIOError\n";
            cleanup();
            return 1;
        }
        CliLog(opts, "Done");
        cleanup();
        return 0;
    }

    if (container.kind_id == kKindDir) {
        CliLog(opts, "Unpacking directory archive to: " + *opts.out);
        std::size_t extracted_count = 0;
        const safeanar::AnarStatus status = safeanar::StreamPacker::UnpackBytesToPath(plaintext, *opts.out, extracted_count);
        if (status != safeanar::AnarStatus::Ok) {
            std::cerr << safeanar::ToString(status) << "\n";
            cleanup();
            return 1;
        }
        CliLog(opts, "Done");
        cleanup();
        return 0;
    }

    std::cerr << "InvalidArchive\n";
    cleanup();
    return 1;
}

int DeleteFlow(const DeleteOptions& opts) {
    safeanar::SecureDeleteOptions delete_options;
    delete_options.passes = opts.passes;
    delete_options.buffer_size = 1024 * 1024;
    const safeanar::AnarStatus status = safeanar::SecureDelete::DeleteFile(*opts.path, delete_options);
    if (status != safeanar::AnarStatus::Ok) {
        std::cerr << safeanar::ToString(status) << "\n";
        return 1;
    }
    return 0;
}

int KeygenFlow(const KeygenOptions& opts) {
    if (*opts.mode == "words") {
        std::vector<std::string> words;
        const safeanar::AnarStatus status = safeanar::KeyGenerator::GenerateWords(opts.word_count, words);
        if (status != safeanar::AnarStatus::Ok) {
            std::cerr << safeanar::ToString(status) << "\n";
            return 1;
        }
        std::cout << safeanar::KeyGenerator::JoinWords(words) << "\n";
        return 0;
    }
    if (*opts.mode == "chars") {
        std::string chars;
        const safeanar::AnarStatus status = safeanar::KeyGenerator::GenerateChars(opts.char_length, chars);
        if (status != safeanar::AnarStatus::Ok) {
            std::cerr << safeanar::ToString(status) << "\n";
            return 1;
        }
        std::cout << chars << "\n";
        return 0;
    }
    std::cerr << "Unknown key mode\n";
    return 1;
}

}  // namespace

int RunCliMain(const int argc, char* argv[]) {
    if (argc >= 2 && std::string(argv[1]) == "delete") {
        DeleteOptions opts;
        std::string error;
        if (!ParseDeleteArgs(argc, argv, opts, error)) {
            std::cerr << error << "\n";
            return 1;
        }
        if (opts.help) {
            PrintDeleteHelp(std::cout);
            return 0;
        }
        return DeleteFlow(opts);
    }
    if (argc >= 2 && (std::string(argv[1]) == "gen-key" || std::string(argv[1]) == "--gen-key")) {
        KeygenOptions opts;
        std::string error;
        if (!ParseKeygenArgs(argc, argv, 2, opts, error)) {
            std::cerr << error << "\n";
            return 1;
        }
        if (opts.help) {
            PrintKeygenHelp(std::cout);
            return 0;
        }
        return KeygenFlow(opts);
    }

    CliOptions opts;
    std::string error;
    if (!ParseArgs(argc, argv, opts, error)) {
        std::cerr << error << "\n";
        return 1;
    }

    if (opts.help) {
        PrintHelp(std::cout);
        return 0;
    }

    if (opts.encrypt) {
        return EncryptFlow(opts);
    }
    return DecryptFlow(opts);
}

#ifdef _WIN32
int main(const int argc, char* argv[]) {
    std::vector<std::string> utf8_args;
    if (BuildUtf8ArgsFromCommandLine(utf8_args)) {
        std::vector<char*> utf8_argv;
        utf8_argv.reserve(utf8_args.size());
        for (auto& arg : utf8_args) {
            utf8_argv.push_back(arg.data());
        }
        return RunCliMain(static_cast<int>(utf8_argv.size()), utf8_argv.data());
    }
    return RunCliMain(argc, argv);
}
#else
int main(const int argc, char* argv[]) {
    return RunCliMain(argc, argv);
}
#endif
