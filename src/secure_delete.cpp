#include "safeanar/secure_delete.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <random>
#include <string>
#include <vector>

#include "osrng.h"
#include "misc.h"

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

namespace safeanar {

namespace {

std::filesystem::path PathFromUtf8(const std::string& value) {
#ifdef _WIN32
    const auto* begin = reinterpret_cast<const char8_t*>(value.data());
    const auto* end = begin + value.size();
    return std::filesystem::path(std::u8string(begin, end));
#else
    return std::filesystem::path(value);
#endif
}

bool FlushToDisk(std::FILE* file) {
    if (file == nullptr) {
        return false;
    }
#ifdef _WIN32
    return _commit(_fileno(file)) == 0;
#else
    return fsync(fileno(file)) == 0;
#endif
}

bool TruncateToZero(std::FILE* file) {
    if (file == nullptr) {
        return false;
    }
#ifdef _WIN32
    return _chsize_s(_fileno(file), 0) == 0;
#else
    return ftruncate(fileno(file), 0) == 0;
#endif
}

void SecureWipeBuffer(std::vector<std::uint8_t>& buffer) {
    if (!buffer.empty()) {
        CryptoPP::memset_z(buffer.data(), 0, buffer.size());
    }
}

std::string RandomHexName(const std::size_t bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    CryptoPP::AutoSeededRandomPool rng;

    std::string name;
    name.reserve(bytes * 2);
    for (std::size_t i = 0; i < bytes; ++i) {
        std::uint8_t value = 0;
        rng.GenerateBlock(&value, 1);
        name.push_back(kHex[(value >> 4U) & 0x0FU]);
        name.push_back(kHex[value & 0x0FU]);
    }
    return name;
}

}  // namespace

AnarStatus SecureDelete::DeleteFile(const std::string& path, const SecureDeleteOptions& options) {
    if (options.passes == 0 || options.buffer_size == 0) {
        return AnarStatus::InvalidLength;
    }

    const std::filesystem::path target = PathFromUtf8(path);
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(target, ec);
    if (ec || !std::filesystem::exists(status) || !std::filesystem::is_regular_file(status) ||
        std::filesystem::is_symlink(status)) {
        return AnarStatus::InvalidPath;
    }

    std::filesystem::permissions(target, std::filesystem::perms::owner_write, std::filesystem::perm_options::add, ec);

    const std::uintmax_t file_size_u = std::filesystem::file_size(target, ec);
    if (ec) {
        return AnarStatus::FileIOError;
    }
    const std::uint64_t file_size = static_cast<std::uint64_t>(file_size_u);

#ifdef _WIN32
    std::FILE* file = _wfopen(target.c_str(), L"r+b");
#else
    std::FILE* file = std::fopen(path.c_str(), "r+b");
#endif
    if (file == nullptr) {
        return AnarStatus::FileIOError;
    }

    std::vector<std::uint8_t> buffer(options.buffer_size, 0U);
    CryptoPP::AutoSeededRandomPool rng;

    auto fail_and_close = [&](const AnarStatus error) -> AnarStatus {
        SecureWipeBuffer(buffer);
        std::fclose(file);
        return error;
    };

    for (std::size_t pass = 0; pass < options.passes; ++pass) {
        if (std::fseek(file, 0, SEEK_SET) != 0) {
            return fail_and_close(AnarStatus::FileIOError);
        }

        std::uint64_t remaining = file_size;
        while (remaining > 0) {
            const std::size_t chunk =
                remaining > buffer.size() ? buffer.size() : static_cast<std::size_t>(remaining);

            if (pass == 0) {
                std::fill(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(chunk), 0x00U);
            } else if (pass == 1) {
                std::fill(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(chunk), 0xFFU);
            } else if (pass == 2) {
                std::fill(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(chunk), 0x55U);
            } else if (pass == 3) {
                std::fill(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(chunk), 0xAAU);
            } else {
                rng.GenerateBlock(buffer.data(), chunk);
            }

            const std::size_t written = std::fwrite(buffer.data(), 1, chunk, file);
            if (written != chunk) {
                return fail_and_close(AnarStatus::FileIOError);
            }
            remaining -= chunk;
        }

        if (std::fflush(file) != 0 || !FlushToDisk(file)) {
            return fail_and_close(AnarStatus::FileIOError);
        }
    }

    if (std::fflush(file) != 0 || !TruncateToZero(file) || std::fflush(file) != 0 || !FlushToDisk(file)) {
        return fail_and_close(AnarStatus::FileIOError);
    }

    SecureWipeBuffer(buffer);
    if (std::fclose(file) != 0) {
        return AnarStatus::FileIOError;
    }

    std::filesystem::path current = target;
    for (int i = 0; i < 3; ++i) {
        std::filesystem::path renamed = current.parent_path() / RandomHexName(16);
        std::filesystem::rename(current, renamed, ec);
        if (ec) {
            break;
        }
        current = renamed;
    }

    std::filesystem::remove(current, ec);
    if (ec) {
        return AnarStatus::FileIOError;
    }
    return AnarStatus::Ok;
}

}  // namespace safeanar
