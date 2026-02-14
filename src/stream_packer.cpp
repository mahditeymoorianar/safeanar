#include "safeanar/stream_packer.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <random>
#include <string>
#include <vector>

namespace safeanar {

namespace {

constexpr std::size_t kChunkSize = 4096;
constexpr std::array<char, 8> kPaddedFooter = {'S', 'P', 'A', 'D', 'E', 'N', 'D', '1'};

void ToLittle16(const std::uint16_t value, std::array<char, 2>& out) {
    out[0] = static_cast<char>(value & 0xFFU);
    out[1] = static_cast<char>((value >> 8U) & 0xFFU);
}

void ToLittle32(const std::uint32_t value, std::array<char, 4>& out) {
    out[0] = static_cast<char>(value & 0xFFU);
    out[1] = static_cast<char>((value >> 8U) & 0xFFU);
    out[2] = static_cast<char>((value >> 16U) & 0xFFU);
    out[3] = static_cast<char>((value >> 24U) & 0xFFU);
}

void ToLittle64(const std::uint64_t value, std::array<char, 8>& out) {
    out[0] = static_cast<char>(value & 0xFFU);
    out[1] = static_cast<char>((value >> 8U) & 0xFFU);
    out[2] = static_cast<char>((value >> 16U) & 0xFFU);
    out[3] = static_cast<char>((value >> 24U) & 0xFFU);
    out[4] = static_cast<char>((value >> 32U) & 0xFFU);
    out[5] = static_cast<char>((value >> 40U) & 0xFFU);
    out[6] = static_cast<char>((value >> 48U) & 0xFFU);
    out[7] = static_cast<char>((value >> 56U) & 0xFFU);
}

bool FromLittle16(std::istream& in, std::uint16_t& value) {
    std::array<unsigned char, 2> bytes{};
    in.read(reinterpret_cast<char*>(bytes.data()), 2);
    if (in.gcount() != 2) {
        return false;
    }
    value = static_cast<std::uint16_t>(bytes[0] | (bytes[1] << 8U));
    return true;
}

bool FromLittle32(std::istream& in, std::uint32_t& value) {
    std::array<unsigned char, 4> bytes{};
    in.read(reinterpret_cast<char*>(bytes.data()), 4);
    if (in.gcount() != 4) {
        return false;
    }
    value = static_cast<std::uint32_t>(
        bytes[0] |
        (bytes[1] << 8U) |
        (bytes[2] << 16U) |
        (bytes[3] << 24U));
    return true;
}

bool FromLittle64(std::istream& in, std::uint64_t& value) {
    std::array<unsigned char, 8> bytes{};
    in.read(reinterpret_cast<char*>(bytes.data()), 8);
    if (in.gcount() != 8) {
        return false;
    }
    value = static_cast<std::uint64_t>(
        static_cast<std::uint64_t>(bytes[0]) |
        (static_cast<std::uint64_t>(bytes[1]) << 8U) |
        (static_cast<std::uint64_t>(bytes[2]) << 16U) |
        (static_cast<std::uint64_t>(bytes[3]) << 24U) |
        (static_cast<std::uint64_t>(bytes[4]) << 32U) |
        (static_cast<std::uint64_t>(bytes[5]) << 40U) |
        (static_cast<std::uint64_t>(bytes[6]) << 48U) |
        (static_cast<std::uint64_t>(bytes[7]) << 56U));
    return true;
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

std::string NormalizeRel(const std::filesystem::path& p) {
    std::string s = Utf8FromPath(p);
    std::replace(s.begin(), s.end(), '\\', '/');
    return s;
}

bool IsRegularFile(const std::filesystem::path& p) {
    std::error_code ec;
    return std::filesystem::is_regular_file(p, ec) && !ec;
}

bool IsDirectory(const std::filesystem::path& p) {
    std::error_code ec;
    return std::filesystem::is_directory(p, ec) && !ec;
}

std::uint64_t FileSize(const std::filesystem::path& p, bool& ok) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(p, ec);
    ok = !ec;
    return ok ? static_cast<std::uint64_t>(size) : 0U;
}

bool ReadExact(std::ifstream& in, char* buf, const std::size_t n) {
    in.read(buf, static_cast<std::streamsize>(n));
    return static_cast<std::size_t>(in.gcount()) == n;
}

void AppendLittle16(std::vector<std::uint8_t>& out, const std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
}

void AppendLittle32(std::vector<std::uint8_t>& out, const std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xFFU));
}

void AppendLittle64(std::vector<std::uint8_t>& out, const std::uint64_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 32U) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 40U) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 48U) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 56U) & 0xFFU));
}

bool ReadLittle16FromBytes(const std::vector<std::uint8_t>& in, std::size_t& pos, std::uint16_t& value) {
    if (pos + 2 > in.size()) {
        return false;
    }
    value = static_cast<std::uint16_t>(in[pos] | (static_cast<std::uint16_t>(in[pos + 1]) << 8U));
    pos += 2;
    return true;
}

bool ReadLittle32FromBytes(const std::vector<std::uint8_t>& in, std::size_t& pos, std::uint32_t& value) {
    if (pos + 4 > in.size()) {
        return false;
    }
    value = static_cast<std::uint32_t>(
        in[pos] |
        (static_cast<std::uint32_t>(in[pos + 1]) << 8U) |
        (static_cast<std::uint32_t>(in[pos + 2]) << 16U) |
        (static_cast<std::uint32_t>(in[pos + 3]) << 24U));
    pos += 4;
    return true;
}

bool ReadLittle64FromBytes(const std::vector<std::uint8_t>& in, std::size_t& pos, std::uint64_t& value) {
    if (pos + 8 > in.size()) {
        return false;
    }
    value = static_cast<std::uint64_t>(
        static_cast<std::uint64_t>(in[pos]) |
        (static_cast<std::uint64_t>(in[pos + 1]) << 8U) |
        (static_cast<std::uint64_t>(in[pos + 2]) << 16U) |
        (static_cast<std::uint64_t>(in[pos + 3]) << 24U) |
        (static_cast<std::uint64_t>(in[pos + 4]) << 32U) |
        (static_cast<std::uint64_t>(in[pos + 5]) << 40U) |
        (static_cast<std::uint64_t>(in[pos + 6]) << 48U) |
        (static_cast<std::uint64_t>(in[pos + 7]) << 56U));
    pos += 8;
    return true;
}

}  // namespace

AnarStatus StreamPacker::PackPath(
    const std::string& input_path,
    const std::string& output_path,
    std::size_t& out_entry_count,
    std::size_t& out_bytes_written) {
    out_entry_count = 0;
    out_bytes_written = 0;

    const std::filesystem::path input = PathFromUtf8(input_path);
    std::vector<std::pair<std::string, std::filesystem::path>> entries;

    if (IsRegularFile(input)) {
        const std::string rel = Utf8FromPath(input.filename());
        if (!ValidateRelativePath(rel)) {
            return AnarStatus::InvalidPath;
        }
        entries.emplace_back(rel, input);
    } else if (IsDirectory(input)) {
        std::error_code ec;
        std::filesystem::recursive_directory_iterator it(input, ec);
        if (ec) {
            return AnarStatus::FileIOError;
        }
        for (const auto& dir_entry : it) {
            if (!dir_entry.is_regular_file(ec)) {
                if (ec) {
                    return AnarStatus::FileIOError;
                }
                continue;
            }
            const std::filesystem::path rel_path = std::filesystem::relative(dir_entry.path(), input, ec);
            if (ec) {
                return AnarStatus::FileIOError;
            }
            const std::string rel = NormalizeRel(rel_path);
            if (!ValidateRelativePath(rel)) {
                return AnarStatus::InvalidPath;
            }
            entries.emplace_back(rel, dir_entry.path());
        }
        std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
            return a.first < b.first;
        });
    } else {
        return AnarStatus::InvalidPath;
    }

    if (entries.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        return AnarStatus::InvalidPath;
    }

    std::ofstream out(PathFromUtf8(output_path), std::ios::binary);
    if (!out.is_open()) {
        return AnarStatus::FileIOError;
    }

    out.write(kArchiveMagic, static_cast<std::streamsize>(kArchiveMagicSize));
    out_bytes_written += kArchiveMagicSize;

    std::array<char, 4> count_le{};
    ToLittle32(static_cast<std::uint32_t>(entries.size()), count_le);
    out.write(count_le.data(), static_cast<std::streamsize>(count_le.size()));
    out_bytes_written += count_le.size();

    std::array<char, kChunkSize> buffer{};
    for (const auto& [rel, src] : entries) {
        if (rel.size() > static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max())) {
            return AnarStatus::InvalidPath;
        }
        bool size_ok = false;
        const std::uint64_t file_size = FileSize(src, size_ok);
        if (!size_ok) {
            return AnarStatus::FileIOError;
        }

        std::array<char, 2> rel_len_le{};
        ToLittle16(static_cast<std::uint16_t>(rel.size()), rel_len_le);
        out.write(rel_len_le.data(), static_cast<std::streamsize>(rel_len_le.size()));
        out.write(rel.data(), static_cast<std::streamsize>(rel.size()));
        out_bytes_written += rel_len_le.size() + rel.size();

        std::array<char, 8> size_le{};
        ToLittle64(file_size, size_le);
        out.write(size_le.data(), static_cast<std::streamsize>(size_le.size()));
        out_bytes_written += size_le.size();

        std::ifstream in(src, std::ios::binary);
        if (!in.is_open()) {
            return AnarStatus::FileIOError;
        }
        while (true) {
            in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            const std::streamsize got = in.gcount();
            if (got <= 0) {
                break;
            }
            out.write(buffer.data(), got);
            out_bytes_written += static_cast<std::size_t>(got);
        }
        if (in.bad() || out.bad()) {
            return AnarStatus::FileIOError;
        }
    }

    out_entry_count = entries.size();
    return AnarStatus::Ok;
}

AnarStatus StreamPacker::PackPathToBytes(
    const std::string& input_path,
    std::vector<std::uint8_t>& out_archive_bytes,
    std::size_t& out_entry_count) {
    out_archive_bytes.clear();
    out_entry_count = 0;

    const std::filesystem::path input = PathFromUtf8(input_path);
    std::vector<std::pair<std::string, std::filesystem::path>> entries;

    if (IsRegularFile(input)) {
        const std::string rel = Utf8FromPath(input.filename());
        if (!ValidateRelativePath(rel)) {
            return AnarStatus::InvalidPath;
        }
        entries.emplace_back(rel, input);
    } else if (IsDirectory(input)) {
        std::error_code ec;
        std::filesystem::recursive_directory_iterator it(input, ec);
        if (ec) {
            return AnarStatus::FileIOError;
        }
        for (const auto& dir_entry : it) {
            if (!dir_entry.is_regular_file(ec)) {
                if (ec) {
                    return AnarStatus::FileIOError;
                }
                continue;
            }
            const std::filesystem::path rel_path = std::filesystem::relative(dir_entry.path(), input, ec);
            if (ec) {
                return AnarStatus::FileIOError;
            }
            const std::string rel = NormalizeRel(rel_path);
            if (!ValidateRelativePath(rel)) {
                return AnarStatus::InvalidPath;
            }
            entries.emplace_back(rel, dir_entry.path());
        }
        std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
            return a.first < b.first;
        });
    } else {
        return AnarStatus::InvalidPath;
    }

    if (entries.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        return AnarStatus::InvalidPath;
    }

    out_archive_bytes.reserve(kArchiveMagicSize + 4);
    out_archive_bytes.insert(out_archive_bytes.end(), kArchiveMagic, kArchiveMagic + kArchiveMagicSize);
    AppendLittle32(out_archive_bytes, static_cast<std::uint32_t>(entries.size()));

    std::array<char, kChunkSize> buffer{};
    for (const auto& [rel, src] : entries) {
        if (rel.size() > static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max())) {
            return AnarStatus::InvalidPath;
        }
        bool size_ok = false;
        const std::uint64_t file_size = FileSize(src, size_ok);
        if (!size_ok) {
            return AnarStatus::FileIOError;
        }

        AppendLittle16(out_archive_bytes, static_cast<std::uint16_t>(rel.size()));
        out_archive_bytes.insert(out_archive_bytes.end(), rel.begin(), rel.end());
        AppendLittle64(out_archive_bytes, file_size);

        std::ifstream in(src, std::ios::binary);
        if (!in.is_open()) {
            return AnarStatus::FileIOError;
        }
        while (true) {
            in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            const std::streamsize got = in.gcount();
            if (got <= 0) {
                break;
            }
            out_archive_bytes.insert(
                out_archive_bytes.end(),
                reinterpret_cast<const std::uint8_t*>(buffer.data()),
                reinterpret_cast<const std::uint8_t*>(buffer.data()) + got);
        }
        if (in.bad()) {
            return AnarStatus::FileIOError;
        }
    }

    out_entry_count = entries.size();
    return AnarStatus::Ok;
}

AnarStatus StreamPacker::InspectArchive(const std::string& input_path, std::vector<ArchiveEntry>& out_entries) {
    out_entries.clear();

    std::ifstream in(PathFromUtf8(input_path), std::ios::binary);
    if (!in.is_open()) {
        return AnarStatus::FileIOError;
    }

    in.seekg(0, std::ios::end);
    const std::streamoff total_size_off = in.tellg();
    if (total_size_off < 0) {
        return AnarStatus::FileIOError;
    }
    const std::uint64_t total_size = static_cast<std::uint64_t>(total_size_off);
    in.seekg(0, std::ios::beg);

    std::array<char, kArchiveMagicSize> magic{};
    if (!ReadExact(in, magic.data(), magic.size())) {
        return AnarStatus::CorruptInput;
    }
    if (!std::equal(magic.begin(), magic.end(), kArchiveMagic)) {
        return AnarStatus::InvalidArchive;
    }

    std::uint32_t entry_count = 0;
    if (!FromLittle32(in, entry_count)) {
        return AnarStatus::CorruptInput;
    }

    out_entries.reserve(entry_count);
    for (std::uint32_t i = 0; i < entry_count; ++i) {
        std::uint16_t rel_len = 0;
        if (!FromLittle16(in, rel_len)) {
            return AnarStatus::CorruptInput;
        }

        std::string rel(rel_len, '\0');
        if (!ReadExact(in, rel.data(), rel.size())) {
            return AnarStatus::CorruptInput;
        }
        if (!ValidateRelativePath(rel)) {
            return AnarStatus::InvalidArchive;
        }

        std::uint64_t size = 0;
        if (!FromLittle64(in, size)) {
            return AnarStatus::CorruptInput;
        }

        const std::streamoff data_offset_off = in.tellg();
        if (data_offset_off < 0) {
            return AnarStatus::CorruptInput;
        }
        const std::uint64_t data_offset = static_cast<std::uint64_t>(data_offset_off);
        if (data_offset + size > total_size) {
            return AnarStatus::CorruptInput;
        }
        in.seekg(static_cast<std::streamoff>(size), std::ios::cur);
        if (!in.good()) {
            return AnarStatus::CorruptInput;
        }

        ArchiveEntry entry;
        entry.path = std::move(rel);
        entry.size = size;
        entry.data_offset = data_offset;
        out_entries.push_back(std::move(entry));
    }

    const std::streamoff final_pos = in.tellg();
    if (final_pos < 0) {
        return AnarStatus::CorruptInput;
    }
    if (static_cast<std::uint64_t>(final_pos) != total_size) {
        return AnarStatus::InvalidArchive;
    }
    return AnarStatus::Ok;
}

AnarStatus StreamPacker::UnpackPath(
    const std::string& input_path,
    const std::string& output_dir,
    std::size_t& out_extracted_count) {
    out_extracted_count = 0;

    std::vector<ArchiveEntry> entries;
    const AnarStatus inspect_status = InspectArchive(input_path, entries);
    if (inspect_status != AnarStatus::Ok) {
        return inspect_status;
    }

    std::ifstream in(PathFromUtf8(input_path), std::ios::binary);
    if (!in.is_open()) {
        return AnarStatus::FileIOError;
    }

    std::error_code ec;
    const std::filesystem::path out_dir_path = PathFromUtf8(output_dir);
    std::filesystem::create_directories(out_dir_path, ec);
    if (ec) {
        return AnarStatus::FileIOError;
    }
    const std::filesystem::path base = std::filesystem::absolute(out_dir_path, ec);
    if (ec) {
        return AnarStatus::FileIOError;
    }

    std::array<char, kChunkSize> buffer{};
    for (const auto& entry : entries) {
        if (!ValidateRelativePath(entry.path)) {
            return AnarStatus::InvalidArchive;
        }

        std::filesystem::path out_path = base;
        std::filesystem::path rel = PathFromUtf8(entry.path);
        out_path /= rel;
        out_path = out_path.lexically_normal();

        const auto base_str = Utf8FromPath(base);
        const auto out_str = Utf8FromPath(out_path);
        if (!(out_str == base_str || (out_str.rfind(base_str + "/", 0) == 0))) {
            return AnarStatus::InvalidArchive;
        }

        std::filesystem::create_directories(out_path.parent_path(), ec);
        if (ec) {
            return AnarStatus::FileIOError;
        }

        in.seekg(static_cast<std::streamoff>(entry.data_offset), std::ios::beg);
        if (!in.good()) {
            return AnarStatus::CorruptInput;
        }

        std::ofstream out(out_path, std::ios::binary);
        if (!out.is_open()) {
            return AnarStatus::FileIOError;
        }

        std::uint64_t remaining = entry.size;
        while (remaining > 0) {
            const std::size_t chunk = remaining > buffer.size() ? buffer.size() : static_cast<std::size_t>(remaining);
            in.read(buffer.data(), static_cast<std::streamsize>(chunk));
            if (static_cast<std::size_t>(in.gcount()) != chunk) {
                return AnarStatus::CorruptInput;
            }
            out.write(buffer.data(), static_cast<std::streamsize>(chunk));
            if (!out.good()) {
                return AnarStatus::FileIOError;
            }
            remaining -= chunk;
        }
        ++out_extracted_count;
    }

    return AnarStatus::Ok;
}

AnarStatus StreamPacker::UnpackBytesToPath(
    const std::vector<std::uint8_t>& archive_bytes,
    const std::string& output_dir,
    std::size_t& out_extracted_count) {
    out_extracted_count = 0;
    if (archive_bytes.size() < kArchiveMagicSize + 4) {
        return AnarStatus::CorruptInput;
    }
    if (!std::equal(archive_bytes.begin(), archive_bytes.begin() + static_cast<std::ptrdiff_t>(kArchiveMagicSize), kArchiveMagic)) {
        return AnarStatus::InvalidArchive;
    }

    std::size_t pos = kArchiveMagicSize;
    std::uint32_t entry_count = 0;
    if (!ReadLittle32FromBytes(archive_bytes, pos, entry_count)) {
        return AnarStatus::CorruptInput;
    }

    std::error_code ec;
    const std::filesystem::path out_dir_path = PathFromUtf8(output_dir);
    std::filesystem::create_directories(out_dir_path, ec);
    if (ec) {
        return AnarStatus::FileIOError;
    }
    const std::filesystem::path base = std::filesystem::absolute(out_dir_path, ec);
    if (ec) {
        return AnarStatus::FileIOError;
    }

    for (std::uint32_t i = 0; i < entry_count; ++i) {
        std::uint16_t rel_len = 0;
        if (!ReadLittle16FromBytes(archive_bytes, pos, rel_len)) {
            return AnarStatus::CorruptInput;
        }
        if (pos + rel_len > archive_bytes.size()) {
            return AnarStatus::CorruptInput;
        }
        std::string rel(
            reinterpret_cast<const char*>(archive_bytes.data() + pos),
            reinterpret_cast<const char*>(archive_bytes.data() + pos + rel_len));
        pos += rel_len;

        if (!ValidateRelativePath(rel)) {
            return AnarStatus::InvalidArchive;
        }

        std::uint64_t file_size = 0;
        if (!ReadLittle64FromBytes(archive_bytes, pos, file_size)) {
            return AnarStatus::CorruptInput;
        }
        if (file_size > static_cast<std::uint64_t>(archive_bytes.size() - pos)) {
            return AnarStatus::CorruptInput;
        }

        std::filesystem::path out_path = base / PathFromUtf8(rel);
        out_path = out_path.lexically_normal();
        const auto base_str = Utf8FromPath(base);
        const auto out_str = Utf8FromPath(out_path);
        if (!(out_str == base_str || (out_str.rfind(base_str + "/", 0) == 0))) {
            return AnarStatus::InvalidArchive;
        }

        std::filesystem::create_directories(out_path.parent_path(), ec);
        if (ec) {
            return AnarStatus::FileIOError;
        }
        std::ofstream out(out_path, std::ios::binary);
        if (!out.is_open()) {
            return AnarStatus::FileIOError;
        }

        const std::size_t data_size = static_cast<std::size_t>(file_size);
        if (data_size > 0) {
            out.write(
                reinterpret_cast<const char*>(archive_bytes.data() + pos),
                static_cast<std::streamsize>(data_size));
            if (!out.good()) {
                return AnarStatus::FileIOError;
            }
        }
        pos += data_size;
        ++out_extracted_count;
    }

    if (pos != archive_bytes.size()) {
        return AnarStatus::InvalidArchive;
    }
    return AnarStatus::Ok;
}

AnarStatus StreamPacker::PadFile(
    const std::string& input_path,
    const std::string& output_path,
    const std::uint64_t target_size,
    std::uint64_t& out_real_size,
    std::size_t& out_bytes_written) {
    out_real_size = 0;
    out_bytes_written = 0;

    const std::filesystem::path input = PathFromUtf8(input_path);
    if (!IsRegularFile(input)) {
        return AnarStatus::InvalidPath;
    }

    bool size_ok = false;
    const std::uint64_t real_size = FileSize(input, size_ok);
    if (!size_ok) {
        return AnarStatus::FileIOError;
    }

    const std::uint64_t min_size = static_cast<std::uint64_t>(kPaddedHeaderSize) + real_size;
    const std::uint64_t required_min_size = min_size + static_cast<std::uint64_t>(kPaddedFooter.size());
    if (target_size < required_min_size) {
        return AnarStatus::InvalidPaddingTarget;
    }

    std::ifstream in(input, std::ios::binary);
    std::ofstream out(PathFromUtf8(output_path), std::ios::binary);
    if (!in.is_open() || !out.is_open()) {
        return AnarStatus::FileIOError;
    }

    out.write(kPaddedMagic, static_cast<std::streamsize>(kPaddedMagicSize));
    std::array<char, 8> size_le{};
    ToLittle64(real_size, size_le);
    out.write(size_le.data(), static_cast<std::streamsize>(size_le.size()));
    out_bytes_written += kPaddedHeaderSize;

    std::array<char, kChunkSize> buffer{};
    while (true) {
        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = in.gcount();
        if (got <= 0) {
            break;
        }
        out.write(buffer.data(), got);
        out_bytes_written += static_cast<std::size_t>(got);
    }
    if (in.bad() || out.bad()) {
        return AnarStatus::FileIOError;
    }

    std::uint64_t remaining = target_size - required_min_size;
    std::mt19937_64 rng(std::random_device{}());
    while (remaining > 0) {
        const std::size_t chunk = remaining > buffer.size() ? buffer.size() : static_cast<std::size_t>(remaining);
        std::size_t i = 0;
        while (i + sizeof(std::uint64_t) <= chunk) {
            const std::uint64_t r = rng();
            std::memcpy(buffer.data() + i, &r, sizeof(std::uint64_t));
            i += sizeof(std::uint64_t);
        }
        while (i < chunk) {
            buffer[i++] = static_cast<char>(rng() & 0xFFU);
        }
        out.write(buffer.data(), static_cast<std::streamsize>(chunk));
        if (!out.good()) {
            return AnarStatus::FileIOError;
        }
        out_bytes_written += chunk;
        remaining -= chunk;
    }

    out.write(kPaddedFooter.data(), static_cast<std::streamsize>(kPaddedFooter.size()));
    if (!out.good()) {
        return AnarStatus::FileIOError;
    }
    out_bytes_written += kPaddedFooter.size();

    out_real_size = real_size;
    return AnarStatus::Ok;
}

AnarStatus StreamPacker::InspectPadded(
    const std::string& input_path,
    std::uint64_t& out_real_size,
    std::uint64_t& out_total_size) {
    out_real_size = 0;
    out_total_size = 0;

    std::ifstream in(PathFromUtf8(input_path), std::ios::binary);
    if (!in.is_open()) {
        return AnarStatus::FileIOError;
    }

    in.seekg(0, std::ios::end);
    const std::streamoff total_off = in.tellg();
    if (total_off < 0) {
        return AnarStatus::FileIOError;
    }
    out_total_size = static_cast<std::uint64_t>(total_off);
    in.seekg(0, std::ios::beg);

    std::array<char, kPaddedMagicSize> magic{};
    if (!ReadExact(in, magic.data(), magic.size())) {
        return AnarStatus::CorruptInput;
    }
    if (!std::equal(magic.begin(), magic.end(), kPaddedMagic)) {
        return AnarStatus::InvalidArchive;
    }

    if (!FromLittle64(in, out_real_size)) {
        return AnarStatus::CorruptInput;
    }
    const std::uint64_t min_size =
        static_cast<std::uint64_t>(kPaddedHeaderSize) +
        out_real_size +
        static_cast<std::uint64_t>(kPaddedFooter.size());
    if (out_total_size < min_size) {
        return AnarStatus::CorruptInput;
    }

    in.seekg(static_cast<std::streamoff>(out_total_size - kPaddedFooter.size()), std::ios::beg);
    std::array<char, kPaddedFooter.size()> footer{};
    if (!ReadExact(in, footer.data(), footer.size())) {
        return AnarStatus::CorruptInput;
    }
    if (!std::equal(footer.begin(), footer.end(), kPaddedFooter.begin())) {
        return AnarStatus::CorruptInput;
    }
    return AnarStatus::Ok;
}

AnarStatus StreamPacker::UnpadFile(
    const std::string& input_path,
    const std::string& output_path,
    std::size_t& out_bytes_written) {
    out_bytes_written = 0;

    std::uint64_t real_size = 0;
    std::uint64_t total_size = 0;
    const AnarStatus inspect_status = InspectPadded(input_path, real_size, total_size);
    if (inspect_status != AnarStatus::Ok) {
        return inspect_status;
    }

    std::ifstream in(PathFromUtf8(input_path), std::ios::binary);
    std::ofstream out(PathFromUtf8(output_path), std::ios::binary);
    if (!in.is_open() || !out.is_open()) {
        return AnarStatus::FileIOError;
    }
    in.seekg(static_cast<std::streamoff>(kPaddedHeaderSize), std::ios::beg);

    std::array<char, kChunkSize> buffer{};
    std::uint64_t remaining = real_size;
    while (remaining > 0) {
        const std::size_t chunk = remaining > buffer.size() ? buffer.size() : static_cast<std::size_t>(remaining);
        in.read(buffer.data(), static_cast<std::streamsize>(chunk));
        if (static_cast<std::size_t>(in.gcount()) != chunk) {
            return AnarStatus::CorruptInput;
        }
        out.write(buffer.data(), static_cast<std::streamsize>(chunk));
        if (!out.good()) {
            return AnarStatus::FileIOError;
        }
        remaining -= chunk;
        out_bytes_written += chunk;
    }

    return AnarStatus::Ok;
}

AnarStatus StreamPacker::PadBytes(
    const std::vector<std::uint8_t>& input_bytes,
    const std::uint64_t target_size,
    std::vector<std::uint8_t>& out_padded_bytes) {
    const std::uint64_t real_size = static_cast<std::uint64_t>(input_bytes.size());
    const std::uint64_t min_size = static_cast<std::uint64_t>(kPaddedHeaderSize) + real_size;
    const std::uint64_t required_min_size = min_size + static_cast<std::uint64_t>(kPaddedFooter.size());
    if (target_size < required_min_size) {
        return AnarStatus::InvalidPaddingTarget;
    }
    if (target_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return AnarStatus::InvalidPaddingTarget;
    }

    out_padded_bytes.clear();
    out_padded_bytes.resize(static_cast<std::size_t>(target_size), 0U);
    std::size_t pos = 0;
    std::memcpy(out_padded_bytes.data() + pos, kPaddedMagic, kPaddedMagicSize);
    pos += kPaddedMagicSize;
    out_padded_bytes[pos + 0] = static_cast<std::uint8_t>(real_size & 0xFFU);
    out_padded_bytes[pos + 1] = static_cast<std::uint8_t>((real_size >> 8U) & 0xFFU);
    out_padded_bytes[pos + 2] = static_cast<std::uint8_t>((real_size >> 16U) & 0xFFU);
    out_padded_bytes[pos + 3] = static_cast<std::uint8_t>((real_size >> 24U) & 0xFFU);
    out_padded_bytes[pos + 4] = static_cast<std::uint8_t>((real_size >> 32U) & 0xFFU);
    out_padded_bytes[pos + 5] = static_cast<std::uint8_t>((real_size >> 40U) & 0xFFU);
    out_padded_bytes[pos + 6] = static_cast<std::uint8_t>((real_size >> 48U) & 0xFFU);
    out_padded_bytes[pos + 7] = static_cast<std::uint8_t>((real_size >> 56U) & 0xFFU);
    pos = kPaddedHeaderSize;

    if (!input_bytes.empty()) {
        std::memcpy(out_padded_bytes.data() + pos, input_bytes.data(), input_bytes.size());
    }
    pos += input_bytes.size();

    const std::size_t footer_pos = out_padded_bytes.size() - kPaddedFooter.size();
    std::mt19937_64 rng(std::random_device{}());
    while (pos < footer_pos) {
        out_padded_bytes[pos++] = static_cast<std::uint8_t>(rng() & 0xFFU);
    }

    std::memcpy(out_padded_bytes.data() + footer_pos, kPaddedFooter.data(), kPaddedFooter.size());
    return AnarStatus::Ok;
}

AnarStatus StreamPacker::InspectPaddedBytes(
    const std::vector<std::uint8_t>& padded_bytes,
    std::uint64_t& out_real_size,
    std::uint64_t& out_total_size) {
    out_real_size = 0;
    out_total_size = static_cast<std::uint64_t>(padded_bytes.size());
    if (padded_bytes.size() < kPaddedHeaderSize + kPaddedFooter.size()) {
        return AnarStatus::CorruptInput;
    }
    if (!std::equal(
            padded_bytes.begin(),
            padded_bytes.begin() + static_cast<std::ptrdiff_t>(kPaddedMagicSize),
            kPaddedMagic)) {
        return AnarStatus::InvalidArchive;
    }

    std::size_t pos = kPaddedMagicSize;
    if (!ReadLittle64FromBytes(padded_bytes, pos, out_real_size)) {
        return AnarStatus::CorruptInput;
    }
    const std::uint64_t min_size =
        static_cast<std::uint64_t>(kPaddedHeaderSize) +
        out_real_size +
        static_cast<std::uint64_t>(kPaddedFooter.size());
    if (out_total_size < min_size) {
        return AnarStatus::CorruptInput;
    }

    const std::size_t footer_pos = padded_bytes.size() - kPaddedFooter.size();
    if (!std::equal(
            padded_bytes.begin() + static_cast<std::ptrdiff_t>(footer_pos),
            padded_bytes.end(),
            kPaddedFooter.begin())) {
        return AnarStatus::CorruptInput;
    }
    return AnarStatus::Ok;
}

AnarStatus StreamPacker::UnpadBytes(
    const std::vector<std::uint8_t>& padded_bytes,
    std::vector<std::uint8_t>& out_plain_bytes) {
    std::uint64_t real_size = 0;
    std::uint64_t total_size = 0;
    const AnarStatus inspect_status = InspectPaddedBytes(padded_bytes, real_size, total_size);
    if (inspect_status != AnarStatus::Ok) {
        return inspect_status;
    }
    if (real_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return AnarStatus::CorruptInput;
    }

    const std::size_t data_pos = kPaddedHeaderSize;
    const std::size_t data_size = static_cast<std::size_t>(real_size);
    if (data_pos + data_size > padded_bytes.size() - kPaddedFooter.size()) {
        return AnarStatus::CorruptInput;
    }

    out_plain_bytes.assign(
        padded_bytes.begin() + static_cast<std::ptrdiff_t>(data_pos),
        padded_bytes.begin() + static_cast<std::ptrdiff_t>(data_pos + data_size));
    return AnarStatus::Ok;
}

bool StreamPacker::ValidateRelativePath(const std::string& path) {
    if (path.empty()) {
        return false;
    }
    if (path[0] == '/' || path[0] == '\\') {
        return false;
    }
    if (path.size() >= 2 && path[1] == ':') {
        return false;
    }
    if (path.find('\\') != std::string::npos) {
        return false;
    }

    std::size_t start = 0;
    while (start <= path.size()) {
        const std::size_t pos = path.find('/', start);
        const std::size_t end = pos == std::string::npos ? path.size() : pos;
        if (end == start) {
            return false;
        }
        const std::string_view part(path.data() + start, end - start);
        if (part == "." || part == "..") {
            return false;
        }
        if (part.find(':') != std::string_view::npos) {
            return false;
        }
        if (pos == std::string::npos) {
            break;
        }
        start = pos + 1;
    }
    return true;
}

}  // namespace safeanar
