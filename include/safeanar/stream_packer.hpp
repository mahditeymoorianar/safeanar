#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "safeanar/anar_status.hpp"

namespace safeanar {

struct ArchiveEntry {
    std::string path;
    std::uint64_t size = 0;
    std::uint64_t data_offset = 0;
};

class StreamPacker {
public:
    static constexpr const char* kArchiveMagic = "SAPK1\0";
    static constexpr std::size_t kArchiveMagicSize = 6;
    static constexpr const char* kPaddedMagic = "SPAD1\0";
    static constexpr std::size_t kPaddedMagicSize = 6;
    static constexpr std::size_t kPaddedHeaderSize = kPaddedMagicSize + sizeof(std::uint64_t);

    static AnarStatus PackPath(
        const std::string& input_path,
        const std::string& output_path,
        std::size_t& out_entry_count,
        std::size_t& out_bytes_written);

    static AnarStatus PackPathToBytes(
        const std::string& input_path,
        std::vector<std::uint8_t>& out_archive_bytes,
        std::size_t& out_entry_count);

    static AnarStatus InspectArchive(
        const std::string& input_path,
        std::vector<ArchiveEntry>& out_entries);

    static AnarStatus UnpackPath(
        const std::string& input_path,
        const std::string& output_dir,
        std::size_t& out_extracted_count);

    static AnarStatus UnpackBytesToPath(
        const std::vector<std::uint8_t>& archive_bytes,
        const std::string& output_dir,
        std::size_t& out_extracted_count);

    static AnarStatus PadFile(
        const std::string& input_path,
        const std::string& output_path,
        std::uint64_t target_size,
        std::uint64_t& out_real_size,
        std::size_t& out_bytes_written);

    static AnarStatus InspectPadded(
        const std::string& input_path,
        std::uint64_t& out_real_size,
        std::uint64_t& out_total_size);

    static AnarStatus UnpadFile(
        const std::string& input_path,
        const std::string& output_path,
        std::size_t& out_bytes_written);

    static AnarStatus PadBytes(
        const std::vector<std::uint8_t>& input_bytes,
        std::uint64_t target_size,
        std::vector<std::uint8_t>& out_padded_bytes);

    static AnarStatus InspectPaddedBytes(
        const std::vector<std::uint8_t>& padded_bytes,
        std::uint64_t& out_real_size,
        std::uint64_t& out_total_size);

    static AnarStatus UnpadBytes(
        const std::vector<std::uint8_t>& padded_bytes,
        std::vector<std::uint8_t>& out_plain_bytes);

private:
    static bool ValidateRelativePath(const std::string& path);
};

}  // namespace safeanar
