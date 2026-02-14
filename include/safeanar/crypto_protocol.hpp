#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string_view>
#include <vector>

#include "safeanar/anar_status.hpp"

namespace safeanar {

class ICryptoProtocol {
public:
    virtual ~ICryptoProtocol() = default;

    virtual AnarStatus Transform(
        const std::vector<std::uint8_t>& input,
        const std::vector<std::uint8_t>& key_bytes,
        const std::array<std::uint8_t, 16>& nonce,
        std::vector<std::uint8_t>& output,
        const std::function<void(std::size_t, std::size_t)>& progress = {}) const = 0;

    virtual bool RequiresKeyFile() const = 0;
    virtual std::string_view Name() const = 0;
};

}  // namespace safeanar
