#pragma once

#include <memory>
#include <string_view>

#include "safeanar/anar_status.hpp"
#include "safeanar/crypto_protocol.hpp"

namespace safeanar {

struct ProtocolFactoryOptions {
    bool fast = false;
};

class ProtocolFactory {
public:
    static std::unique_ptr<ICryptoProtocol> Create(
        std::string_view protocol_name,
        const ProtocolFactoryOptions& options,
        AnarStatus& out_status);
};

}  // namespace safeanar

