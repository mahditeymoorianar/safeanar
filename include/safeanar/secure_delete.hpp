#pragma once

#include <cstddef>
#include <string>

#include "safeanar/anar_status.hpp"

namespace safeanar {

struct SecureDeleteOptions {
    std::size_t passes = 7;
    std::size_t buffer_size = 1024 * 1024;
};

class SecureDelete {
public:
    static AnarStatus DeleteFile(const std::string& path, const SecureDeleteOptions& options = {});
};

}  // namespace safeanar

