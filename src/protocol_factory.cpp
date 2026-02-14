#include "safeanar/protocol_factory.hpp"

#include <array>
#include <memory>
#include <string>

#include "safeanar/crypto_engine.hpp"

namespace safeanar {

namespace {

class AesCtrProtocol final : public ICryptoProtocol {
public:
    explicit AesCtrProtocol(const ProtocolFactoryOptions options) : options_(options) {}

    AnarStatus Transform(
        const std::vector<std::uint8_t>& input,
        const std::vector<std::uint8_t>& key_bytes,
        const std::array<std::uint8_t, 16>& nonce,
        std::vector<std::uint8_t>& output,
        const std::function<void(std::size_t, std::size_t)>& progress) const override {
        (void)options_;
        if (key_bytes.size() != 32U) {
            return AnarStatus::InvalidKeyLength;
        }
        std::array<std::uint8_t, 32> key{};
        for (std::size_t i = 0; i < key.size(); ++i) {
            key[i] = key_bytes[i];
        }
        return CryptoEngine::Aes256CtrXor(key, nonce, input, output, progress);
    }

    bool RequiresKeyFile() const override {
        return false;
    }

    std::string_view Name() const override {
        return "aes";
    }

private:
    ProtocolFactoryOptions options_;
};

class OtpProtocol final : public ICryptoProtocol {
public:
    explicit OtpProtocol(const ProtocolFactoryOptions options) : options_(options) {}

    AnarStatus Transform(
        const std::vector<std::uint8_t>& input,
        const std::vector<std::uint8_t>& key_bytes,
        const std::array<std::uint8_t, 16>& nonce,
        std::vector<std::uint8_t>& output,
        const std::function<void(std::size_t, std::size_t)>& progress) const override {
        (void)options_;
        (void)nonce;
        return CryptoEngine::OtpXorBytes(input, key_bytes, output, progress);
    }

    bool RequiresKeyFile() const override {
        return true;
    }

    std::string_view Name() const override {
        return "otp";
    }

private:
    ProtocolFactoryOptions options_;
};

class PqSha256Protocol final : public ICryptoProtocol {
public:
    explicit PqSha256Protocol(const ProtocolFactoryOptions options) : options_(options) {}

    AnarStatus Transform(
        const std::vector<std::uint8_t>& input,
        const std::vector<std::uint8_t>& key_bytes,
        const std::array<std::uint8_t, 16>& nonce,
        std::vector<std::uint8_t>& output,
        const std::function<void(std::size_t, std::size_t)>& progress) const override {
        (void)options_;
        if (key_bytes.size() != 32U) {
            return AnarStatus::InvalidKeyLength;
        }
        std::array<std::uint8_t, 32> key{};
        for (std::size_t i = 0; i < key.size(); ++i) {
            key[i] = key_bytes[i];
        }
        return CryptoEngine::PqSha256StreamXor(key, nonce, input, output, progress);
    }

    bool RequiresKeyFile() const override {
        return false;
    }

    std::string_view Name() const override {
        return "pq";
    }

private:
    ProtocolFactoryOptions options_;
};

class Serpent256CtrProtocol final : public ICryptoProtocol {
public:
    explicit Serpent256CtrProtocol(const ProtocolFactoryOptions options) : options_(options) {}

    AnarStatus Transform(
        const std::vector<std::uint8_t>& input,
        const std::vector<std::uint8_t>& key_bytes,
        const std::array<std::uint8_t, 16>& nonce,
        std::vector<std::uint8_t>& output,
        const std::function<void(std::size_t, std::size_t)>& progress) const override {
        (void)options_;
        if (key_bytes.size() != 32U) {
            return AnarStatus::InvalidKeyLength;
        }
        std::array<std::uint8_t, 32> key{};
        for (std::size_t i = 0; i < key.size(); ++i) {
            key[i] = key_bytes[i];
        }
        return CryptoEngine::Serpent256CtrXor(key, nonce, input, output, progress);
    }

    bool RequiresKeyFile() const override {
        return false;
    }

    std::string_view Name() const override {
        return "serpent-256";
    }

private:
    ProtocolFactoryOptions options_;
};

}  // namespace

std::unique_ptr<ICryptoProtocol> ProtocolFactory::Create(
    const std::string_view protocol_name,
    const ProtocolFactoryOptions& options,
    AnarStatus& out_status) {
    std::string normalized(protocol_name);
    for (char& ch : normalized) {
        if (ch >= 'A' && ch <= 'Z') {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }

    if (normalized == "aes") {
        out_status = AnarStatus::Ok;
        return std::make_unique<AesCtrProtocol>(options);
    }
    if (normalized == "otp") {
        out_status = AnarStatus::Ok;
        return std::make_unique<OtpProtocol>(options);
    }
    if (normalized == "pq") {
        out_status = AnarStatus::Ok;
        return std::make_unique<PqSha256Protocol>(options);
    }
    if (normalized == "serpent-256" || normalized == "serpent256") {
        out_status = AnarStatus::Ok;
        return std::make_unique<Serpent256CtrProtocol>(options);
    }

    out_status = AnarStatus::UnknownOp;
    return nullptr;
}

}  // namespace safeanar
