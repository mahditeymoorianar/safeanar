#include "safeanar/crypto_engine.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include "chachapoly.h"
#include "modes.h"
#include "serpent.h"

namespace safeanar {

namespace {

constexpr std::size_t kAesBlockSize = 16;
constexpr std::size_t kAes256KeySize = 32;
constexpr int kAesNk = 8;
constexpr int kAesNr = 14;
constexpr std::size_t kSha256BlockSize = 64;
constexpr std::size_t kSha256DigestSize = 32;

constexpr std::array<std::uint8_t, 256> kSbox = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};

constexpr std::array<std::uint8_t, 256> kInvSbox = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};

constexpr std::array<std::uint8_t, 15> kRcon = {
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36,
    0x6C, 0xD8, 0xAB, 0x4D, 0x9A};

using Word = std::array<std::uint8_t, 4>;
using Matrix = std::array<Word, 4>;  // 4 columns x 4 rows
using RoundKeys = std::array<Matrix, kAesNr + 1>;

std::uint32_t RotRight32(const std::uint32_t v, const std::uint32_t n) {
    return (v >> n) | (v << (32U - n));
}

std::array<std::uint8_t, kSha256DigestSize> Sha256Digest(const std::uint8_t* data, const std::size_t len) {
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

    std::vector<std::uint8_t> msg;
    msg.reserve(len + kSha256BlockSize);
    msg.insert(msg.end(), data, data + len);
    const std::uint64_t bit_len = static_cast<std::uint64_t>(msg.size()) * 8ULL;
    msg.push_back(0x80U);
    while ((msg.size() % kSha256BlockSize) != 56U) {
        msg.push_back(0U);
    }
    for (int i = 7; i >= 0; --i) {
        msg.push_back(static_cast<std::uint8_t>((bit_len >> (i * 8)) & 0xFFU));
    }

    std::array<std::uint32_t, 64> w{};
    for (std::size_t chunk = 0; chunk < msg.size(); chunk += kSha256BlockSize) {
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

    std::array<std::uint8_t, kSha256DigestSize> out{};
    for (int i = 0; i < 8; ++i) {
        out[static_cast<std::size_t>(i * 4)] = static_cast<std::uint8_t>((h[i] >> 24U) & 0xFFU);
        out[static_cast<std::size_t>(i * 4 + 1)] = static_cast<std::uint8_t>((h[i] >> 16U) & 0xFFU);
        out[static_cast<std::size_t>(i * 4 + 2)] = static_cast<std::uint8_t>((h[i] >> 8U) & 0xFFU);
        out[static_cast<std::size_t>(i * 4 + 3)] = static_cast<std::uint8_t>(h[i] & 0xFFU);
    }
    volatile std::uint8_t* msg_ptr = msg.data();
    for (std::size_t i = 0; i < msg.size(); ++i) {
        msg_ptr[i] = 0U;
    }
    return out;
}

void SecureWipeRaw(void* data, const std::size_t bytes) {
    volatile std::uint8_t* ptr = static_cast<volatile std::uint8_t*>(data);
    for (std::size_t i = 0; i < bytes; ++i) {
        ptr[i] = 0U;
    }
}

template <typename T, std::size_t N>
void SecureWipeArray(std::array<T, N>& buffer) {
    SecureWipeRaw(buffer.data(), sizeof(T) * buffer.size());
}

void SecureWipeVector(std::vector<std::uint8_t>& buffer) {
    SecureWipeRaw(buffer.data(), buffer.size());
    buffer.clear();
}

void SecureWipeRoundKeys(RoundKeys& keys) {
    SecureWipeRaw(keys.data(), sizeof(keys));
}

std::size_t ProgressStepFor(const std::size_t total) {
    return std::max<std::size_t>(64U * 1024U, total / 200U);
}

void EmitProgress(
    const std::function<void(std::size_t, std::size_t)>& progress,
    const std::size_t done,
    const std::size_t total,
    std::size_t& next_update,
    const std::size_t update_step) {
    if (!progress) {
        return;
    }
    if (done >= next_update || done == total) {
        progress(done, total);
        next_update = done + update_step;
    }
}

inline std::uint8_t XTime(const std::uint8_t value) {
    if ((value & 0x80U) != 0U) {
        return static_cast<std::uint8_t>(((value << 1U) ^ 0x1BU) & 0xFFU);
    }
    return static_cast<std::uint8_t>((value << 1U) & 0xFFU);
}

inline Matrix BytesToMatrix(const std::uint8_t* in) {
    Matrix state{};
    for (std::size_t col = 0; col < 4; ++col) {
        for (std::size_t row = 0; row < 4; ++row) {
            state[col][row] = in[col * 4 + row];
        }
    }
    return state;
}

inline void MatrixToBytes(const Matrix& state, std::uint8_t* out) {
    for (std::size_t col = 0; col < 4; ++col) {
        for (std::size_t row = 0; row < 4; ++row) {
            out[col * 4 + row] = state[col][row];
        }
    }
}

inline Word XorWords(const Word& a, const Word& b) {
    return {
        static_cast<std::uint8_t>(a[0] ^ b[0]),
        static_cast<std::uint8_t>(a[1] ^ b[1]),
        static_cast<std::uint8_t>(a[2] ^ b[2]),
        static_cast<std::uint8_t>(a[3] ^ b[3])};
}

inline void AddRoundKey(Matrix& state, const Matrix& round_key) {
    for (std::size_t col = 0; col < 4; ++col) {
        for (std::size_t row = 0; row < 4; ++row) {
            state[col][row] ^= round_key[col][row];
        }
    }
}

inline void SubBytes(Matrix& state) {
    for (auto& col : state) {
        for (auto& byte : col) {
            byte = kSbox[byte];
        }
    }
}

inline void InvSubBytes(Matrix& state) {
    for (auto& col : state) {
        for (auto& byte : col) {
            byte = kInvSbox[byte];
        }
    }
}

inline void ShiftRows(Matrix& state) {
    const std::uint8_t s01 = state[0][1];
    const std::uint8_t s11 = state[1][1];
    const std::uint8_t s21 = state[2][1];
    const std::uint8_t s31 = state[3][1];
    state[0][1] = s11;
    state[1][1] = s21;
    state[2][1] = s31;
    state[3][1] = s01;

    const std::uint8_t s02 = state[0][2];
    const std::uint8_t s12 = state[1][2];
    const std::uint8_t s22 = state[2][2];
    const std::uint8_t s32 = state[3][2];
    state[0][2] = s22;
    state[1][2] = s32;
    state[2][2] = s02;
    state[3][2] = s12;

    const std::uint8_t s03 = state[0][3];
    const std::uint8_t s13 = state[1][3];
    const std::uint8_t s23 = state[2][3];
    const std::uint8_t s33 = state[3][3];
    state[0][3] = s33;
    state[1][3] = s03;
    state[2][3] = s13;
    state[3][3] = s23;
}

inline void InvShiftRows(Matrix& state) {
    const std::uint8_t s01 = state[0][1];
    const std::uint8_t s11 = state[1][1];
    const std::uint8_t s21 = state[2][1];
    const std::uint8_t s31 = state[3][1];
    state[0][1] = s31;
    state[1][1] = s01;
    state[2][1] = s11;
    state[3][1] = s21;

    const std::uint8_t s02 = state[0][2];
    const std::uint8_t s12 = state[1][2];
    const std::uint8_t s22 = state[2][2];
    const std::uint8_t s32 = state[3][2];
    state[0][2] = s22;
    state[1][2] = s32;
    state[2][2] = s02;
    state[3][2] = s12;

    const std::uint8_t s03 = state[0][3];
    const std::uint8_t s13 = state[1][3];
    const std::uint8_t s23 = state[2][3];
    const std::uint8_t s33 = state[3][3];
    state[0][3] = s13;
    state[1][3] = s23;
    state[2][3] = s33;
    state[3][3] = s03;
}

inline void MixSingleColumn(Word& a) {
    const std::uint8_t t = static_cast<std::uint8_t>(a[0] ^ a[1] ^ a[2] ^ a[3]);
    const std::uint8_t u = a[0];
    a[0] = static_cast<std::uint8_t>(a[0] ^ t ^ XTime(static_cast<std::uint8_t>(a[0] ^ a[1])));
    a[1] = static_cast<std::uint8_t>(a[1] ^ t ^ XTime(static_cast<std::uint8_t>(a[1] ^ a[2])));
    a[2] = static_cast<std::uint8_t>(a[2] ^ t ^ XTime(static_cast<std::uint8_t>(a[2] ^ a[3])));
    a[3] = static_cast<std::uint8_t>(a[3] ^ t ^ XTime(static_cast<std::uint8_t>(a[3] ^ u)));
}

inline void MixColumns(Matrix& state) {
    for (auto& col : state) {
        MixSingleColumn(col);
    }
}

inline void InvMixColumns(Matrix& state) {
    for (auto& col : state) {
        const std::uint8_t u = XTime(XTime(static_cast<std::uint8_t>(col[0] ^ col[2])));
        const std::uint8_t v = XTime(XTime(static_cast<std::uint8_t>(col[1] ^ col[3])));
        col[0] ^= u;
        col[1] ^= v;
        col[2] ^= u;
        col[3] ^= v;
    }
    MixColumns(state);
}

RoundKeys ExpandKey256(const std::array<std::uint8_t, kAes256KeySize>& key) {
    std::array<Word, 4 * (kAesNr + 1)> key_columns{};
    for (std::size_t i = 0; i < kAesNk; ++i) {
        key_columns[i] = {
            key[i * 4 + 0],
            key[i * 4 + 1],
            key[i * 4 + 2],
            key[i * 4 + 3]};
    }

    int iteration = 0;
    std::size_t column_index = kAesNk;
    while (column_index < key_columns.size()) {
        Word word = key_columns[column_index - 1];
        if ((column_index % kAesNk) == 0) {
            const std::uint8_t first = word[0];
            word[0] = word[1];
            word[1] = word[2];
            word[2] = word[3];
            word[3] = first;
            for (auto& b : word) {
                b = kSbox[b];
            }
            word[0] ^= kRcon[iteration];
            ++iteration;
        } else if ((column_index % kAesNk) == 4) {
            for (auto& b : word) {
                b = kSbox[b];
            }
        }
        key_columns[column_index] = XorWords(word, key_columns[column_index - kAesNk]);
        ++column_index;
    }

    RoundKeys round_keys{};
    for (int round = 0; round <= kAesNr; ++round) {
        for (int col = 0; col < 4; ++col) {
            round_keys[round][col] = key_columns[round * 4 + col];
        }
    }
    return round_keys;
}

std::array<std::uint8_t, kAesBlockSize> EncryptBlock(
    const RoundKeys& round_keys,
    const std::array<std::uint8_t, kAesBlockSize>& block) {
    Matrix state = BytesToMatrix(block.data());
    AddRoundKey(state, round_keys[0]);
    for (int round = 1; round < kAesNr; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, round_keys[round]);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, round_keys[kAesNr]);

    std::array<std::uint8_t, kAesBlockSize> out{};
    MatrixToBytes(state, out.data());
    return out;
}

std::array<std::uint8_t, kAesBlockSize> DecryptBlock(
    const RoundKeys& round_keys,
    const std::array<std::uint8_t, kAesBlockSize>& block) {
    Matrix state = BytesToMatrix(block.data());
    AddRoundKey(state, round_keys[kAesNr]);
    InvShiftRows(state);
    InvSubBytes(state);

    for (int round = kAesNr - 1; round >= 1; --round) {
        AddRoundKey(state, round_keys[round]);
        InvMixColumns(state);
        InvShiftRows(state);
        InvSubBytes(state);
    }
    AddRoundKey(state, round_keys[0]);

    std::array<std::uint8_t, kAesBlockSize> out{};
    MatrixToBytes(state, out.data());
    return out;
}

}  // namespace

AnarStatus CryptoEngine::Aes256EcbEncryptHex(
    const std::string_view key_hex,
    const std::string_view plaintext_hex,
    std::string& out_ciphertext_hex) {
    std::vector<std::uint8_t> key_bytes;
    AnarStatus status = ParseHex(key_hex, key_bytes);
    if (status != AnarStatus::Ok) {
        return status;
    }
    std::vector<std::uint8_t> plaintext;
    status = ParseHex(plaintext_hex, plaintext);
    if (status != AnarStatus::Ok) {
        return status;
    }

    if (key_bytes.size() != kAes256KeySize) {
        SecureWipeVector(key_bytes);
        SecureWipeVector(plaintext);
        return AnarStatus::InvalidKeyLength;
    }
    if ((plaintext.size() % kAesBlockSize) != 0U) {
        SecureWipeVector(key_bytes);
        SecureWipeVector(plaintext);
        return AnarStatus::InvalidBlockLength;
    }

    std::array<std::uint8_t, kAes256KeySize> key_array{};
    for (std::size_t i = 0; i < key_array.size(); ++i) {
        key_array[i] = key_bytes[i];
    }
    RoundKeys round_keys = ExpandKey256(key_array);

    std::vector<std::uint8_t> ciphertext;
    ciphertext.resize(plaintext.size());
    for (std::size_t i = 0; i < plaintext.size(); i += kAesBlockSize) {
        std::array<std::uint8_t, kAesBlockSize> in_block{};
        for (std::size_t j = 0; j < kAesBlockSize; ++j) {
            in_block[j] = plaintext[i + j];
        }
        const auto out_block = EncryptBlock(round_keys, in_block);
        for (std::size_t j = 0; j < kAesBlockSize; ++j) {
            ciphertext[i + j] = out_block[j];
        }
    }
    out_ciphertext_hex = ToHex(ciphertext);
    SecureWipeArray(key_array);
    SecureWipeRoundKeys(round_keys);
    SecureWipeVector(key_bytes);
    SecureWipeVector(plaintext);
    SecureWipeVector(ciphertext);
    return AnarStatus::Ok;
}

AnarStatus CryptoEngine::Aes256EcbDecryptHex(
    const std::string_view key_hex,
    const std::string_view ciphertext_hex,
    std::string& out_plaintext_hex) {
    std::vector<std::uint8_t> key_bytes;
    AnarStatus status = ParseHex(key_hex, key_bytes);
    if (status != AnarStatus::Ok) {
        return status;
    }
    std::vector<std::uint8_t> ciphertext;
    status = ParseHex(ciphertext_hex, ciphertext);
    if (status != AnarStatus::Ok) {
        return status;
    }

    if (key_bytes.size() != kAes256KeySize) {
        SecureWipeVector(key_bytes);
        SecureWipeVector(ciphertext);
        return AnarStatus::InvalidKeyLength;
    }
    if ((ciphertext.size() % kAesBlockSize) != 0U) {
        SecureWipeVector(key_bytes);
        SecureWipeVector(ciphertext);
        return AnarStatus::InvalidBlockLength;
    }

    std::array<std::uint8_t, kAes256KeySize> key_array{};
    for (std::size_t i = 0; i < key_array.size(); ++i) {
        key_array[i] = key_bytes[i];
    }
    RoundKeys round_keys = ExpandKey256(key_array);

    std::vector<std::uint8_t> plaintext;
    plaintext.resize(ciphertext.size());
    for (std::size_t i = 0; i < ciphertext.size(); i += kAesBlockSize) {
        std::array<std::uint8_t, kAesBlockSize> in_block{};
        for (std::size_t j = 0; j < kAesBlockSize; ++j) {
            in_block[j] = ciphertext[i + j];
        }
        const auto out_block = DecryptBlock(round_keys, in_block);
        for (std::size_t j = 0; j < kAesBlockSize; ++j) {
            plaintext[i + j] = out_block[j];
        }
    }
    out_plaintext_hex = ToHex(plaintext);
    SecureWipeArray(key_array);
    SecureWipeRoundKeys(round_keys);
    SecureWipeVector(key_bytes);
    SecureWipeVector(ciphertext);
    SecureWipeVector(plaintext);
    return AnarStatus::Ok;
}

AnarStatus CryptoEngine::OtpXorBytesHex(
    const std::string_view data_hex,
    const std::string_view key_hex,
    std::string& out_result_hex) {
    std::vector<std::uint8_t> data;
    AnarStatus status = ParseHex(data_hex, data);
    if (status != AnarStatus::Ok) {
        return status;
    }

    std::vector<std::uint8_t> key;
    status = ParseHex(key_hex, key);
    if (status != AnarStatus::Ok) {
        SecureWipeVector(data);
        return status;
    }

    if (key.size() < data.size()) {
        SecureWipeVector(data);
        SecureWipeVector(key);
        return AnarStatus::KeyTooShort;
    }

    std::vector<std::uint8_t> out(data.size(), 0U);
    for (std::size_t i = 0; i < data.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(data[i] ^ key[i]);
    }
    out_result_hex = ToHex(out);
    SecureWipeVector(data);
    SecureWipeVector(key);
    SecureWipeVector(out);
    return AnarStatus::Ok;
}

AnarStatus CryptoEngine::OtpXorFile(
    const std::string& input_path,
    const std::string& key_path,
    const std::string& output_path,
    std::size_t& out_bytes_processed) {
    out_bytes_processed = 0;
    std::ifstream input(input_path, std::ios::binary);
    std::ifstream key(key_path, std::ios::binary);
    std::ofstream output(output_path, std::ios::binary);
    if (!input.is_open() || !key.is_open() || !output.is_open()) {
        return AnarStatus::FileIOError;
    }

    input.seekg(0, std::ios::end);
    const std::streamoff input_size = input.tellg();
    key.seekg(0, std::ios::end);
    const std::streamoff key_size = key.tellg();
    if (input_size < 0 || key_size < 0) {
        return AnarStatus::FileIOError;
    }
    if (key_size < input_size) {
        return AnarStatus::KeyTooShort;
    }
    input.seekg(0, std::ios::beg);
    key.seekg(0, std::ios::beg);
    if (!input.good() || !key.good()) {
        return AnarStatus::FileIOError;
    }

    constexpr std::size_t kChunkSize = 4096;
    std::array<char, kChunkSize> input_chunk{};
    std::array<char, kChunkSize> key_chunk{};
    std::array<char, kChunkSize> output_chunk{};
    auto wipe_chunks = [&]() {
        SecureWipeRaw(input_chunk.data(), input_chunk.size());
        SecureWipeRaw(key_chunk.data(), key_chunk.size());
        SecureWipeRaw(output_chunk.data(), output_chunk.size());
    };

    while (true) {
        input.read(input_chunk.data(), static_cast<std::streamsize>(kChunkSize));
        const std::streamsize n = input.gcount();
        if (n <= 0) {
            break;
        }

        key.read(key_chunk.data(), n);
        if (key.gcount() != n) {
            wipe_chunks();
            return AnarStatus::KeyTooShort;
        }

        for (std::streamsize i = 0; i < n; ++i) {
            output_chunk[static_cast<std::size_t>(i)] = static_cast<char>(
                static_cast<unsigned char>(input_chunk[static_cast<std::size_t>(i)]) ^
                static_cast<unsigned char>(key_chunk[static_cast<std::size_t>(i)]));
        }
        output.write(output_chunk.data(), n);
        if (!output.good()) {
            wipe_chunks();
            return AnarStatus::FileIOError;
        }

        out_bytes_processed += static_cast<std::size_t>(n);
    }

    if (input.bad() || key.bad()) {
        wipe_chunks();
        return AnarStatus::FileIOError;
    }
    wipe_chunks();
    return AnarStatus::Ok;
}

AnarStatus CryptoEngine::Aes256CtrXor(
    const std::array<std::uint8_t, 32>& key_bytes,
    const std::array<std::uint8_t, 16>& nonce,
    const std::vector<std::uint8_t>& input,
    std::vector<std::uint8_t>& output,
    const std::function<void(std::size_t, std::size_t)>& progress) {
    RoundKeys round_keys = ExpandKey256(key_bytes);
    std::array<std::uint8_t, kAesBlockSize> counter = nonce;

    output.resize(input.size());
    const std::size_t total = input.size();
    if (progress) {
        progress(0, total);
    }

    const std::size_t update_step = std::max<std::size_t>(64U * 1024U, total / 200U);
    std::size_t next_update = update_step;
    std::size_t offset = 0;
    while (offset < input.size()) {
        auto keystream_block = EncryptBlock(round_keys, counter);
        const std::size_t n = std::min<std::size_t>(kAesBlockSize, input.size() - offset);
        for (std::size_t i = 0; i < n; ++i) {
            output[offset + i] = static_cast<std::uint8_t>(input[offset + i] ^ keystream_block[i]);
        }
        SecureWipeArray(keystream_block);
        offset += n;
        if (progress && (offset >= next_update || offset == total)) {
            progress(offset, total);
            next_update = offset + update_step;
        }

        for (int i = static_cast<int>(counter.size()) - 1; i >= 0; --i) {
            counter[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(counter[static_cast<std::size_t>(i)] + 1U);
            if (counter[static_cast<std::size_t>(i)] != 0U) {
                break;
            }
        }
    }

    SecureWipeArray(counter);
    SecureWipeRoundKeys(round_keys);
    return AnarStatus::Ok;
}

AnarStatus CryptoEngine::PqSha256StreamXor(
    const std::array<std::uint8_t, 32>& key_bytes,
    const std::array<std::uint8_t, 16>& nonce,
    const std::vector<std::uint8_t>& input,
    std::vector<std::uint8_t>& output,
    const std::function<void(std::size_t, std::size_t)>& progress) {
    constexpr std::array<std::uint8_t, 4> kDomain = {'P', 'Q', '2', '5'};
    constexpr std::size_t kPrefixBytes = kDomain.size() + 32U + 16U;
    std::array<std::uint8_t, kPrefixBytes + 8U> seed{};

    std::copy(kDomain.begin(), kDomain.end(), seed.begin());
    std::copy(key_bytes.begin(), key_bytes.end(), seed.begin() + static_cast<std::ptrdiff_t>(kDomain.size()));
    std::copy(nonce.begin(), nonce.end(), seed.begin() + static_cast<std::ptrdiff_t>(kDomain.size() + 32U));

    output.resize(input.size());
    const std::size_t total = input.size();
    if (progress) {
        progress(0, total);
    }

    const std::size_t update_step = std::max<std::size_t>(64U * 1024U, total / 200U);
    std::size_t next_update = update_step;
    std::size_t offset = 0;
    std::uint64_t counter = 0;
    while (offset < total) {
        for (std::size_t i = 0; i < 8U; ++i) {
            seed[kPrefixBytes + i] = static_cast<std::uint8_t>((counter >> (i * 8U)) & 0xFFU);
        }

        auto stream_block = Sha256Digest(seed.data(), seed.size());
        const std::size_t n = std::min<std::size_t>(stream_block.size(), total - offset);
        for (std::size_t i = 0; i < n; ++i) {
            output[offset + i] = static_cast<std::uint8_t>(input[offset + i] ^ stream_block[i]);
        }
        SecureWipeArray(stream_block);

        offset += n;
        ++counter;

        if (progress && (offset >= next_update || offset == total)) {
            progress(offset, total);
            next_update = offset + update_step;
        }
    }

    SecureWipeArray(seed);
    return AnarStatus::Ok;
}

AnarStatus CryptoEngine::ChaCha20Poly1305Encrypt(
    const std::array<std::uint8_t, 32>& key_bytes,
    const std::array<std::uint8_t, 24>& nonce,
    const std::vector<std::uint8_t>& plaintext,
    std::vector<std::uint8_t>& out_ciphertext,
    std::array<std::uint8_t, 16>& out_tag,
    const std::function<void(std::size_t, std::size_t)>& progress) {
    const std::size_t total = plaintext.size();
    if (progress) {
        progress(0, total);
    }

    out_ciphertext.resize(total);
    out_tag.fill(0U);
    try {
        CryptoPP::ChaCha20Poly1305::Encryption enc;
        enc.SetKeyWithIV(key_bytes.data(), key_bytes.size(), nonce.data(), 12);
        enc.EncryptAndAuthenticate(
            out_ciphertext.empty() ? nullptr : out_ciphertext.data(),
            out_tag.data(),
            out_tag.size(),
            nonce.data(),
            12,
            nullptr,
            0,
            plaintext.empty() ? nullptr : plaintext.data(),
            plaintext.size());
    } catch (...) {
        SecureWipeVector(out_ciphertext);
        SecureWipeArray(out_tag);
        return AnarStatus::UnknownOp;
    }

    if (progress) {
        progress(total, total);
    }
    return AnarStatus::Ok;
}

AnarStatus CryptoEngine::ChaCha20Poly1305DecryptVerify(
    const std::array<std::uint8_t, 32>& key_bytes,
    const std::array<std::uint8_t, 24>& nonce,
    const std::vector<std::uint8_t>& ciphertext,
    const std::array<std::uint8_t, 16>& tag,
    std::vector<std::uint8_t>& out_plaintext,
    bool& out_auth_ok,
    const std::function<void(std::size_t, std::size_t)>& progress) {
    const std::size_t total = ciphertext.size();
    if (progress) {
        progress(0, total);
    }

    out_auth_ok = false;
    out_plaintext.resize(total);
    try {
        CryptoPP::ChaCha20Poly1305::Decryption dec;
        dec.SetKeyWithIV(key_bytes.data(), key_bytes.size(), nonce.data(), 12);
        out_auth_ok = dec.DecryptAndVerify(
            out_plaintext.empty() ? nullptr : out_plaintext.data(),
            tag.data(),
            tag.size(),
            nonce.data(),
            12,
            nullptr,
            0,
            ciphertext.empty() ? nullptr : ciphertext.data(),
            ciphertext.size());
    } catch (...) {
        SecureWipeVector(out_plaintext);
        return AnarStatus::UnknownOp;
    }

    if (!out_auth_ok) {
        SecureWipeVector(out_plaintext);
    }
    if (progress) {
        progress(total, total);
    }
    return AnarStatus::Ok;
}

AnarStatus CryptoEngine::XChaCha20Poly1305Encrypt(
    const std::array<std::uint8_t, 32>& key_bytes,
    const std::array<std::uint8_t, 24>& nonce,
    const std::vector<std::uint8_t>& plaintext,
    std::vector<std::uint8_t>& out_ciphertext,
    std::array<std::uint8_t, 16>& out_tag,
    const std::function<void(std::size_t, std::size_t)>& progress) {
    const std::size_t total = plaintext.size();
    if (progress) {
        progress(0, total);
    }

    out_ciphertext.resize(total);
    out_tag.fill(0U);
    try {
        CryptoPP::XChaCha20Poly1305::Encryption enc;
        enc.SetKeyWithIV(key_bytes.data(), key_bytes.size(), nonce.data(), nonce.size());
        enc.EncryptAndAuthenticate(
            out_ciphertext.empty() ? nullptr : out_ciphertext.data(),
            out_tag.data(),
            out_tag.size(),
            nonce.data(),
            static_cast<int>(nonce.size()),
            nullptr,
            0,
            plaintext.empty() ? nullptr : plaintext.data(),
            plaintext.size());
    } catch (...) {
        SecureWipeVector(out_ciphertext);
        SecureWipeArray(out_tag);
        return AnarStatus::UnknownOp;
    }

    if (progress) {
        progress(total, total);
    }
    return AnarStatus::Ok;
}

AnarStatus CryptoEngine::XChaCha20Poly1305DecryptVerify(
    const std::array<std::uint8_t, 32>& key_bytes,
    const std::array<std::uint8_t, 24>& nonce,
    const std::vector<std::uint8_t>& ciphertext,
    const std::array<std::uint8_t, 16>& tag,
    std::vector<std::uint8_t>& out_plaintext,
    bool& out_auth_ok,
    const std::function<void(std::size_t, std::size_t)>& progress) {
    const std::size_t total = ciphertext.size();
    if (progress) {
        progress(0, total);
    }

    out_auth_ok = false;
    out_plaintext.resize(total);
    try {
        CryptoPP::XChaCha20Poly1305::Decryption dec;
        dec.SetKeyWithIV(key_bytes.data(), key_bytes.size(), nonce.data(), nonce.size());
        out_auth_ok = dec.DecryptAndVerify(
            out_plaintext.empty() ? nullptr : out_plaintext.data(),
            tag.data(),
            tag.size(),
            nonce.data(),
            static_cast<int>(nonce.size()),
            nullptr,
            0,
            ciphertext.empty() ? nullptr : ciphertext.data(),
            ciphertext.size());
    } catch (...) {
        SecureWipeVector(out_plaintext);
        return AnarStatus::UnknownOp;
    }

    if (!out_auth_ok) {
        SecureWipeVector(out_plaintext);
    }
    if (progress) {
        progress(total, total);
    }
    return AnarStatus::Ok;
}

AnarStatus CryptoEngine::Serpent256CtrXor(
    const std::array<std::uint8_t, 32>& key_bytes,
    const std::array<std::uint8_t, 16>& nonce,
    const std::vector<std::uint8_t>& input,
    std::vector<std::uint8_t>& output,
    const std::function<void(std::size_t, std::size_t)>& progress) {
    output.resize(input.size());
    const std::size_t total = input.size();
    if (progress) {
        progress(0, total);
    }

    try {
        CryptoPP::CTR_Mode<CryptoPP::Serpent>::Encryption enc;
        enc.SetKeyWithIV(key_bytes.data(), key_bytes.size(), nonce.data(), nonce.size());

        const std::size_t update_step = ProgressStepFor(total);
        std::size_t next_update = update_step;
        std::size_t offset = 0;
        constexpr std::size_t kChunk = 64U * 1024U;
        while (offset < total) {
            const std::size_t n = std::min<std::size_t>(kChunk, total - offset);
            enc.ProcessData(output.data() + offset, input.data() + offset, n);
            offset += n;
            EmitProgress(progress, offset, total, next_update, update_step);
        }
    } catch (...) {
        SecureWipeVector(output);
        return AnarStatus::UnknownOp;
    }

    if (progress) {
        progress(total, total);
    }
    return AnarStatus::Ok;
}

AnarStatus CryptoEngine::OtpXorBytes(
    const std::vector<std::uint8_t>& input,
    const std::vector<std::uint8_t>& key_bytes,
    std::vector<std::uint8_t>& output,
    const std::function<void(std::size_t, std::size_t)>& progress) {
    if (key_bytes.size() < input.size()) {
        return AnarStatus::KeyTooShort;
    }
    const std::size_t total = input.size();
    output.resize(total);
    if (progress) {
        progress(0, total);
    }

    constexpr std::size_t kOtpChunkBytes = 64U * 1024U;
    std::size_t offset = 0;
    while (offset < total) {
        const std::size_t n = std::min<std::size_t>(kOtpChunkBytes, total - offset);
        for (std::size_t i = 0; i < n; ++i) {
            output[offset + i] = static_cast<std::uint8_t>(input[offset + i] ^ key_bytes[offset + i]);
        }
        offset += n;
        if (progress) {
            progress(offset, total);
        }
    }
    return AnarStatus::Ok;
}

AnarStatus CryptoEngine::ParseHex(const std::string_view hex, std::vector<std::uint8_t>& out_bytes) {
    if ((hex.size() % 2U) != 0U) {
        return AnarStatus::BadHex;
    }

    auto nibble = [](const char ch) -> int {
        if (ch >= '0' && ch <= '9') {
            return ch - '0';
        }
        if (ch >= 'a' && ch <= 'f') {
            return 10 + (ch - 'a');
        }
        if (ch >= 'A' && ch <= 'F') {
            return 10 + (ch - 'A');
        }
        return -1;
    };

    out_bytes.clear();
    out_bytes.reserve(hex.size() / 2U);
    for (std::size_t i = 0; i < hex.size(); i += 2U) {
        const int high = nibble(hex[i]);
        const int low = nibble(hex[i + 1U]);
        if (high < 0 || low < 0) {
            SecureWipeVector(out_bytes);
            return AnarStatus::BadHex;
        }
        out_bytes.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }
    return AnarStatus::Ok;
}

std::string CryptoEngine::ToHex(const std::vector<std::uint8_t>& data) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2U);
    for (const std::uint8_t b : data) {
        out.push_back(kHex[(b >> 4U) & 0x0FU]);
        out.push_back(kHex[b & 0x0FU]);
    }
    return out;
}

}  // namespace safeanar
