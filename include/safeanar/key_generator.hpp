#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "safeanar/anar_status.hpp"

namespace safeanar {

constexpr std::size_t kDefaultGeneratedWordCount = 32;
constexpr std::size_t kDefaultGeneratedCharCount = 43;

class KeyGenerator {
public:
    static AnarStatus GenerateWords(std::size_t count, std::vector<std::string>& out_words);
    static AnarStatus GenerateChars(std::size_t length, std::string& out_chars);
    static std::string JoinWords(const std::vector<std::string>& words);
    static const std::string& CharacterAlphabet();
};

}  // namespace safeanar

