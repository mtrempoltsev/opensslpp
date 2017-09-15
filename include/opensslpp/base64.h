#pragma once

#include <array>
#include <string>
#include <vector>

namespace opensslpp
{
    class Base64 final
    {
    public:
        static std::string encode(const std::vector<uint8_t>& data);
        static std::string encode(const uint8_t* data, size_t size);

        static std::vector<uint8_t> decode(const std::string& text);
        static size_t decode(const std::string& text, uint8_t* data, size_t size);

    private:
        static size_t calculateLengthOfDecoded(const std::string& text);
    };
}
