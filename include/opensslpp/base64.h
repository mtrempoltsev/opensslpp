#pragma once

#include <array>
#include <string>
#include <vector>

namespace opensslpp
{
    class Base64 final
    {
    public:
        static std::string encode(const std::vector<unsigned char>& data);
        static std::string encode(const unsigned char* data, size_t size);

        static std::vector<unsigned char> decode(const std::string& text);
        static size_t decode(const std::string& text, unsigned char* data, size_t size);

    private:
        static size_t calculateLengthOfDecoded(const std::string& text);
    };
}
