#pragma once

#include <string>
#include <vector>

namespace opensslpp
{
    class Base64 final
    {
    public:
        static std::string encode(const std::vector<unsigned char>& data);
        static std::vector<unsigned char> decode(const std::string& text);

    private:
        static size_t calculateLengthOfDecoded(const std::string& text);
    };
}
