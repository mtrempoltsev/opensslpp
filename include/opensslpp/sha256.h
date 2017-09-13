#pragma once

#include <array>

namespace opensslpp
{
    class Sha256 final
    {
    public:
        static constexpr size_t DigestSize = 32;
        using Digest = std::array<unsigned char, DigestSize>;

        static bool calculate(const std::string& message, Digest& result);

        static std::string toBase64(const Digest& digest);
        static Digest fromBase64(const std::string& digest);
    };
}
