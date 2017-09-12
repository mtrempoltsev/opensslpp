#pragma once

#include <array>

namespace opensslpp
{
    class Sha256 final
    {
    public:
        static constexpr size_t DigestSize = 32;
        using Digest = std::array<unsigned char, DigestSize>;

        static Digest calculate(const std::string& message);
    };
}
