#pragma once

#include "base64.h"

namespace opensslpp
{
    template <size_t Bits, class Type>
    class Sha final
    {
    public:
        static constexpr size_t DigestSize = Bits / 8;
        using Digest = std::array<uint8_t, DigestSize>;

        static bool calculate(const std::string& message, Digest& result)
        {
            DigestContextPtr context(EVP_MD_CTX_create(), EVP_MD_CTX_free);
            if (!context)
                return false;

            if (EVP_DigestInit_ex(context.get(), Type::Function(), nullptr) != Success)
                return false;

            if (EVP_DigestUpdate(context.get(), message.c_str(), message.size()) != Success)
                return false;

            unsigned size = 0;
            if (EVP_DigestFinal_ex(context.get(), result.data(), &size) != Success)
                return false;

            return true;
        }

        static std::string toBase64(const Digest& digest)
        {
            return Base64::encode(digest.data(), digest.size());
        }

        static Digest fromBase64(const std::string& digest)
        {
            Digest result;
            Base64::decode(digest, result.data(), result.size());
            return result;
        }
    };

    using Sha256 = Sha<256, Sha256Type>;
    using Sha512 = Sha<512, Sha512Type>;
}
