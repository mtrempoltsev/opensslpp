#pragma once

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

namespace opensslpp
{
    static constexpr int Success = 1;

    struct Sha256Type
    {
        static constexpr decltype(EVP_sha256)* Function = &EVP_sha256;
    };

    struct Sha512Type
    {
        static constexpr decltype(EVP_sha256)* Function = &EVP_sha512;
    };

    using BignumPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
    using RsaPtr = std::unique_ptr<RSA, decltype(&RSA_free)>;
    using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using KeyContextPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
    using CipherContextPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
    using DigestContextPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    using BioMemPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

    template <class BioMethod>
    BioMemPtr makeBio(BioMethod method)
    {
        return BioMemPtr(BIO_new(method), BIO_free);
    }

    inline BioMemPtr makeBio(BIO* bio)
    {
        return BioMemPtr(bio, BIO_free);
    }

    template <class WritePem>
    std::string keyToString(WritePem write)
    {
        auto bio = makeBio(BIO_s_mem());

        if (write(bio.get()) != Success)
            return std::string();

        BUF_MEM* buffer = nullptr;
        BIO_get_mem_ptr(bio.get(), &buffer);

        if (!buffer || !buffer->data || !buffer->length)
            return std::string();

        return std::string(buffer->data, buffer->length);
    }
}
