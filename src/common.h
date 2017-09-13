#pragma once

#include <memory>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

namespace opensslpp
{
    static constexpr int Success = 1;

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

    template <class Algorithm, class ReadPem>
    Algorithm* createWithKey(const std::string& key, ReadPem read)
    {
        auto bio = makeBio(BIO_new_mem_buf(key.c_str(), key.size()));
        return read(bio.get());
    }
}
