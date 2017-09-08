#pragma once

#include <memory>

#include <openssl/bio.h>

namespace opensslpp
{
    static constexpr int Success = 1;

    using BioMemPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

    template <class WritePem>
    std::string keyToString(WritePem write)
    {
        BioMemPtr bio(BIO_new(BIO_s_mem()), BIO_free);

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
        BioMemPtr bio(BIO_new_mem_buf(key.c_str(), key.size()), &BIO_free);
        return read(bio.get());
    }
}
