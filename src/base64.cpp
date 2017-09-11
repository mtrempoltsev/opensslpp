#include "../include/opensslpp/base64.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include "common.h"

std::string opensslpp::Base64::encode(const std::vector<unsigned char>& data)
{
    auto encoder = makeBio(BIO_f_base64());
    auto buffer = makeBio(BIO_s_mem());
    auto stream = BIO_push(encoder.get(), buffer.get());

    if (!stream)
        return std::string();

    BIO_set_flags(stream, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(stream, data.data(), data.size());
    BIO_flush(stream);

    BUF_MEM* ptr = nullptr;
    BIO_get_mem_ptr(stream, &ptr);

    return std::string(ptr->data, ptr->length);
}

std::vector<unsigned char> opensslpp::Base64::decode(const std::string& text)
{
    auto buffer = makeBio(BIO_new_mem_buf(text.c_str(), text.size()));
    auto decoder = makeBio(BIO_f_base64());
    auto stream = BIO_push(decoder.get(), buffer.get());

    if (!stream)
        return std::vector<unsigned char>();

    std::vector<unsigned char> result(calculateLengthOfDecoded(text));

    BIO_set_flags(stream, BIO_FLAGS_BASE64_NO_NL);
    BIO_read(stream, result.data(), result.size());

    return result;
}

size_t opensslpp::Base64::calculateLengthOfDecoded(const std::string& text)
{
    const size_t length = text.length();

    size_t padding = 0;
    if (text[length - 1] == '=')
    {
        padding = text[length - 2] == '=' ? 2 : 1;
    }

    return (length * 3) / 4 - padding;
}
