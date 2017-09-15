#include "../include/opensslpp/base64.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include "common.h"

std::string opensslpp::Base64::encode(const std::vector<uint8_t>& data)
{
    return encode(data.data(), data.size());
}

std::string opensslpp::Base64::encode(const uint8_t* data, size_t size)
{
    auto encoder = makeBio(BIO_f_base64());
    auto buffer = makeBio(BIO_s_mem());
    auto stream = BIO_push(encoder.get(), buffer.get());

    if (!stream)
        return std::string();

    BIO_set_flags(stream, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(stream, data, size);
    BIO_flush(stream);

    BUF_MEM* ptr = nullptr;
    BIO_get_mem_ptr(stream, &ptr);

    return std::string(ptr->data, ptr->length);
}

std::vector<uint8_t> opensslpp::Base64::decode(const std::string& text)
{
    const auto size = calculateLengthOfDecoded(text);

    std::vector<uint8_t> result(size);

    if (decode(text, result.data(), result.size()) != size)
        return std::vector<uint8_t>();

    return result;
}

size_t opensslpp::Base64::decode(const std::string& text, uint8_t* data, size_t size)
{
    auto buffer = makeBio(BIO_new_mem_buf(text.c_str(), text.size()));
    auto decoder = makeBio(BIO_f_base64());
    auto stream = BIO_push(decoder.get(), buffer.get());

    if (!stream)
        return 0;

    BIO_set_flags(stream, BIO_FLAGS_BASE64_NO_NL);
    return BIO_read(stream, data, size);
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
