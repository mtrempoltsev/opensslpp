#include "../include/opensslpp/sha256.h"

#include "../include/opensslpp/base64.h"

#include "common.h"

bool opensslpp::Sha256::calculate(const std::string& message, Digest& result)
{
    DigestContextPtr context(EVP_MD_CTX_create(), EVP_MD_CTX_free);
    if (!context)
        return false;

    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != Success)
        return false;

    if (EVP_DigestUpdate(context.get(), message.c_str(), message.size()) != Success)
        return false;

    unsigned size = 0;
    if (EVP_DigestFinal_ex(context.get(), result.data(), &size) != Success)
        return false;

    return true;
}

std::string opensslpp::Sha256::toBase64(const Digest& digest)
{
    return Base64::encode(digest.data(), digest.size());
}

opensslpp::Sha256::Digest opensslpp::Sha256::fromBase64(const std::string& digest)
{
    Digest result;
    Base64::decode(digest, result.data(), result.size());
    return result;
}
