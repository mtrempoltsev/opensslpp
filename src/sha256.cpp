#include "../include/opensslpp/sha256.h"

#include <openssl/sha.h>

#include "../include/opensslpp/base64.h"

opensslpp::Sha256::Digest opensslpp::Sha256::calculate(const std::string& message)
{
    Digest result;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message.c_str(), message.size());
    SHA256_Final(result.data(), &sha256);
    return result;
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
