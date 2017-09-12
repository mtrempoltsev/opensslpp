#include "../include/opensslpp/sha256.h"

#include <openssl/sha.h>

opensslpp::Sha256::Digest opensslpp::Sha256::calculate(const std::string& message)
{
    Digest result;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message.c_str(), message.size());
    SHA256_Final(result.data(), &sha256);
    return result;
}
