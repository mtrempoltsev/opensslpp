#include "../include/opensslpp/random.h"

#include <openssl/rand.h>

#include "common.h"

std::unique_ptr<opensslpp::Random> opensslpp::Random::create()
{
    if (RAND_status() != Success)
    {
        if (!seed())
        {
            return nullptr;
        }
    }

    return std::unique_ptr<Random>(new Random());
}

std::vector<unsigned char> opensslpp::Random::getRandomBytes(size_t count) const
{
    std::vector<unsigned char> result(count);

    if (RAND_bytes(result.data(), count) != Success)
        result.clear();

    return result;
}

bool opensslpp::Random::seed()
{
    //TODO implement this
    return false;
}

opensslpp::Random::Random()
{
}
