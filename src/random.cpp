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

std::vector<uint8_t> opensslpp::Random::getRandomBytes(size_t count) const
{
    std::vector<uint8_t> result(count);

    if (RAND_bytes(result.data(), count) != Success)
        result.clear();

    return result;
}

bool opensslpp::Random::getRandomBytes(uint8_t* result, size_t count) const
{
    return RAND_bytes(result, count) == Success;
}

bool opensslpp::Random::seed()
{
    //TODO implement this
    return false;
}

opensslpp::Random::Random()
{
}

opensslpp::Random::~Random()
{
}
