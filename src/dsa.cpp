#include "../include/opensslpp/dsa.h"

#include <openssl/dsa.h>
#include <openssl/pem.h>

#include "../include/opensslpp/random.h"

#include "common.h"

namespace
{
    using DsaPtr = std::unique_ptr<DSA, decltype(&DSA_free)>;
}

std::unique_ptr<opensslpp::Dsa> opensslpp::Dsa::createNewKeys(int bits)
{
    auto random = Random::create();
    if (!random)
        return nullptr;

    DsaPtr dsa(DSA_new(), DSA_free);
    if (!dsa)
        return nullptr;

    const int seedSize = 32;
    const auto seed = random->getRandomBytes(seedSize);

    if (seed.size() != seedSize)
        return nullptr;

    if (DSA_generate_parameters_ex(dsa.get(), bits, seed.data(), seed.size(), nullptr, nullptr, nullptr) != Success)
        return nullptr;

    if (DSA_generate_key(dsa.get()) != Success)
        return nullptr;

    auto result = std::unique_ptr<Dsa>(new Dsa());
    result->dsa_ = dsa.release();
    return result;
}

std::unique_ptr<opensslpp::Dsa> opensslpp::Dsa::createWithPublicKey(const std::string& publicKey)
{
    auto result = std::unique_ptr<Dsa>(new Dsa());
    result->dsa_ = createWithKey<DSA>(publicKey, [](BIO* bio)
    {
        return PEM_read_bio_DSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    });
    return result;
}

std::unique_ptr<opensslpp::Dsa> opensslpp::Dsa::createWithPrivateKey(const std::string& privateKey)
{
    auto result = std::unique_ptr<Dsa>(new Dsa());
    result->dsa_ = createWithKey<DSA>(privateKey, [](BIO* bio)
    {
        return PEM_read_bio_DSAPrivateKey(bio, nullptr, nullptr, nullptr);
    });
    return result;
}

std::string opensslpp::Dsa::publicKey() const
{
    return keyToString([this](BIO* bio)
    {
        return PEM_write_bio_DSA_PUBKEY(bio, dsa_);
    });
}

std::string opensslpp::Dsa::privateKey() const
{
    return keyToString([this](BIO* bio)
    {
        return PEM_write_bio_DSAPrivateKey(bio, dsa_, nullptr, nullptr, 0, nullptr, nullptr);
    });
}

opensslpp::Dsa::Dsa()
    : dsa_(nullptr)
{
}

opensslpp::Dsa::~Dsa()
{
    if (dsa_)
        DSA_free(dsa_);
}
