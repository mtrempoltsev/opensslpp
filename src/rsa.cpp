#include "../include/opensslpp/rsa.h"

#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "../include/opensslpp/random.h"

#include "common.h"

namespace
{
    using BignumPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
    using RsaPtr = std::unique_ptr<RSA, decltype(&RSA_free)>;
}

std::unique_ptr<opensslpp::Rsa> opensslpp::Rsa::createNewKeys(size_t bits)
{
    if (!Random::create())
        return nullptr;

    BignumPtr exponent(BN_new(), BN_free);
    if (!exponent)
        return nullptr;

    if (BN_set_word(exponent.get(), RSA_F4) != Success)
        return nullptr;

    RsaPtr rsa(RSA_new(), RSA_free);

    if (RSA_generate_key_ex(rsa.get(), bits, exponent.get(), nullptr) != Success)
        return nullptr;

    auto result = std::unique_ptr<Rsa>(new Rsa());
    result->rsa_ = rsa.release();
    return result;
}

std::unique_ptr<opensslpp::Rsa> opensslpp::Rsa::createWithPublicKey(const std::string& publicKey)
{
    auto result = std::unique_ptr<Rsa>(new Rsa());
    result->rsa_ = createWithKey<RSA>(publicKey, [](BIO* bio)
    {
        return PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
    });
    return result;
}

std::unique_ptr<opensslpp::Rsa> opensslpp::Rsa::createWithPrivateKey(const std::string& privateKey)
{
    auto result = std::unique_ptr<Rsa>(new Rsa());
    result->rsa_ = createWithKey<RSA>(privateKey, [](BIO* bio)
    {
        return PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    });
    return result;
}

std::string opensslpp::Rsa::publicKey() const
{
    return keyToString([this](BIO* bio)
    {
        return PEM_write_bio_RSAPublicKey(bio, rsa_);
    });
}

std::string opensslpp::Rsa::privateKey() const
{
    return keyToString([this](BIO* bio)
    {
        return PEM_write_bio_RSAPrivateKey(bio, rsa_, nullptr, nullptr, 0, nullptr, nullptr);
    });
}

opensslpp::Rsa::Rsa()
    : rsa_(nullptr)
{
}

opensslpp::Rsa::~Rsa()
{
    if (rsa_)
        RSA_free(rsa_);
}
