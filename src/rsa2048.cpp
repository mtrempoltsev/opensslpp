#include "../include/opensslpp/rsa2048.h"

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

std::unique_ptr<opensslpp::Rsa2048> opensslpp::Rsa2048::createNewKeys()
{
    if (!Random::create())
        return nullptr;

    BignumPtr exponent(BN_new(), BN_free);
    if (!exponent)
        return nullptr;

    if (BN_set_word(exponent.get(), RSA_F4) != Success)
        return nullptr;

    RsaPtr rsa(RSA_new(), RSA_free);

    if (RSA_generate_key_ex(rsa.get(), Bits, exponent.get(), nullptr) != Success)
        return nullptr;

    auto result = std::unique_ptr<Rsa2048>(new Rsa2048());
    result->rsa_ = rsa.release();
    return result;
}

std::unique_ptr<opensslpp::Rsa2048> opensslpp::Rsa2048::createWithPublicKey(const std::string& publicKey)
{
    auto result = std::unique_ptr<Rsa2048>(new Rsa2048());
    result->rsa_ = createWithKey<RSA>(publicKey, [](BIO* bio)
    {
        return PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
    });
    return result;
}

std::unique_ptr<opensslpp::Rsa2048> opensslpp::Rsa2048::createWithPrivateKey(const std::string& privateKey)
{
    auto result = std::unique_ptr<Rsa2048>(new Rsa2048());
    result->rsa_ = createWithKey<RSA>(privateKey, [](BIO* bio)
    {
        return PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    });
    return result;
}

std::string opensslpp::Rsa2048::publicKey() const
{
    return keyToString([this](BIO* bio)
    {
        return PEM_write_bio_RSAPublicKey(bio, rsa_);
    });
}

std::string opensslpp::Rsa2048::privateKey() const
{
    return keyToString([this](BIO* bio)
    {
        return PEM_write_bio_RSAPrivateKey(bio, rsa_, nullptr, nullptr, 0, nullptr, nullptr);
    });
}

bool opensslpp::Rsa2048::encrypt(const std::string& plainText, EncryptedKey& key, Aes256::Iv& iv, std::vector<uint8_t>& cipher) const
{
    return encrypt(reinterpret_cast<const uint8_t*>(plainText.c_str()), plainText.size(), key, iv, cipher);
}

bool opensslpp::Rsa2048::encrypt(const uint8_t* plainData, size_t plainDataSize, EncryptedKey& key, Aes256::Iv& iv, std::vector<uint8_t>& cipher) const
{
    PublicKeyPtr publicKey(EVP_PKEY_new(), EVP_PKEY_free);
    if (!publicKey)
        return false;

    if (EVP_PKEY_set1_RSA(publicKey.get(), rsa_) != Success)
        return false;

    CipherContextPtr context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context)
        return false;

    const int publicKeysCount = 1;
    uint8_t* keys[] = { key.data() };
    EVP_PKEY* publicKeys[] = { publicKey.get() };

    int keySize = 0;
    if (EVP_SealInit(context.get(), EVP_aes_256_cbc(), keys, &keySize, iv.data(), publicKeys, publicKeysCount) != publicKeysCount)
        return false;

    const size_t cipherSize = Aes256::getCipherSize(plainDataSize);
    cipher.resize(cipherSize);

    int size = 0;
    if (EVP_SealUpdate(context.get(), cipher.data(), &size, plainData, plainDataSize) != Success)
        return false;

    if (EVP_SealFinal(context.get(), cipher.data() + size, &size) != Success)
        return false;

    return true;
}

bool opensslpp::Rsa2048::decrypt(const EncryptedKey& key, const Aes256::Iv& iv, const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plainData) const
{
    PublicKeyPtr privateKey(EVP_PKEY_new(), EVP_PKEY_free);
    if (!privateKey)
        return false;

    if (EVP_PKEY_set1_RSA(privateKey.get(), rsa_) != Success)
        return false;

    CipherContextPtr context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context)
        return false;

    if (EVP_OpenInit(context.get(), EVP_aes_256_cbc(), key.data(), key.size(), iv.data(), privateKey.get()) != Success)
        return false;

    plainData.resize(cipher.size());

    int size = 0;
    if (EVP_OpenUpdate(context.get(), plainData.data(), &size, cipher.data(), cipher.size()) != Success)
        return false;

    auto plainDataSize = size;

    if (EVP_OpenFinal(context.get(), plainData.data() + size, &size) != Success)
        return false;

    plainDataSize += size;

    plainData.resize(plainDataSize);

    return true;
}

opensslpp::Rsa2048::Rsa2048()
    : rsa_(nullptr)
{
}

opensslpp::Rsa2048::~Rsa2048()
{
    if (rsa_)
        RSA_free(rsa_);
}
