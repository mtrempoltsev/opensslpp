#pragma once

#include "aes.h"
#include "random.h"

namespace opensslpp
{
    template <size_t Bits, class Mode>
    class Rsa final
    {
        using RsaT = Rsa<Bits, Mode>;
    public:
        static constexpr size_t Bits = Bits;
        static constexpr size_t KeySize = Bits / 8;
        using EncryptedKey = std::array<uint8_t, KeySize>;

        static std::unique_ptr<RsaT> createNewKeys()
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

            return std::unique_ptr<RsaT>(new RsaT(std::move(rsa)));
        }

        static std::unique_ptr<RsaT> createWithPublicKey(const std::string& publicKey)
        {
            RsaPtr rsa(
                createWithKey<RSA>(publicKey, [](BIO* bio)
                {
                    return PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
                }),
                RSA_free);
            return std::unique_ptr<RsaT>(new RsaT(std::move(rsa)));
        }

        static std::unique_ptr<RsaT> createWithPrivateKey(const std::string& privateKey)
        {
            RsaPtr rsa(
                createWithKey<RSA>(privateKey, [](BIO* bio)
                {
                    return PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
                }),
                RSA_free);
            return std::unique_ptr<RsaT>(new RsaT(std::move(rsa)));
        }

        std::string publicKey() const
        {
            return keyToString([this](BIO* bio)
            {
                return PEM_write_bio_RSAPublicKey(bio, rsa_.get());
            });
        }

        std::string privateKey() const
        {
            return keyToString([this](BIO* bio)
            {
                return PEM_write_bio_RSAPrivateKey(bio, rsa_.get(), nullptr, nullptr, 0, nullptr, nullptr);
            });
        }

        bool encrypt(const std::string& plainText, EncryptedKey& key, Aes256::Iv& iv, std::vector<uint8_t>& cipher) const
        {
            return encrypt(reinterpret_cast<const uint8_t*>(plainText.c_str()), plainText.size(), key, iv, cipher);
        }

        bool encrypt(const uint8_t* plainData, size_t plainDataSize, EncryptedKey& key, Aes256::Iv& iv, std::vector<uint8_t>& cipher) const
        {
            PublicKeyPtr publicKey(EVP_PKEY_new(), EVP_PKEY_free);
            if (!publicKey)
                return false;

            if (EVP_PKEY_set1_RSA(publicKey.get(), rsa_.get()) != Success)
                return false;

            CipherContextPtr context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
            if (!context)
                return false;

            const int publicKeysCount = 1;
            uint8_t* keys[] = { key.data() };
            EVP_PKEY* publicKeys[] = { publicKey.get() };

            int keySize = 0;
            if (EVP_SealInit(context.get(), Mode::function(), keys, &keySize, iv.data(), publicKeys, publicKeysCount) != publicKeysCount)
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

        bool decrypt(const EncryptedKey& key, const Aes256::Iv& iv, const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plainData) const
        {
            PublicKeyPtr privateKey(EVP_PKEY_new(), EVP_PKEY_free);
            if (!privateKey)
                return false;

            if (EVP_PKEY_set1_RSA(privateKey.get(), rsa_.get()) != Success)
                return false;

            CipherContextPtr context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
            if (!context)
                return false;

            if (EVP_OpenInit(context.get(), Mode::function(), key.data(), key.size(), iv.data(), privateKey.get()) != Success)
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

        bool sign(const std::string& plainText, std::vector<uint8_t>& signature)
        {

        }

        bool isCorrectSignature(const std::vector<uint8_t>& signature)
        {

        }

        Rsa(const Rsa&) = delete;
        Rsa& operator=(const Rsa&) = delete;

        Rsa(Rsa&&) = delete;
        Rsa& operator=(Rsa&&) = delete;

        ~Rsa()
        {
        }

    private:
        Rsa(RsaPtr&& rsa)
            : rsa_(std::move(rsa))
        {
        }

    private:
        RsaPtr rsa_;
    };

    using Rsa2048 = Rsa<2048, AesCbc256Mode>;
}
