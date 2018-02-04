#pragma once

#include "base64.h"
#include "random.h"

namespace opensslpp
{
    class Random;

    template <size_t Bits>
    class AesCbc final
    {
    public:
        using Key = std::array<uint8_t, Bits / 8>;

        static constexpr size_t IvSize = 128 / 8;
        using Iv = std::array<uint8_t, IvSize>;

        static constexpr decltype(EVP_aes_256_cbc)* Mode = &EVP_aes_256_cbc;

        static std::unique_ptr<AesCbc> createNewKey()
        {
            auto random = Random::create();
            if (!random)
                return nullptr;

            Key key;
            if (!random->getRandomBytes(key.data(), key.size()))
                return nullptr;

            return std::unique_ptr<AesCbc>(new AesCbc(std::move(random), std::move(key)));
        }

        static std::unique_ptr<AesCbc> createWithKey(const std::string& base64Key)
        {
            auto random = Random::create();
            if (!random)
                return nullptr;

            Key key;

            if (Base64::decode(base64Key, key.data(), key.size()) != key.size())
                return nullptr;

            return std::unique_ptr<AesCbc>(new AesCbc(std::move(random), std::move(key)));
        }

        std::string base64Key() const
        {
            return Base64::encode(key_.data(), key_.size());
        }

        const Key& key() const
        {
            return key_;
        }

        bool encrypt(const std::string& plainText, std::vector<uint8_t>& cipher, Iv& iv) const
        {
            return encrypt(reinterpret_cast<const uint8_t*>(plainText.c_str()), plainText.size(), cipher, iv);
        }

        bool encrypt(const uint8_t* plainData, size_t plainDataSize, std::vector<uint8_t>& cipher, Iv& iv) const
        {
            if (!random_->getRandomBytes(iv.data(), iv.size()))
                return false;

            CipherContextPtr context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
            if (!context)
                return false;

            if (EVP_EncryptInit_ex(context.get(), EVP_aes_256_cbc(), nullptr, key_.data(), iv.data()) != Success)
                return false;

            cipher.resize(getCipherSize(plainDataSize));

            int size = 0;

            if (EVP_EncryptUpdate(context.get(), cipher.data(), &size, plainData, plainDataSize) != Success)
                return false;

            if (EVP_EncryptFinal_ex(context.get(), cipher.data() + size, &size) != Success)
                return false;

            return true;
        }

        bool decrypt(const std::vector<uint8_t>& cipher, const Iv& iv, std::vector<uint8_t>& plainData) const
        {
            CipherContextPtr context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
            if (!context)
                return false;

            if (EVP_DecryptInit_ex(context.get(), EVP_aes_256_cbc(), nullptr, key_.data(), iv.data()) != Success)
                return false;

            plainData.resize(cipher.size());

            int size = 0;
            if (EVP_DecryptUpdate(context.get(), plainData.data(), &size, cipher.data(), cipher.size()) != Success)
                return false;

            auto plainDataSize = size;

            if (EVP_DecryptFinal_ex(context.get(), plainData.data() + size, &size) != Success)
                return false;

            plainDataSize += size;

            plainData.resize(plainDataSize);

            return true;
        }

        static constexpr size_t getCipherSize(size_t plainSize)
        {
            return (plainSize / IvSize + 1) * IvSize;
        }

    private:
        AesCbc(std::unique_ptr<Random>&& random, Key&& key)
            : random_(std::move(random))
            , key_(std::move(key))
        {
        }

    private:
        std::unique_ptr<Random> random_;
        Key key_;
    };

    using Aes256Cbc = AesCbc<256>;
}
