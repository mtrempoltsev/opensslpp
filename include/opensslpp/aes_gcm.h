#pragma once

#include "base64.h"
#include "random.h"

namespace opensslpp
{
    class Random;

    template <size_t Bits>
    class AesGcm final
    {
    public:
        using Key = std::array<uint8_t, Bits / 8>;

        static constexpr size_t IvSize = 96 / 8;
        using Iv = std::array<uint8_t, IvSize>;

        static constexpr size_t TagSize = 128 / 8;
        using Tag = std::array<uint8_t, TagSize>;

        static std::unique_ptr<AesGcm> createNewKey()
        {
            auto random = Random::create();
            if (!random)
                return nullptr;

            Key key;
            if (!random->getRandomBytes(key.data(), key.size()))
                return nullptr;

            return std::unique_ptr<AesGcm>(new AesGcm(std::move(random), std::move(key)));
        }

        static std::unique_ptr<AesGcm> createWithKey(const std::string& base64Key)
        {
            auto random = Random::create();
            if (!random)
                return nullptr;

            Key key;

            if (Base64::decode(base64Key, key.data(), key.size()) != key.size())
                return nullptr;

            return std::unique_ptr<AesGcm>(new AesGcm(std::move(random), std::move(key)));
        }

        std::string base64Key() const
        {
            return Base64::encode(key_.data(), key_.size());
        }

        const Key& key() const
        {
            return key_;
        }

        bool encrypt(const std::string& plainText, std::vector<uint8_t>& cipher, Iv& iv, Tag& tag) const
        {
            return encrypt(reinterpret_cast<const uint8_t*>(plainText.c_str()), plainText.size(), cipher, iv, tag);
        }

        bool encrypt(const uint8_t* plainData, size_t plainDataSize, std::vector<uint8_t>& cipher, Iv& iv, Tag& tag) const
        {
            if (!random_->getRandomBytes(iv.data(), iv.size()))
                return false;

            CipherContextPtr context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
            if (!context)
                return false;

            if (EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != Success)
                return false;

            if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, IvSize, nullptr) != Success)
                return false;

            if (EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key_.data(), iv.data()) != Success)
                return false;

            cipher.resize(getCipherSize(plainDataSize));

            int size = 0;

            if (EVP_EncryptUpdate(context.get(), cipher.data(), &size, plainData, plainDataSize) != Success)
                return false;

            if (EVP_EncryptFinal_ex(context.get(), cipher.data() + size, &size) != Success)
                return false;

            if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) != Success)
                return false;

            return true;
        }

        bool decrypt(const std::vector<uint8_t>& cipher, const Iv& iv, const Tag& tag, std::vector<uint8_t>& plainData) const
        {
            CipherContextPtr context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
            if (!context)
                return false;

            if (EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != Success)
                return false;

            if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, IvSize, nullptr) != Success)
                return false;

            if (EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key_.data(), iv.data()) != Success)
                return false;

            plainData.resize(cipher.size());

            int size = 0;

            if (EVP_DecryptUpdate(context.get(), plainData.data(), &size, cipher.data(), cipher.size()) != Success)
                return false;

            if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, tag.size(), const_cast<uint8_t*>(tag.data())) != Success)
                return false;

            if (EVP_DecryptFinal_ex(context.get(), plainData.data() + size, &size) != Success)
                return false;

            return true;
        }

        static constexpr size_t getCipherSize(size_t plainSize)
        {
            return plainSize;
        }

    private:
        AesGcm(std::unique_ptr<Random>&& random, Key&& key)
            : random_(std::move(random))
            , key_(std::move(key))
        {
        }

    private:
        std::unique_ptr<Random> random_;
        Key key_;
    };

    using Aes256Gcm = AesGcm<256>;
}
