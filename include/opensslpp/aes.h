#pragma once

#include "base64.h"
#include "random.h"

namespace opensslpp
{
    class Random;

    template <size_t Bits, size_t IvBits, class Mode>
    class Aes final
    {
        using AesT = Aes<Bits, IvBits, Mode>;
    public:
        static constexpr size_t KeySize = Bits / 8;
        using Key = std::array<uint8_t, KeySize>;

        static constexpr size_t IvSize = IvBits / 8;
        using Iv = std::array<uint8_t, IvSize>;

        static std::unique_ptr<AesT> createNewKey()
        {
            auto random = Random::create();
            if (!random)
                return nullptr;

            Key key;
            if (!random->getRandomBytes(key.data(), key.size()))
                return nullptr;

            return std::unique_ptr<AesT>(new AesT(std::move(random), std::move(key)));
        }

        static std::unique_ptr<AesT> createWithKey(const std::string& base64Key)
        {
            auto random = Random::create();
            if (!random)
                return nullptr;

            Key key;

            if (Base64::decode(base64Key, key.data(), key.size()) != key.size())
                return nullptr;

            return std::unique_ptr<AesT>(new AesT(std::move(random), std::move(key)));
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

            if (EVP_EncryptInit_ex(context.get(), Mode::function(), nullptr, key_.data(), iv.data()) != Success)
                return false;

            const size_t cipherSize = getCipherSize(plainDataSize);
            cipher.resize(cipherSize);

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

            if (EVP_DecryptInit_ex(context.get(), Mode::function(), nullptr, key_.data(), iv.data()) != Success)
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

        static size_t getCipherSize(size_t plainSize)
        {
            return (plainSize / IvSize + 1) * IvSize;
        }

        ~Aes()
        {
        }

        Aes(const Aes&) = delete;
        Aes& operator=(const Aes&) = delete;

        Aes(Aes&&) = delete;
        Aes& operator=(Aes&&) = delete;

    private:
        Aes(std::unique_ptr<Random>&& random, Key&& key)
            : random_(std::move(random))
            , key_(std::move(key))
        {
        }

    private:
        std::unique_ptr<Random> random_;
        Key key_;
    };

    using Aes256 = Aes<256, 128, AesCbc256Mode>;
}
