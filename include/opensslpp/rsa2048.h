#pragma once

#include <memory>
#include <string>

#include "aes256.h"

struct rsa_st;

namespace opensslpp
{
    class Rsa2048 final
    {
    public:
        static constexpr size_t Bits = 2048;
        static constexpr size_t KeySize = Bits / 8;
        using EncryptedKey = std::array<uint8_t, KeySize>;

        static std::unique_ptr<Rsa2048> createNewKeys();

        static std::unique_ptr<Rsa2048> createWithPublicKey(const std::string& publicKey);
        static std::unique_ptr<Rsa2048> createWithPrivateKey(const std::string& privateKey);

        std::string publicKey() const;
        std::string privateKey() const;

        bool encrypt(const std::string& plainText, EncryptedKey& key, Aes256::Iv& iv, std::vector<uint8_t>& cipher) const;
        bool encrypt(const uint8_t* plainData, size_t plainDataSize, EncryptedKey& key, Aes256::Iv& iv, std::vector<uint8_t>& cipher) const;

        bool decrypt(const EncryptedKey& key, const Aes256::Iv& iv, const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plainData) const;

        bool sign(const std::string& plainText, std::vector<uint8_t>& signature);
        bool isCorrectSignature(const std::vector<uint8_t>& signature);

        Rsa2048(const Rsa2048&) = delete;
        Rsa2048& operator=(const Rsa2048&) = delete;

        Rsa2048(Rsa2048&&) = delete;
        Rsa2048& operator=(Rsa2048&&) = delete;

        ~Rsa2048();

    private:
        Rsa2048();

    private:
        rsa_st* rsa_;
    };
}
