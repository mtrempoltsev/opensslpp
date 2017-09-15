#pragma once

#include <array>
#include <memory>
#include <string>
#include <vector>

namespace opensslpp
{
    class Random;

    class Aes256 final
    {
    public:
        static constexpr size_t KeySize = 256 / 8;
        using Key = std::array<uint8_t, KeySize>;

        static constexpr size_t IvSize = 128 / 8;
        using Iv = std::array<uint8_t, IvSize>;

        static std::unique_ptr<Aes256> createNewKey();
        static std::unique_ptr<Aes256> createWithKey(const std::string& base64Key);

        std::string base64Key() const;
        const Key& key() const;

        bool encrypt(const std::string& plainText, std::vector<uint8_t>& cipher, Iv& iv) const;
        bool encrypt(const uint8_t* plainData, size_t plainDataSize, std::vector<uint8_t>& cipher, Iv& iv) const;

        bool decrypt(const std::vector<uint8_t>& cipher, const Iv& iv, std::vector<uint8_t>& plainData) const;

        static size_t getCipherSize(size_t plainSize);

        ~Aes256();

        Aes256(const Aes256&) = delete;
        Aes256& operator=(const Aes256&) = delete;

        Aes256(Aes256&&) = delete;
        Aes256& operator=(Aes256&&) = delete;

    private:
        Aes256(std::unique_ptr<Random>&& random, Key&& key);

    private:
        std::unique_ptr<Random> random_;
        Key key_;
    };
}
