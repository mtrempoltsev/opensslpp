#pragma once

#include <memory>
#include <string>
#include <vector>

namespace opensslpp
{
    class Aes final
    {
    public:
        static std::unique_ptr<Aes> createNewKey(size_t bits);

        static std::unique_ptr<Aes> createWithKey(const std::string& key);

        std::string base64Key() const;
        const std::vector<unsigned char>& key() const;



        Aes(const Aes&) = delete;
        Aes& operator=(const Aes&) = delete;

        Aes(Aes&&) = delete;
        Aes& operator=(Aes&&) = delete;

    private:
        explicit Aes(const std::string& key);
        explicit Aes(std::vector<unsigned char>&& key);

    private:
        std::vector<unsigned char> key_;
    };
}
