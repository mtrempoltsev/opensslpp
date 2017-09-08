#pragma once

#include <memory>
#include <string>

struct rsa_st;

namespace opensslpp
{
    class Rsa final
    {
    public:
        static std::unique_ptr<Rsa> createNewKeys(size_t bits);

        static std::unique_ptr<Rsa> createWithPublicKey(const std::string& publicKey);
        static std::unique_ptr<Rsa> createWithPrivateKey(const std::string& privateKey);

        std::string publicKey() const;
        std::string privateKey() const;

        Rsa(const Rsa&) = delete;
        Rsa& operator=(const Rsa&) = delete;

        Rsa(Rsa&&) = delete;
        Rsa& operator=(Rsa&&) = delete;

        ~Rsa();

    private:
        Rsa();

    private:
        rsa_st* rsa_;
    };
}
