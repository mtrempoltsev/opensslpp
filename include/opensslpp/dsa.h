#pragma once

#include <memory>
#include <string>

struct dsa_st;

namespace opensslpp
{
    class Dsa final
    {
    public:
        static std::unique_ptr<Dsa> createNewKeys(int bits);
        static std::unique_ptr<Dsa> createWithPublicKey(const std::string& publicKey);
        static std::unique_ptr<Dsa> createWithPrivateKey(const std::string& privateKey);

        std::string publicKey() const;
        std::string privateKey() const;

        Dsa(const Dsa&) = delete;
        Dsa& operator=(const Dsa&) = delete;

        Dsa(Dsa&&) = default;
        Dsa& operator=(Dsa&&) = default;

        ~Dsa();

    private:
        Dsa();

    private:
        dsa_st* dsa_;
    };
}
