#pragma once

#include <memory>
#include <vector>

namespace opensslpp
{
    class Random final
    {
    public:
        static std::unique_ptr<Random> create();

        ~Random();

        Random(const Random&) = delete;
        Random& operator=(const Random&) = delete;

        Random(Random&&) = delete;
        Random& operator=(Random&&) = delete;

        std::vector<uint8_t> getRandomBytes(size_t count) const;
        bool getRandomBytes(uint8_t* result, size_t count) const;

    private:
        Random();

        static bool seed();
    };
}
