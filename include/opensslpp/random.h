#pragma once

#include <memory>
#include <vector>

namespace opensslpp
{
    class Random final
    {
    public:
        static std::unique_ptr<Random> create();

        Random(const Random&) = delete;
        Random& operator=(const Random&) = delete;

        Random(Random&&) = delete;
        Random& operator=(Random&&) = delete;

        std::vector<unsigned char> getRandomBytes(size_t count) const;

    private:
        Random();

        static bool seed();
    };
}
