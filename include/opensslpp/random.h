#pragma once

#include "details/common.h"

namespace opensslpp
{
    class Random final
    {
    public:
        static std::unique_ptr<Random> create()
        {
            if (RAND_status() != Success)
            {
                if (!seed())
                {
                    return nullptr;
                }
            }

            return std::unique_ptr<Random>(new Random());
        }

        ~Random()
        {
        }

        Random(const Random&) = delete;
        Random& operator=(const Random&) = delete;

        Random(Random&&) = delete;
        Random& operator=(Random&&) = delete;

        std::vector<uint8_t> getRandomBytes(size_t count) const
        {
            {
                std::vector<uint8_t> result(count);

                if (RAND_bytes(result.data(), static_cast<int>(count)) != Success)
                    result.clear();

                return result;
            }
        }

        bool getRandomBytes(uint8_t* result, size_t count) const
        {
            return RAND_bytes(result, static_cast<int>(count)) == Success;
        }

    private:
        Random()
        {
        }

        static bool seed()
        {
            //TODO implement this
            return false;
        }
    };
}
