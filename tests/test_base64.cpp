#include <gtest/gtest.h>

#include <opensslpp/base64.h>

TEST(base64, common)
{
    const std::vector<uint8_t> data = { 1, 2, 3, 4, 5 };

    {
        const auto encoded = opensslpp::Base64::encode(data);
        const auto decoded = opensslpp::Base64::decode(encoded);

        ASSERT_EQ(data, decoded);
    }

    {
        std::vector<uint8_t> decoded(data.size());

        const auto encoded = opensslpp::Base64::encode(data.data(), data.size());
        const auto size = opensslpp::Base64::decode(encoded, decoded.data(), decoded.size());

        ASSERT_EQ(size, decoded.size());
        ASSERT_EQ(data, decoded);
    }
}
