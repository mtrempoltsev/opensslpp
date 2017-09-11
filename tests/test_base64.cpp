#include <gtest/gtest.h>

#include <opensslpp/base64.h>

TEST(base64, common)
{
    const std::vector<unsigned char> data = { 1, 2, 3, 4, 5 };

    const auto encoded = opensslpp::Base64::encode(data);
    const auto decoded = opensslpp::Base64::decode(encoded);

    ASSERT_EQ(data, decoded);
}
