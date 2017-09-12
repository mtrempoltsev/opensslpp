#include <gtest/gtest.h>

#include <opensslpp/sha256.h>

TEST(sha256, common)
{
    auto digest1 = opensslpp::Sha256::calculate("test1");
    auto digest2 = opensslpp::Sha256::calculate("test2");
    auto digest3 = opensslpp::Sha256::calculate("test1");

    ASSERT_EQ(digest1, digest3);
    ASSERT_NE(digest1, digest2);

    auto base1 = opensslpp::Sha256::toBase64(digest1);
    auto base2 = opensslpp::Sha256::toBase64(digest2);
    auto base3 = opensslpp::Sha256::toBase64(digest3);

    ASSERT_EQ(base1, base3);
    ASSERT_NE(base1, base2);

    auto d1 = opensslpp::Sha256::fromBase64(base1);
    auto d2 = opensslpp::Sha256::fromBase64(base2);
    auto d3 = opensslpp::Sha256::fromBase64(base3);

    ASSERT_EQ(d1, d3);
    ASSERT_NE(d1, d2);
}
