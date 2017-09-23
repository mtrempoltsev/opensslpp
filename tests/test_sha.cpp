#include <gtest/gtest.h>

#include <opensslpp/sha.h>

TEST(sha256, common)
{
    opensslpp::Sha256::Digest digest1;
    ASSERT_TRUE(opensslpp::Sha256::calculate("test1", digest1));

    opensslpp::Sha256::Digest digest2;
    ASSERT_TRUE(opensslpp::Sha256::calculate("test2", digest2));

    opensslpp::Sha256::Digest digest3;
    ASSERT_TRUE(opensslpp::Sha256::calculate("test1", digest3));

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
