#include <gtest/gtest.h>

#include <opensslpp/sha256.h>

TEST(sha256, common)
{
    auto d1 = opensslpp::Sha256::calculate("test1");
    auto d2 = opensslpp::Sha256::calculate("test2");
    auto d3 = opensslpp::Sha256::calculate("test1");

    ASSERT_EQ(d1, d3);
    ASSERT_NE(d1, d2);
}
