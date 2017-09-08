#include <gtest/gtest.h>

#include <opensslpp/rsa.h>

TEST(rsa, common)
{
    auto newRsa = opensslpp::Rsa::createNewKeys(1024);
    ASSERT_NE(newRsa, nullptr);

    const auto publicKey = newRsa->publicKey();
    const auto privateKey = newRsa->privateKey();

    auto publicRsa = opensslpp::Rsa::createWithPublicKey(publicKey);
    ASSERT_NE(publicRsa, nullptr);
    ASSERT_EQ(publicRsa->publicKey(), publicKey);

    auto privateRsa = opensslpp::Rsa::createWithPrivateKey(privateKey);
    ASSERT_NE(privateRsa, nullptr);
    ASSERT_EQ(privateRsa->privateKey(), privateKey);
}
