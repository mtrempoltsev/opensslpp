    #include <gtest/gtest.h>

    #include <opensslpp/dsa.h>

    TEST(dsa, common)
    {
        auto newDsa = opensslpp::Dsa::createNewKeys(1024);
        ASSERT_NE(newDsa, nullptr);

        const auto publicKey = newDsa->publicKey();
        const auto privateKey = newDsa->privateKey();

        auto publicDsa = opensslpp::Dsa::createWithPublicKey(publicKey);
        ASSERT_NE(publicDsa, nullptr);
        ASSERT_EQ(publicDsa->publicKey(), publicKey);

        auto privateDsa = opensslpp::Dsa::createWithPrivateKey(privateKey);
        ASSERT_NE(privateDsa, nullptr);
        ASSERT_EQ(privateDsa->privateKey(), privateKey);
    }
