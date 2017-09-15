#include <gtest/gtest.h>

#include <opensslpp/aes256.h>

TEST(aes256, common)
{
    auto newAes = opensslpp::Aes256::createNewKey();
    ASSERT_NE(newAes, nullptr);

    const auto base64Key = newAes->base64Key();
    auto aes = opensslpp::Aes256::createWithKey(base64Key);
    ASSERT_NE(aes, nullptr);
    ASSERT_EQ(aes->base64Key(), base64Key);

    const std::string plainText = "1234567890abcdef-+=!qwerty0987654321ABCDEF";

    std::vector<uint8_t> cipher;
    opensslpp::Aes256::Iv iv;

    ASSERT_TRUE(aes->encrypt(plainText, cipher, iv));

    std::vector<uint8_t> plainData;

    ASSERT_TRUE(aes->decrypt(cipher, iv, plainData));

    ASSERT_EQ(plainText, std::string(reinterpret_cast<char*>(plainData.data()), plainData.size()));
}
