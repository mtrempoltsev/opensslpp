#include <gtest/gtest.h>

#include <opensslpp/rsa.h>

TEST(rsa, common)
{
    auto newRsa = opensslpp::Rsa2048::createNewKeys();
    ASSERT_NE(newRsa, nullptr);

    const auto publicKey = newRsa->publicKey();
    const auto privateKey = newRsa->privateKey();

    auto publicRsa = opensslpp::Rsa2048::createWithPublicKey(publicKey);
    ASSERT_NE(publicRsa, nullptr);
    ASSERT_EQ(publicRsa->publicKey(), publicKey);

    auto privateRsa = opensslpp::Rsa2048::createWithPrivateKey(privateKey);
    ASSERT_NE(privateRsa, nullptr);
    ASSERT_EQ(privateRsa->privateKey(), privateKey);

    const std::string plainText = "1234567890abcdef-+=!qwerty0987654321ABCDEF";

    opensslpp::Rsa2048::EncryptedKey encryptedKey;
    opensslpp::Aes256::Iv iv;

    std::vector<uint8_t> cipher;

    ASSERT_TRUE(publicRsa->encrypt(plainText, encryptedKey, iv, cipher));

    std::vector<uint8_t> plainData;

    ASSERT_TRUE(privateRsa->decrypt(encryptedKey, iv, cipher, plainData));

    ASSERT_EQ(plainText, std::string(reinterpret_cast<char*>(plainData.data()), plainData.size()));

    std::vector<uint8_t> signature;
    ASSERT_TRUE(privateRsa->sign(plainText, signature));

    ASSERT_TRUE(publicRsa->isCorrectSignature(plainText, signature));
}

TEST(rsa, passPhrase)
{
    auto newRsa = opensslpp::Rsa2048::createNewKeys();
    ASSERT_NE(newRsa, nullptr);

    const std::string passPhrase = "testPhrase";

    const auto publicKey = newRsa->publicKey();
    const auto privateKey = newRsa->privateKey();
    const auto cryptedPrivateKey = newRsa->privateKeyPKCS8(passPhrase);

    ASSERT_NE(privateKey, cryptedPrivateKey);

    auto publicRsa = opensslpp::Rsa2048::createWithPublicKey(publicKey);
    ASSERT_NE(publicRsa, nullptr);
    ASSERT_EQ(publicRsa->publicKey(), publicKey);

    auto privateRsa = opensslpp::Rsa2048::createWithPrivateKey(cryptedPrivateKey, passPhrase);
    ASSERT_NE(privateRsa, nullptr);
    ASSERT_EQ(privateRsa->privateKey(), privateKey);

    auto invalid = opensslpp::Rsa2048::createWithPrivateKey(cryptedPrivateKey);
    ASSERT_EQ(invalid, nullptr);
    const std::string plainText = "1234567890abcdef-+=!qwerty0987654321ABCDEF";

    opensslpp::Rsa2048::EncryptedKey encryptedKey;
    opensslpp::Aes256::Iv iv;

    std::vector<uint8_t> cipher;

    ASSERT_TRUE(publicRsa->encrypt(plainText, encryptedKey, iv, cipher));

    std::vector<uint8_t> plainData;

    ASSERT_TRUE(privateRsa->decrypt(encryptedKey, iv, cipher, plainData));

    ASSERT_EQ(plainText, std::string(reinterpret_cast<char*>(plainData.data()), plainData.size()));

    std::vector<uint8_t> signature;
    ASSERT_TRUE(privateRsa->sign(plainText, signature));

    ASSERT_TRUE(publicRsa->isCorrectSignature(plainText, signature));
}
