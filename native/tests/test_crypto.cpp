#include "fidologon/crypto.h"
#include "fidologon/errors.h"
#include "test_framework.h"

using namespace fidologon;

namespace {

Bytes FromHex(const char* hex) {
    Bytes result;
    for (const char* p = hex; p[0] != '\0' && p[1] != '\0'; p += 2) {
        auto nibble = [](char c) { return static_cast<std::uint8_t>(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10); };
        result.push_back(static_cast<std::uint8_t>((nibble(p[0]) << 4) | nibble(p[1])));
    }
    return result;
}

}  // namespace

TEST(HmacSha256MatchesRfc4231TestCase1) {
    const Bytes key(20, 0x0b);
    const char data[] = "Hi There";
    const Bytes digest = crypto::HmacSha256(key, reinterpret_cast<const std::uint8_t*>(data), sizeof(data) - 1);
    CHECK(digest == FromHex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
}

TEST(AesGcmMatchesNistVectorWithEmptyPlaintext) {
    // McGrew & Viega GCM spec, test case 13 (256-bit zero key, zero IV, empty plaintext).
    const Bytes key(32, 0);
    const Bytes nonce(12, 0);
    Bytes tag;
    const Bytes ciphertext = crypto::AesGcmEncrypt(key, nonce, nullptr, 0, {}, tag);
    CHECK(ciphertext.empty());
    CHECK(tag == FromHex("530f8afbc74536b9a963b4f1c4cb738b"));
}

TEST(AesGcmMatchesNistVectorWithOneBlock) {
    // Test case 14: 256-bit zero key, zero IV, one zero block.
    const Bytes key(32, 0);
    const Bytes nonce(12, 0);
    const Bytes plaintext(16, 0);
    Bytes tag;
    const Bytes ciphertext = crypto::AesGcmEncrypt(key, nonce, plaintext.data(), plaintext.size(), {}, tag);
    CHECK(ciphertext == FromHex("cea7403d4d606b6e074ec5d3baf39d18"));
    CHECK(tag == FromHex("d0d1c8a799996bf0265b98b5d48ab919"));

    Bytes decrypted;
    CHECK(crypto::AesGcmDecrypt(key, nonce, ciphertext, {}, tag, decrypted));
    CHECK(decrypted == plaintext);
}

TEST(SealAndOpenPasswordRoundTrip) {
    const Bytes secret = crypto::RandomBytes(32);
    const std::string aad = crypto::RecordAad(L"{id}", L"S-1-5-21-1");
    const std::wstring password = L"Pa$$w0rd with accents: éàü and emoji \U0001F511";
    const Bytes blob = crypto::SealPassword(secret, aad, password);
    CHECK_EQ(blob[0], crypto::kBlobVersion);
    CHECK_EQ(blob.size(), 1 + crypto::kNonceSize + password.size() * sizeof(wchar_t) + crypto::kTagSize);
    CHECK(crypto::OpenPassword(secret, aad, blob) == password);
}

TEST(SealUsesFreshNonceEachTime) {
    const Bytes secret = crypto::RandomBytes(32);
    const std::string aad = crypto::RecordAad(L"{id}", L"S-1-5-21-1");
    CHECK(crypto::SealPassword(secret, aad, L"same") != crypto::SealPassword(secret, aad, L"same"));
}

TEST(OpenPasswordRejectsWrongSecretAadOrTampering) {
    const Bytes secret = crypto::RandomBytes(32);
    const std::string aad = crypto::RecordAad(L"{id}", L"S-1-5-21-1");
    Bytes blob = crypto::SealPassword(secret, aad, L"secret");

    CHECK_THROWS_CODE(crypto::OpenPassword(crypto::RandomBytes(32), aad, blob), ErrorCode::DecryptFailed);
    CHECK_THROWS_CODE(crypto::OpenPassword(secret, crypto::RecordAad(L"{other}", L"S-1-5-21-1"), blob),
                      ErrorCode::DecryptFailed);

    Bytes tampered = blob;
    tampered[1 + crypto::kNonceSize] ^= 0x01;
    CHECK_THROWS_CODE(crypto::OpenPassword(secret, aad, tampered), ErrorCode::DecryptFailed);

    Bytes wrongVersion = blob;
    wrongVersion[0] = 2;
    CHECK_THROWS_CODE(crypto::OpenPassword(secret, aad, wrongVersion), ErrorCode::DecryptFailed);

    CHECK_THROWS_CODE(crypto::OpenPassword(secret, aad, Bytes(10, 0)), ErrorCode::DecryptFailed);
}
