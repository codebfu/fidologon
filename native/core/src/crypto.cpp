#include "fidologon/crypto.h"

#include <windows.h>
#include <bcrypt.h>

#include "fidologon/errors.h"

namespace fidologon::crypto {
namespace {

constexpr char kKeyDerivationLabel[] = "fidologon/v1/password-key";

void Check(NTSTATUS status, const char* what) {
    if (!BCRYPT_SUCCESS(status)) {
        throw Error(ErrorCode::Internal, std::string(what) + " failed");
    }
}

class AlgHandle {
public:
    AlgHandle(LPCWSTR algorithm, ULONG flags) {
        Check(BCryptOpenAlgorithmProvider(&handle_, algorithm, nullptr, flags), "BCryptOpenAlgorithmProvider");
    }
    ~AlgHandle() { BCryptCloseAlgorithmProvider(handle_, 0); }
    AlgHandle(const AlgHandle&) = delete;
    AlgHandle& operator=(const AlgHandle&) = delete;
    BCRYPT_ALG_HANDLE get() const { return handle_; }

private:
    BCRYPT_ALG_HANDLE handle_ = nullptr;
};

class KeyHandle {
public:
    KeyHandle(BCRYPT_ALG_HANDLE alg, const Bytes& secret) {
        Check(BCryptGenerateSymmetricKey(alg, &handle_, nullptr, 0, const_cast<PUCHAR>(secret.data()),
                                         static_cast<ULONG>(secret.size()), 0),
              "BCryptGenerateSymmetricKey");
    }
    ~KeyHandle() { BCryptDestroyKey(handle_); }
    KeyHandle(const KeyHandle&) = delete;
    KeyHandle& operator=(const KeyHandle&) = delete;
    BCRYPT_KEY_HANDLE get() const { return handle_; }

private:
    BCRYPT_KEY_HANDLE handle_ = nullptr;
};

class AesGcmAlg : public AlgHandle {
public:
    AesGcmAlg() : AlgHandle(BCRYPT_AES_ALGORITHM, 0) {
        Check(BCryptSetProperty(get(), BCRYPT_CHAINING_MODE,
                                reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                                sizeof(BCRYPT_CHAIN_MODE_GCM), 0),
              "BCryptSetProperty(GCM)");
    }
};

void RequireAesGcmParameters(const Bytes& key, const Bytes& nonce) {
    if (key.size() != 32 || nonce.size() != kNonceSize) {
        throw Error(ErrorCode::InvalidArgument, "AES-256-GCM requires a 32-byte key and a 12-byte nonce");
    }
}

Bytes DerivePasswordKey(const Bytes& hmacSecret) {
    if (hmacSecret.size() != kHmacSecretSize) {
        throw Error(ErrorCode::InvalidArgument, "hmac-secret output must be 32 bytes");
    }
    return HmacSha256(hmacSecret, reinterpret_cast<const std::uint8_t*>(kKeyDerivationLabel),
                      sizeof(kKeyDerivationLabel) - 1);
}

}  // namespace

Bytes RandomBytes(std::size_t size) {
    Bytes result(size);
    if (size != 0) {
        Check(BCryptGenRandom(nullptr, result.data(), static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG),
              "BCryptGenRandom");
    }
    return result;
}

Bytes HmacSha256(const Bytes& key, const std::uint8_t* data, std::size_t size) {
    AlgHandle alg(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    Bytes digest(32);
    Check(BCryptHash(alg.get(), const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()),
                     const_cast<PUCHAR>(data), static_cast<ULONG>(size), digest.data(),
                     static_cast<ULONG>(digest.size())),
          "BCryptHash");
    return digest;
}

Bytes AesGcmEncrypt(const Bytes& key, const Bytes& nonce, const std::uint8_t* plaintext, std::size_t size,
                    const Bytes& aad, Bytes& tag) {
    RequireAesGcmParameters(key, nonce);
    AesGcmAlg alg;
    KeyHandle keyHandle(alg.get(), key);

    tag.assign(kTagSize, 0);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce.data());
    info.cbNonce = static_cast<ULONG>(nonce.size());
    info.pbAuthData = aad.empty() ? nullptr : const_cast<PUCHAR>(aad.data());
    info.cbAuthData = static_cast<ULONG>(aad.size());
    info.pbTag = tag.data();
    info.cbTag = static_cast<ULONG>(tag.size());

    Bytes ciphertext(size);
    ULONG written = 0;
    Check(BCryptEncrypt(keyHandle.get(), const_cast<PUCHAR>(plaintext), static_cast<ULONG>(size), &info, nullptr, 0,
                        ciphertext.data(), static_cast<ULONG>(ciphertext.size()), &written, 0),
          "BCryptEncrypt");
    ciphertext.resize(written);
    return ciphertext;
}

bool AesGcmDecrypt(const Bytes& key, const Bytes& nonce, const Bytes& ciphertext, const Bytes& aad,
                   const Bytes& tag, Bytes& plaintext) {
    RequireAesGcmParameters(key, nonce);
    if (tag.size() != kTagSize) {
        return false;
    }
    AesGcmAlg alg;
    KeyHandle keyHandle(alg.get(), key);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce.data());
    info.cbNonce = static_cast<ULONG>(nonce.size());
    info.pbAuthData = aad.empty() ? nullptr : const_cast<PUCHAR>(aad.data());
    info.cbAuthData = static_cast<ULONG>(aad.size());
    info.pbTag = const_cast<PUCHAR>(tag.data());
    info.cbTag = static_cast<ULONG>(tag.size());

    plaintext.assign(ciphertext.size(), 0);
    ULONG written = 0;
    const NTSTATUS status =
        BCryptDecrypt(keyHandle.get(), const_cast<PUCHAR>(ciphertext.data()), static_cast<ULONG>(ciphertext.size()),
                      &info, nullptr, 0, plaintext.data(), static_cast<ULONG>(plaintext.size()), &written, 0);
    if (!BCRYPT_SUCCESS(status)) {
        Wipe(plaintext);
        return false;
    }
    plaintext.resize(written);
    return true;
}

std::string RecordAad(const std::wstring& recordId, const std::wstring& userSid) {
    return "fidologon/v1|" + ToUtf8(recordId) + "|" + ToUtf8(userSid);
}

Bytes SealPassword(const Bytes& hmacSecret, const std::string& aad, const std::wstring& password) {
    Bytes key = DerivePasswordKey(hmacSecret);
    WipeOnExit wipeKey(key);
    const Bytes nonce = RandomBytes(kNonceSize);
    const Bytes aadBytes(aad.begin(), aad.end());
    Bytes tag;
    const Bytes ciphertext =
        AesGcmEncrypt(key, nonce, reinterpret_cast<const std::uint8_t*>(password.data()),
                      password.size() * sizeof(wchar_t), aadBytes, tag);

    Bytes blob;
    blob.reserve(1 + nonce.size() + ciphertext.size() + tag.size());
    blob.push_back(kBlobVersion);
    blob.insert(blob.end(), nonce.begin(), nonce.end());
    blob.insert(blob.end(), ciphertext.begin(), ciphertext.end());
    blob.insert(blob.end(), tag.begin(), tag.end());
    return blob;
}

std::wstring OpenPassword(const Bytes& hmacSecret, const std::string& aad, const Bytes& blob) {
    if (blob.size() < 1 + kNonceSize + kTagSize || blob[0] != kBlobVersion) {
        throw Error(ErrorCode::DecryptFailed, "unsupported or truncated password blob");
    }
    const Bytes nonce(blob.begin() + 1, blob.begin() + 1 + kNonceSize);
    const Bytes ciphertext(blob.begin() + 1 + kNonceSize, blob.end() - kTagSize);
    const Bytes tag(blob.end() - kTagSize, blob.end());
    const Bytes aadBytes(aad.begin(), aad.end());

    Bytes key = DerivePasswordKey(hmacSecret);
    WipeOnExit wipeKey(key);
    Bytes plaintext;
    WipeOnExit wipePlaintext(plaintext);
    if (!AesGcmDecrypt(key, nonce, ciphertext, aadBytes, tag, plaintext) || plaintext.size() % sizeof(wchar_t) != 0) {
        throw Error(ErrorCode::DecryptFailed);
    }
    return std::wstring(reinterpret_cast<const wchar_t*>(plaintext.data()), plaintext.size() / sizeof(wchar_t));
}

}  // namespace fidologon::crypto
