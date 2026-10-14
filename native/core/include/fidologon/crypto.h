#pragma once

#include <string>

#include "fidologon/bytes.h"

namespace fidologon::crypto {

constexpr std::size_t kHmacSecretSize = 32;
constexpr std::size_t kSaltSize = 32;
constexpr std::size_t kNonceSize = 12;
constexpr std::size_t kTagSize = 16;
constexpr std::uint8_t kBlobVersion = 1;

Bytes RandomBytes(std::size_t size);

Bytes HmacSha256(const Bytes& key, const std::uint8_t* data, std::size_t size);

// AES-256-GCM with a 96-bit nonce and a 128-bit tag.
Bytes AesGcmEncrypt(const Bytes& key, const Bytes& nonce, const std::uint8_t* plaintext, std::size_t size,
                    const Bytes& aad, Bytes& tag);

// Returns false when authentication fails (wrong key, tampered data or AAD).
bool AesGcmDecrypt(const Bytes& key, const Bytes& nonce, const Bytes& ciphertext, const Bytes& aad,
                   const Bytes& tag, Bytes& plaintext);

// Additional authenticated data binding an encrypted password to its record and account.
std::string RecordAad(const std::wstring& recordId, const std::wstring& userSid);

// Encrypts a Windows password with a key derived from an hmac-secret output.
// Blob layout: version (1 byte) | nonce (12) | ciphertext | tag (16).
// The plaintext is the UTF-16LE password without terminator.
Bytes SealPassword(const Bytes& hmacSecret, const std::string& aad, const std::wstring& password);

// Reverses SealPassword. Throws Error(DecryptFailed) on any mismatch.
std::wstring OpenPassword(const Bytes& hmacSecret, const std::string& aad, const Bytes& blob);

}  // namespace fidologon::crypto
