#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "fidologon/bytes.h"

namespace fidologon {

struct DeviceInfo {
    std::wstring path;
    std::wstring product;
    std::wstring manufacturer;
    // USB identifiers, read from the HID enumeration without talking to the device.
    std::uint16_t vendorId = 0;
    std::uint16_t productId = 0;
};

struct DeviceCaps {
    bool fido2 = false;
    bool hasPin = false;
    bool hmacSecret = false;
    // Advertises the CTAP 2.1 credProtect extension, needed to make the key itself require its PIN.
    bool credProtect = false;
};

// Result of a credential creation, with the attestation needed to check the key model.
struct CredentialResult {
    Bytes credentialId;
    Bytes aaguid;                        // 16 bytes, from the authenticator data
    std::string attestationFormat;       // "packed", "none", ...
    std::vector<Bytes> attestationCertificates;  // x5c, leaf first (empty for self or no attestation)
    bool attestationSignatureValid = false;      // signature checked against the leaf certificate
};

// Abstraction over the FIDO2 operations FidoLogon needs, so the logic above it
// can be tested without hardware. A null pin means "no user verification".
class Authenticator {
public:
    virtual ~Authenticator() = default;

    // USB HID FIDO devices currently plugged in.
    virtual std::vector<DeviceInfo> ListDevices() = 0;

    virtual DeviceCaps GetCaps(const std::wstring& path) = 0;

    // Creates a non-discoverable credential with the hmac-secret extension and returns its id.
    // With requireUv, the credential is created with credProtect "user verification required":
    // the key then refuses any assertion made without its PIN.
    virtual CredentialResult MakeCredential(const std::wstring& path, const std::wstring& rpId, const Bytes& userId,
                                            const std::wstring& userName, const std::wstring* pin,
                                            bool requireUv) = 0;

    // Check without touch that the credential lives on this device. Without a PIN, credentials
    // protected with requireUv are invisible; with a PIN, the key verifies it (a wrong PIN counts
    // as a failed attempt on that key).
    virtual bool HasCredential(const std::wstring& path, const std::wstring& rpId, const Bytes& credentialId,
                               const std::wstring* pin) = 0;

    // Performs an assertion (user presence required) and returns the 32-byte hmac-secret output.
    virtual Bytes GetHmacSecret(const std::wstring& path, const std::wstring& rpId, const Bytes& credentialId,
                                const Bytes& salt, const std::wstring* pin) = 0;
};

// Process-wide authenticator (libfido2 unless replaced for tests). The shared pointer keeps it
// alive for the caller even if a test replaces it meanwhile.
std::shared_ptr<Authenticator> GetAuthenticator();

#ifdef FIDOLOGON_TESTING
// Test builds only; null restores libfido2.
void ReplaceAuthenticatorForTests(std::shared_ptr<Authenticator> authenticator);
#endif

std::unique_ptr<Authenticator> CreateFido2Authenticator();

}  // namespace fidologon
