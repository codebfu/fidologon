#pragma once

#include <map>
#include <mutex>
#include <set>

#include "fidologon/authenticator.h"

namespace fidologon {

// In-memory authenticator used by automated tests. Each fake device derives
// hmac-secret outputs from its own seed, like a real authenticator derives them
// from its per-credential random, and distinguishes outputs with and without PIN.
class FakeAuthenticator final : public Authenticator {
public:
    // How the device handles credProtect: a CTAP 2.1 key (default), a CTAP 2.0 key that
    // does not know it, or a broken key that advertises it but does not enforce it.
    enum class CredProtectMode { Enforced, Unsupported, AdvertisedOnly };

    // Empty pin = no PIN set. Replugging a known device keeps its state.
    void PlugDevice(const std::wstring& path, const std::wstring& pin,
                    CredProtectMode credProtect = CredProtectMode::Enforced, std::uint16_t vendorId = kVendorId,
                    std::uint16_t productId = kProductId);
    void UnplugDevice(const std::wstring& path);
    // Number of PIN verifications attempted on a device (right or wrong).
    int PinAttempts(const std::wstring& path);
    // Number of exchanges with a device (any operation other than the HID enumeration).
    int Exchanges(const std::wstring& path);
    // The next `count` exchanges with the device fail with DeviceError (a key still starting).
    void FailNextExchanges(const std::wstring& path, int count);

    static constexpr std::uint16_t kVendorId = 0x1050;
    static constexpr std::uint16_t kProductId = 0x0407;

    std::vector<DeviceInfo> ListDevices() override;
    DeviceCaps GetCaps(const std::wstring& path) override;
    CredentialResult MakeCredential(const std::wstring& path, const std::wstring& rpId, const Bytes& userId,
                                    const std::wstring& userName, const std::wstring* pin, bool requireUv) override;
    // Attestation returned by MakeCredential (default: AAGUID 11..11, no certificate).
    void SetAttestation(const std::wstring& path, const Bytes& aaguid, const std::vector<Bytes>& certificates,
                        bool signatureValid);
    bool HasCredential(const std::wstring& path, const std::wstring& rpId, const Bytes& credentialId,
                       const std::wstring* pin) override;
    Bytes GetHmacSecret(const std::wstring& path, const std::wstring& rpId, const Bytes& credentialId,
                        const Bytes& salt, const std::wstring* pin) override;

private:
    struct Device {
        std::wstring pin;
        Bytes seed;
        CredProtectMode credProtect = CredProtectMode::Enforced;
        std::map<Bytes, bool> credentials;  // id -> requires user verification
        int pinAttempts = 0;
        int exchanges = 0;
        Bytes aaguid = Bytes(16, 0x11);
        std::vector<Bytes> certificates;
        bool signatureValid = false;
        std::uint16_t vendorId = kVendorId;
        std::uint16_t productId = kProductId;
        bool plugged = true;
        int failingExchanges = 0;
    };

    Device& Require(const std::wstring& path);
    static void CheckPin(Device& device, const std::wstring* pin);
    // Whether the key lets this request see the credential (credProtect level 3 hides it without UV).
    static bool Visible(const Device& device, const Bytes& credentialId, const std::wstring* pin);

    std::mutex mutex_;
    std::map<std::wstring, Device> devices_;
};

}  // namespace fidologon
