#include "fidologon/fake_authenticator.h"

#include "fidologon/crypto.h"
#include "fidologon/errors.h"

namespace fidologon {

void FakeAuthenticator::PlugDevice(const std::wstring& path, const std::wstring& pin, CredProtectMode credProtect,
                                   std::uint16_t vendorId, std::uint16_t productId) {
    std::lock_guard lock(mutex_);
    auto it = devices_.find(path);
    if (it != devices_.end()) {
        it->second.plugged = true;
        return;
    }
    Device device;
    device.pin = pin;
    device.seed = crypto::RandomBytes(32);
    device.credProtect = credProtect;
    device.vendorId = vendorId;
    device.productId = productId;
    devices_.emplace(path, std::move(device));
}

int FakeAuthenticator::Exchanges(const std::wstring& path) {
    std::lock_guard lock(mutex_);
    auto it = devices_.find(path);
    return it != devices_.end() ? it->second.exchanges : 0;
}

void FakeAuthenticator::FailNextExchanges(const std::wstring& path, int count) {
    std::lock_guard lock(mutex_);
    devices_.at(path).failingExchanges = count;
}

int FakeAuthenticator::PinAttempts(const std::wstring& path) {
    std::lock_guard lock(mutex_);
    auto it = devices_.find(path);
    return it != devices_.end() ? it->second.pinAttempts : 0;
}

void FakeAuthenticator::UnplugDevice(const std::wstring& path) {
    std::lock_guard lock(mutex_);
    auto it = devices_.find(path);
    if (it != devices_.end()) {
        it->second.plugged = false;
    }
}

FakeAuthenticator::Device& FakeAuthenticator::Require(const std::wstring& path) {
    auto it = devices_.find(path);
    if (it == devices_.end() || !it->second.plugged) {
        throw Error(ErrorCode::DeviceError, "fake device not plugged");
    }
    ++it->second.exchanges;
    if (it->second.failingExchanges > 0) {
        --it->second.failingExchanges;
        throw Error(ErrorCode::DeviceError, "fake device not ready");
    }
    return it->second;
}

void FakeAuthenticator::CheckPin(Device& device, const std::wstring* pin) {
    if (pin == nullptr) {
        return;
    }
    if (device.pin.empty()) {
        throw Error(ErrorCode::PinNotSet);
    }
    ++device.pinAttempts;
    if (*pin != device.pin) {
        throw Error(ErrorCode::PinInvalid);
    }
}

bool FakeAuthenticator::Visible(const Device& device, const Bytes& credentialId, const std::wstring* pin) {
    const auto it = device.credentials.find(credentialId);
    return it != device.credentials.end() && (!it->second || pin != nullptr);
}

std::vector<DeviceInfo> FakeAuthenticator::ListDevices() {
    std::lock_guard lock(mutex_);
    std::vector<DeviceInfo> result;
    for (const auto& [path, device] : devices_) {
        if (device.plugged) {
            result.push_back(DeviceInfo{path, L"Fake FIDO2 key", L"FidoLogon tests", device.vendorId, device.productId});
        }
    }
    return result;
}

DeviceCaps FakeAuthenticator::GetCaps(const std::wstring& path) {
    std::lock_guard lock(mutex_);
    Device& device = Require(path);
    return DeviceCaps{true, !device.pin.empty(), true, device.credProtect != CredProtectMode::Unsupported};
}

void FakeAuthenticator::SetAttestation(const std::wstring& path, const Bytes& aaguid,
                                       const std::vector<Bytes>& certificates, bool signatureValid) {
    std::lock_guard lock(mutex_);
    Device& device = devices_.at(path);
    device.aaguid = aaguid;
    device.certificates = certificates;
    device.signatureValid = signatureValid;
}

CredentialResult FakeAuthenticator::MakeCredential(const std::wstring& path, const std::wstring&, const Bytes&,
                                                   const std::wstring&, const std::wstring* pin, bool requireUv) {
    std::lock_guard lock(mutex_);
    Device& device = Require(path);
    if (!device.pin.empty() && pin == nullptr) {
        throw Error(ErrorCode::PinRequired);
    }
    CheckPin(device, pin);
    Bytes id = crypto::RandomBytes(48);
    // Keys without credProtect ignore the extension, like real CTAP 2.0 keys.
    device.credentials[id] = requireUv && device.credProtect == CredProtectMode::Enforced;
    CredentialResult result;
    result.credentialId = std::move(id);
    result.aaguid = device.aaguid;
    result.attestationFormat = device.certificates.empty() ? "none" : "packed";
    result.attestationCertificates = device.certificates;
    result.attestationSignatureValid = device.signatureValid;
    return result;
}

bool FakeAuthenticator::HasCredential(const std::wstring& path, const std::wstring&, const Bytes& credentialId,
                                      const std::wstring* pin) {
    std::lock_guard lock(mutex_);
    Device& device = Require(path);
    CheckPin(device, pin);
    return Visible(device, credentialId, pin);
}

Bytes FakeAuthenticator::GetHmacSecret(const std::wstring& path, const std::wstring&, const Bytes& credentialId,
                                       const Bytes& salt, const std::wstring* pin) {
    std::lock_guard lock(mutex_);
    Device& device = Require(path);
    CheckPin(device, pin);
    if (!Visible(device, credentialId, pin)) {
        throw Error(ErrorCode::CredentialNotOnDevice);
    }
    // Like CTAP 2.1, outputs differ depending on whether user verification happened.
    Bytes message = credentialId;
    message.insert(message.end(), salt.begin(), salt.end());
    message.push_back(pin != nullptr ? 1 : 0);
    return crypto::HmacSha256(device.seed, message.data(), message.size());
}

}  // namespace fidologon
