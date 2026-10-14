#include "fidologon/enrollment.h"

#include <ctime>

#include "fidologon/attestation.h"
#include "fidologon/crypto.h"
#include "fidologon/errors.h"

namespace fidologon {

std::wstring Enroll(const EnrollRequest& request, RecordStore& store) {
    if (request.devicePath.empty() || request.userSid.empty() || request.userName.empty()) {
        throw Error(ErrorCode::InvalidArgument, "device, user SID and user name are required");
    }
    if (request.password.empty()) {
        throw Error(ErrorCode::InvalidArgument, "accounts without a password cannot be enrolled");
    }

    const std::shared_ptr<Authenticator> authenticatorPtr = GetAuthenticator();
    Authenticator& authenticator = *authenticatorPtr;
    const DeviceCaps caps = authenticator.GetCaps(request.devicePath);
    if (!caps.fido2) {
        throw Error(ErrorCode::DeviceError, "the security key does not support FIDO2");
    }
    if (!caps.hmacSecret) {
        throw Error(ErrorCode::HmacSecretUnsupported);
    }
    if (request.requirePin && !caps.hasPin) {
        throw Error(ErrorCode::PinNotSet);
    }
    // Without credProtect, the PIN would only be a convention of this software: anyone holding
    // the key and a copy of the record could get the hmac-secret output without it.
    if (request.requirePin && !caps.credProtect) {
        throw Error(ErrorCode::CredProtectUnsupported);
    }
    if (caps.hasPin && request.pin.empty()) {
        throw Error(ErrorCode::PinRequired);
    }

    KeyRecord record;
    record.id = NewRecordId();
    bool listed = false;
    for (const DeviceInfo& device : authenticator.ListDevices()) {
        if (device.path == request.devicePath) {
            record.vendorId = device.vendorId;
            record.productId = device.productId;
            listed = true;
        }
    }
    if (!listed) {
        throw Error(ErrorCode::NoDevice, "the security key is no longer listed");  // sign-in could never find it
    }
    record.userSid = request.userSid;
    record.userName = request.userName;
    record.label = request.label;
    record.requirePin = request.requirePin;
    record.createdUnix = static_cast<std::int64_t>(std::time(nullptr));

    // Creating a credential needs the PIN whenever one is set on the key; the
    // hmac-secret output, however, depends on whether the PIN is used, so it must be
    // obtained exactly the way logon will request it.
    // Key model policy (F-11): only checked when the administrator allowed specific models or
    // every model certified by the FIDO Alliance. Checked before the first touch too, when no
    // model can pass yet.
    bool policyEnforced = false;
    const std::vector<AllowedModel> allowedModels = store.EnrollmentModels(policyEnforced);
    if (policyEnforced && allowedModels.empty()) {
        throw Error(ErrorCode::AttestationRejected,
                    "only certified key models can be enrolled, and no FIDO Metadata Service data was downloaded "
                    "yet: synchronize it ('fidologon models sync'), or turn certified models off");
    }

    const Bytes userId = crypto::RandomBytes(16);
    const std::wstring* makeCredPin = caps.hasPin ? &request.pin : nullptr;
    if (request.onTouch) {
        request.onTouch(1, 2);
    }
    const CredentialResult credential = authenticator.MakeCredential(request.devicePath, record.rpId, userId,
                                                                     request.userName, makeCredPin, request.requirePin);
    record.credentialId = credential.credentialId;
    record.aaguid = FormatAaguid(credential.aaguid);
    if (policyEnforced) {
        CheckAttestation(credential, allowedModels);
    }
    // A key that advertises credProtect but still answers without PIN would make PIN mode a lie.
    if (request.requirePin &&
        authenticator.HasCredential(request.devicePath, record.rpId, record.credentialId, nullptr)) {
        throw Error(ErrorCode::CredProtectUnsupported, "the key does not enforce credProtect");
    }

    record.hmacSalt = crypto::RandomBytes(crypto::kSaltSize);
    if (request.onTouch) {
        request.onTouch(2, 2);
    }
    Bytes secret = authenticator.GetHmacSecret(request.devicePath, record.rpId, record.credentialId, record.hmacSalt,
                                               request.requirePin ? &request.pin : nullptr);
    WipeOnExit wipeSecret(secret);

    record.encryptedPassword =
        crypto::SealPassword(secret, crypto::RecordAad(record.id, record.userSid), request.password);
    store.Save(record);
    return record.id;
}

namespace {

bool SameModel(const DeviceInfo& device, const KeyRecord& record) {
    return device.vendorId == record.vendorId && device.productId == record.productId;
}

}  // namespace

std::optional<KeyMatch> FindEnrolledKey(const std::vector<KeyRecord>& candidates, const std::wstring* pin) {
    if (candidates.empty()) {
        return std::nullopt;
    }
    const std::shared_ptr<Authenticator> authenticatorPtr = GetAuthenticator();
    Authenticator& authenticator = *authenticatorPtr;

    // Only talk to devices whose USB identifiers match an enrolled key: any other FIDO device
    // (possibly hostile) plugged at the sign-in screen is never opened. The HID enumeration
    // itself does not exchange any data with the devices.
    std::vector<DeviceInfo> devices;
    for (DeviceInfo& device : authenticator.ListDevices()) {
        for (const KeyRecord& record : candidates) {
            if (SameModel(device, record)) {
                devices.push_back(std::move(device));
                break;
            }
        }
    }
    if (devices.empty()) {
        return std::nullopt;
    }

    const bool pinMissing = pin == nullptr || pin->empty();
    std::vector<const KeyRecord*> protectedRecords;
    for (const KeyRecord& record : candidates) {
        if (record.requirePin) {
            protectedRecords.push_back(&record);
        }
    }
    if (pinMissing && protectedRecords.size() == candidates.size()) {
        throw Error(ErrorCode::PinRequired);  // before any exchange with the devices
    }

    // 1. Silent probe: finds touch-only credentials without any PIN attempt.
    for (const DeviceInfo& device : devices) {
        for (const KeyRecord& record : candidates) {
            if (!SameModel(device, record)) {
                continue;
            }
            try {
                if (authenticator.HasCredential(device.path, record.rpId, record.credentialId, nullptr)) {
                    return KeyMatch{device, record};
                }
            } catch (const Error&) {
                break;  // device unusable (e.g. unplugged meanwhile): try the next one
            }
        }
    }

    // 2. PIN-protected credentials only answer with the PIN. Never send it to a key that may be
    // someone else's: it would count as a failed attempt there, so require a single candidate key.
    if (protectedRecords.empty()) {
        return std::nullopt;
    }
    std::vector<const DeviceInfo*> pinDevices;
    for (const DeviceInfo& device : devices) {
        bool modelMatches = false;
        for (const KeyRecord* record : protectedRecords) {
            modelMatches = modelMatches || SameModel(device, *record);
        }
        if (!modelMatches) {
            continue;
        }
        try {
            const DeviceCaps caps = authenticator.GetCaps(device.path);
            if (caps.fido2 && caps.hasPin) {
                pinDevices.push_back(&device);
            }
        } catch (const Error&) {
            // unusable device: ignore it
        }
    }
    if (pinDevices.empty()) {
        return std::nullopt;
    }
    if (pinMissing) {
        throw Error(ErrorCode::PinRequired);
    }
    if (pinDevices.size() > 1) {
        throw Error(ErrorCode::MultipleDevices);
    }
    const DeviceInfo& device = *pinDevices.front();
    for (const KeyRecord* record : protectedRecords) {
        if (SameModel(device, *record) &&
            authenticator.HasCredential(device.path, record->rpId, record->credentialId, pin)) {
            return KeyMatch{device, *record};
        }
    }
    return std::nullopt;
}

std::vector<std::wstring> ListMatchingDevicePaths(const std::vector<KeyRecord>& candidates) {
    std::vector<std::wstring> paths;
    for (const DeviceInfo& device : GetAuthenticator()->ListDevices()) {
        for (const KeyRecord& record : candidates) {
            if (SameModel(device, record)) {
                paths.push_back(device.path);
                break;
            }
        }
    }
    return paths;
}

PresenceResult DetectEnrolledKey(const std::vector<KeyRecord>& candidates) {
    const std::shared_ptr<Authenticator> authenticatorPtr = GetAuthenticator();
    Authenticator& authenticator = *authenticatorPtr;
    std::vector<DeviceInfo> devices;
    for (DeviceInfo& device : authenticator.ListDevices()) {
        for (const KeyRecord& record : candidates) {
            if (SameModel(device, record)) {
                devices.push_back(std::move(device));
                break;
            }
        }
    }
    PresenceResult result;
    if (devices.empty()) {
        return result;
    }
    if (devices.size() > 1) {
        result.presence = KeyPresence::Multiple;
        return result;
    }
    const DeviceInfo& device = devices.front();
    bool pinModel = false;
    for (const KeyRecord& record : candidates) {
        if (!SameModel(device, record)) {
            continue;
        }
        if (record.requirePin) {
            pinModel = true;
            continue;
        }
        if (authenticator.HasCredential(device.path, record.rpId, record.credentialId, nullptr)) {
            result.presence = KeyPresence::TouchOnly;
            result.match = KeyMatch{device, record};
            return result;
        }
    }
    result.presence = pinModel ? KeyPresence::PinNeeded : KeyPresence::NotEnrolled;
    return result;
}

std::wstring UnlockPassword(const KeyMatch& match, const std::wstring& pin) {
    if (match.record.requirePin && pin.empty()) {
        throw Error(ErrorCode::PinRequired);
    }
    Bytes secret = GetAuthenticator()->GetHmacSecret(match.device.path, match.record.rpId, match.record.credentialId,
                                                    match.record.hmacSalt, match.record.requirePin ? &pin : nullptr);
    WipeOnExit wipeSecret(secret);
    return crypto::OpenPassword(secret, crypto::RecordAad(match.record.id, match.record.userSid),
                                match.record.encryptedPassword);
}

bool EveryEnabledUserEnrolled(const std::vector<LocalUser>& users, const std::vector<KeyRecord>& records) {
    bool anyEnabled = false;
    for (const LocalUser& user : users) {
        if (user.disabled) {
            continue;
        }
        anyEnabled = true;
        bool enrolled = false;
        for (const KeyRecord& record : records) {
            if (_wcsicmp(record.userSid.c_str(), user.sid.c_str()) == 0) {
                enrolled = true;
                break;
            }
        }
        if (!enrolled) {
            return false;
        }
    }
    return anyEnabled;
}

}  // namespace fidologon
