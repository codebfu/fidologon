// libfido2-backed implementation of the Authenticator interface.
//
// On Windows, direct access to FIDO HID devices requires administrator rights
// (or SYSTEM, which is what LogonUI and the service run as).

#include <fido.h>

#include <cstring>
#include <memory>
#include <mutex>

#include "fidologon/authenticator.h"
#include "fidologon/crypto.h"
#include "fidologon/errors.h"

namespace fidologon {
namespace {

constexpr std::size_t kMaxDevices = 64;
constexpr int kTouchTimeoutMs = 30000;
// Operations that never wait for a touch (getInfo, silent probes): a key answers at once, so a
// short timeout keeps a misbehaving device from stalling the sign-in screen.
constexpr int kProbeTimeoutMs = 3000;
constexpr char kHmacSecretExtension[] = "hmac-secret";
constexpr char kCredProtectExtension[] = "credProtect";

ErrorCode MapFidoError(int code) {
    switch (code) {
        case FIDO_ERR_PIN_INVALID:
            return ErrorCode::PinInvalid;
        case FIDO_ERR_PIN_BLOCKED:
        case FIDO_ERR_PIN_AUTH_BLOCKED:
            return ErrorCode::PinBlocked;
        case FIDO_ERR_PIN_REQUIRED:
        case FIDO_ERR_UV_BLOCKED:
        case FIDO_ERR_UV_INVALID:
            return ErrorCode::PinRequired;
        case FIDO_ERR_PIN_NOT_SET:
            return ErrorCode::PinNotSet;
        case FIDO_ERR_NO_CREDENTIALS:
            return ErrorCode::CredentialNotOnDevice;
        case FIDO_ERR_ACTION_TIMEOUT:
        case FIDO_ERR_USER_ACTION_TIMEOUT:
            return ErrorCode::Timeout;
        case FIDO_ERR_UNSUPPORTED_EXTENSION:
        case FIDO_ERR_UNSUPPORTED_OPTION:
            return ErrorCode::HmacSecretUnsupported;
        case FIDO_ERR_OPERATION_DENIED:
            return ErrorCode::OperationDenied;
        default:
            return ErrorCode::DeviceError;
    }
}

[[noreturn]] void ThrowFido(int code, const char* what) {
    throw Error(MapFidoError(code), std::string(what) + ": " + fido_strerr(code));
}

void EnsureInitialized() {
    static std::once_flag once;
    std::call_once(once, [] { fido_init(0); });
}

std::wstring Widen(const char* value) {
    if (value == nullptr) {
        return {};
    }
    try {
        return FromUtf8(value);
    } catch (const Error&) {
        return {};
    }
}

// Only USB HID devices are supported: their paths are what the service watches.
bool IsHidPath(const char* path) { return path != nullptr && std::strncmp(path, "\\\\?\\", 4) == 0; }

struct DevDeleter {
    void operator()(fido_dev_t* dev) const {
        fido_dev_close(dev);
        fido_dev_free(&dev);
    }
};
using DevPtr = std::unique_ptr<fido_dev_t, DevDeleter>;

struct AssertDeleter {
    void operator()(fido_assert_t* value) const { fido_assert_free(&value); }
};
using AssertPtr = std::unique_ptr<fido_assert_t, AssertDeleter>;

struct CredDeleter {
    void operator()(fido_cred_t* value) const { fido_cred_free(&value); }
};
using CredPtr = std::unique_ptr<fido_cred_t, CredDeleter>;

struct CborInfoDeleter {
    void operator()(fido_cbor_info_t* value) const { fido_cbor_info_free(&value); }
};
using CborInfoPtr = std::unique_ptr<fido_cbor_info_t, CborInfoDeleter>;

DevPtr OpenDevice(const std::wstring& path, int timeoutMs) {
    EnsureInitialized();
    const std::string narrowPath = ToUtf8(path);
    fido_dev_t* raw = fido_dev_new();
    if (raw == nullptr) {
        throw Error(ErrorCode::Internal, "fido_dev_new failed");
    }
    const int status = fido_dev_open(raw, narrowPath.c_str());
    if (status != FIDO_OK) {
        fido_dev_free(&raw);
        ThrowFido(status, "fido_dev_open");
    }
    DevPtr dev(raw);
    fido_dev_set_timeout(dev.get(), timeoutMs);
    return dev;
}

void SetCommonAssertParameters(fido_assert_t* assertion, const std::wstring& rpId, const Bytes& credentialId) {
    const std::string rp = ToUtf8(rpId);
    const Bytes clientDataHash = crypto::RandomBytes(32);
    int status = fido_assert_set_rp(assertion, rp.c_str());
    if (status == FIDO_OK) {
        status = fido_assert_set_clientdata_hash(assertion, clientDataHash.data(), clientDataHash.size());
    }
    if (status == FIDO_OK) {
        status = fido_assert_allow_cred(assertion, credentialId.data(), credentialId.size());
    }
    if (status != FIDO_OK) {
        ThrowFido(status, "fido_assert_set");
    }
}

class Fido2Authenticator final : public Authenticator {
public:
    std::vector<DeviceInfo> ListDevices() override {
        EnsureInitialized();
        std::vector<DeviceInfo> devices;
        fido_dev_info_t* list = fido_dev_info_new(kMaxDevices);
        if (list == nullptr) {
            throw Error(ErrorCode::Internal, "fido_dev_info_new failed");
        }
        std::size_t count = 0;
        const int status = fido_dev_info_manifest(list, kMaxDevices, &count);
        if (status == FIDO_OK) {
            for (std::size_t i = 0; i < count; ++i) {
                const fido_dev_info_t* info = fido_dev_info_ptr(list, i);
                const char* path = fido_dev_info_path(info);
                if (!IsHidPath(path)) {
                    continue;  // skip windows://hello and pcsc:// pseudo-devices
                }
                devices.push_back(DeviceInfo{Widen(path), Widen(fido_dev_info_product_string(info)),
                                             Widen(fido_dev_info_manufacturer_string(info)),
                                             static_cast<std::uint16_t>(fido_dev_info_vendor(info)),
                                             static_cast<std::uint16_t>(fido_dev_info_product(info))});
            }
        }
        fido_dev_info_free(&list, kMaxDevices);
        if (status != FIDO_OK) {
            ThrowFido(status, "fido_dev_info_manifest");
        }
        return devices;
    }

    DeviceCaps GetCaps(const std::wstring& path) override {
        DevPtr dev = OpenDevice(path, kProbeTimeoutMs);
        DeviceCaps caps;
        caps.fido2 = fido_dev_is_fido2(dev.get());
        caps.hasPin = fido_dev_has_pin(dev.get());
        if (caps.fido2) {
            CborInfoPtr info(fido_cbor_info_new());
            if (info && fido_dev_get_cbor_info(dev.get(), info.get()) == FIDO_OK) {
                char** extensions = fido_cbor_info_extensions_ptr(info.get());
                const std::size_t count = fido_cbor_info_extensions_len(info.get());
                for (std::size_t i = 0; i < count; ++i) {
                    if (extensions[i] == nullptr) {
                        continue;
                    }
                    if (std::strcmp(extensions[i], kHmacSecretExtension) == 0) {
                        caps.hmacSecret = true;
                    } else if (std::strcmp(extensions[i], kCredProtectExtension) == 0) {
                        caps.credProtect = true;
                    }
                }
            }
        }
        return caps;
    }

    CredentialResult MakeCredential(const std::wstring& path, const std::wstring& rpId, const Bytes& userId,
                                    const std::wstring& userName, const std::wstring* pin, bool requireUv) override {
        DevPtr dev = OpenDevice(path, kTouchTimeoutMs);
        CredPtr cred(fido_cred_new());
        if (!cred) {
            throw Error(ErrorCode::Internal, "fido_cred_new failed");
        }
        const std::string rp = ToUtf8(rpId);
        const std::string name = ToUtf8(userName);
        const Bytes clientDataHash = crypto::RandomBytes(32);

        int status = fido_cred_set_type(cred.get(), COSE_ES256);
        if (status == FIDO_OK) {
            status = fido_cred_set_clientdata_hash(cred.get(), clientDataHash.data(), clientDataHash.size());
        }
        if (status == FIDO_OK) {
            status = fido_cred_set_rp(cred.get(), rp.c_str(), "FidoLogon");
        }
        if (status == FIDO_OK) {
            status = fido_cred_set_user(cred.get(), userId.data(), userId.size(), name.c_str(), name.c_str(), nullptr);
        }
        if (status == FIDO_OK) {
            status = fido_cred_set_extensions(cred.get(), FIDO_EXT_HMAC_SECRET);
        }
        if (status == FIDO_OK) {
            status = fido_cred_set_rk(cred.get(), FIDO_OPT_FALSE);
        }
        if (status == FIDO_OK && requireUv) {
            status = fido_cred_set_prot(cred.get(), FIDO_CRED_PROT_UV_REQUIRED);
        }
        if (status != FIDO_OK) {
            ThrowFido(status, "fido_cred_set");
        }

        std::string narrowPin = pin != nullptr ? ToUtf8(*pin) : std::string();
        WipeOnExit wipePin(narrowPin);
        status = fido_dev_make_cred(dev.get(), cred.get(), pin != nullptr ? narrowPin.c_str() : nullptr);
        if (status != FIDO_OK) {
            ThrowFido(status, "fido_dev_make_cred");
        }
        const unsigned char* id = fido_cred_id_ptr(cred.get());
        const std::size_t idLength = fido_cred_id_len(cred.get());
        if (id == nullptr || idLength == 0) {
            throw Error(ErrorCode::DeviceError, "the key returned an empty credential id");
        }

        CredentialResult result;
        result.credentialId.assign(id, id + idLength);
        const unsigned char* aaguid = fido_cred_aaguid_ptr(cred.get());
        if (aaguid != nullptr) {
            result.aaguid.assign(aaguid, aaguid + fido_cred_aaguid_len(cred.get()));
        }
        const char* format = fido_cred_fmt(cred.get());
        result.attestationFormat = format != nullptr ? format : "";
        const std::size_t certificates = fido_cred_x5c_list_count(cred.get());
        for (std::size_t i = 0; i < certificates; ++i) {
            const unsigned char* der = fido_cred_x5c_list_ptr(cred.get(), i);
            result.attestationCertificates.emplace_back(der, der + fido_cred_x5c_list_len(cred.get(), i));
        }
        // Checks the attestation signature over the authenticator data with the leaf certificate's key.
        result.attestationSignatureValid = certificates > 0 && fido_cred_verify(cred.get()) == FIDO_OK;
        return result;
    }

    bool HasCredential(const std::wstring& path, const std::wstring& rpId, const Bytes& credentialId,
                       const std::wstring* pin) override {
        DevPtr dev = OpenDevice(path, kProbeTimeoutMs);
        // Enrolled keys are FIDO2: a key that answers otherwise (for example still starting) is an
        // error to retry, not a key without the credential.
        if (!fido_dev_is_fido2(dev.get())) {
            throw Error(ErrorCode::DeviceError, "the key did not answer as a FIDO2 key");
        }
        AssertPtr assertion(fido_assert_new());
        if (!assertion) {
            throw Error(ErrorCode::Internal, "fido_assert_new failed");
        }
        SetCommonAssertParameters(assertion.get(), rpId, credentialId);
        const int upStatus = fido_assert_set_up(assertion.get(), FIDO_OPT_FALSE);
        if (upStatus != FIDO_OK) {
            ThrowFido(upStatus, "fido_assert_set_up");
        }
        std::string narrowPin = pin != nullptr ? ToUtf8(*pin) : std::string();
        WipeOnExit wipePin(narrowPin);
        const int status = fido_dev_get_assert(dev.get(), assertion.get(), pin != nullptr ? narrowPin.c_str() : nullptr);
        if (status == FIDO_OK) {
            return true;
        }
        if (status == FIDO_ERR_NO_CREDENTIALS || status == FIDO_ERR_INVALID_CREDENTIAL) {
            return false;
        }
        ThrowFido(status, "fido_dev_get_assert(probe)");
    }

    Bytes GetHmacSecret(const std::wstring& path, const std::wstring& rpId, const Bytes& credentialId,
                        const Bytes& salt, const std::wstring* pin) override {
        if (salt.size() != crypto::kSaltSize) {
            throw Error(ErrorCode::InvalidArgument, "hmac-secret salt must be 32 bytes");
        }
        DevPtr dev = OpenDevice(path, kTouchTimeoutMs);
        AssertPtr assertion(fido_assert_new());
        if (!assertion) {
            throw Error(ErrorCode::Internal, "fido_assert_new failed");
        }
        SetCommonAssertParameters(assertion.get(), rpId, credentialId);
        int status = fido_assert_set_extensions(assertion.get(), FIDO_EXT_HMAC_SECRET);
        if (status == FIDO_OK) {
            status = fido_assert_set_hmac_salt(assertion.get(), salt.data(), salt.size());
        }
        if (status == FIDO_OK) {
            status = fido_assert_set_up(assertion.get(), FIDO_OPT_TRUE);
        }
        if (status != FIDO_OK) {
            ThrowFido(status, "fido_assert_set");
        }

        std::string narrowPin = pin != nullptr ? ToUtf8(*pin) : std::string();
        WipeOnExit wipePin(narrowPin);
        status = fido_dev_get_assert(dev.get(), assertion.get(), pin != nullptr ? narrowPin.c_str() : nullptr);
        if (status != FIDO_OK) {
            ThrowFido(status, "fido_dev_get_assert");
        }
        if (fido_assert_count(assertion.get()) != 1) {
            throw Error(ErrorCode::DeviceError, "unexpected number of assertions");
        }
        const unsigned char* secret = fido_assert_hmac_secret_ptr(assertion.get(), 0);
        const std::size_t secretLength = fido_assert_hmac_secret_len(assertion.get(), 0);
        if (secret == nullptr || secretLength != crypto::kHmacSecretSize) {
            throw Error(ErrorCode::HmacSecretUnsupported, "the key did not return an hmac-secret output");
        }
        return Bytes(secret, secret + secretLength);
    }
};

}  // namespace

std::unique_ptr<Authenticator> CreateFido2Authenticator() { return std::make_unique<Fido2Authenticator>(); }

}  // namespace fidologon
