#include "fidologon/errors.h"

#include "fidologon/bytes.h"

namespace fidologon {

Error::Error(ErrorCode code, const std::string& detail) : std::runtime_error(detail), code_(code) {}

Error::Error(ErrorCode code) : Error(code, ToUtf8(DescribeError(code))) {}

const wchar_t* DescribeError(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::Ok: return L"Success.";
        case ErrorCode::InvalidArgument: return L"Invalid argument.";
        case ErrorCode::NotFound: return L"Not found.";
        case ErrorCode::NoDevice: return L"No enrolled security key is plugged in.";
        case ErrorCode::DeviceError: return L"The security key reported an error.";
        case ErrorCode::PinRequired: return L"This security key requires its PIN.";
        case ErrorCode::PinInvalid: return L"Incorrect security key PIN.";
        case ErrorCode::PinBlocked: return L"The security key PIN is blocked. Unplug and replug the key, or reset it.";
        case ErrorCode::PinNotSet: return L"The security key has no PIN. Set a PIN on the key first.";
        case ErrorCode::HmacSecretUnsupported: return L"The security key does not support the hmac-secret extension.";
        case ErrorCode::CredentialNotOnDevice: return L"This security key is not enrolled for this account.";
        case ErrorCode::DecryptFailed: return L"The security key could not unlock the stored credential.";
        case ErrorCode::StorageError: return L"Could not access the FidoLogon configuration.";
        case ErrorCode::AccessDenied: return L"Access denied. Administrator rights are required.";
        case ErrorCode::Timeout: return L"Timed out waiting for the security key to be touched.";
        case ErrorCode::PasswordInvalid: return L"The Windows password is incorrect.";
        case ErrorCode::BufferTooSmall: return L"Buffer too small.";
        case ErrorCode::Internal: return L"Internal error.";
        case ErrorCode::OperationDenied: return L"The operation was denied on the security key.";
        case ErrorCode::MultipleDevices:
            return L"Several security keys are plugged in. Leave only the key enrolled for this account and try again.";
        case ErrorCode::CredProtectUnsupported:
            return L"This security key cannot enforce its PIN (no CTAP 2.1 credProtect support). "
                   L"Enroll it in touch-only mode or use a more recent key.";
        case ErrorCode::AttestationRejected:
            return L"This security key model is not allowed on this computer, or its attestation could not be verified.";
    }
    return L"Unknown error.";
}

}  // namespace fidologon
