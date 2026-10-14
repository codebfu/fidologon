#pragma once

#include <stdexcept>
#include <string>

namespace fidologon {

// Error codes shared by the C++ core, the native C API and the .NET wrapper.
// Values are part of the native API contract: never renumber existing entries.
enum class ErrorCode : int {
    Ok = 0,
    InvalidArgument = 1,
    NotFound = 2,
    NoDevice = 3,
    DeviceError = 4,
    PinRequired = 5,
    PinInvalid = 6,
    PinBlocked = 7,
    PinNotSet = 8,
    HmacSecretUnsupported = 9,
    CredentialNotOnDevice = 10,
    DecryptFailed = 11,
    StorageError = 12,
    AccessDenied = 13,
    Timeout = 14,
    PasswordInvalid = 15,
    BufferTooSmall = 16,
    Internal = 17,
    OperationDenied = 18,
    MultipleDevices = 19,
    CredProtectUnsupported = 20,
    AttestationRejected = 21,
};

class Error : public std::runtime_error {
public:
    Error(ErrorCode code, const std::string& detail);
    explicit Error(ErrorCode code);

    ErrorCode code() const noexcept { return code_; }

private:
    ErrorCode code_;
};

// Short, user-facing description of an error code (English).
const wchar_t* DescribeError(ErrorCode code) noexcept;

}  // namespace fidologon
