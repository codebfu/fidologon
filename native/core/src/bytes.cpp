#include "fidologon/bytes.h"

#include <windows.h>

#include "fidologon/errors.h"

namespace fidologon {

void SecureWipe(void* data, std::size_t size) noexcept {
    if (data != nullptr && size != 0) {
        SecureZeroMemory(data, size);
    }
}

void Wipe(Bytes& value) noexcept {
    SecureWipe(value.data(), value.size());
    value.clear();
}

void Wipe(std::wstring& value) noexcept {
    SecureWipe(value.data(), value.size() * sizeof(wchar_t));
    value.clear();
}

void Wipe(std::string& value) noexcept {
    SecureWipe(value.data(), value.size());
    value.clear();
}

std::string ToUtf8(std::wstring_view value) {
    if (value.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        throw Error(ErrorCode::InvalidArgument, "invalid UTF-16 string");
    }
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(),
                        size, nullptr, nullptr);
    return result;
}

std::wstring FromUtf8(std::string_view value) {
    if (value.empty()) {
        return {};
    }
    const int size =
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) {
        throw Error(ErrorCode::InvalidArgument, "invalid UTF-8 string");
    }
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(),
                        size);
    return result;
}

}  // namespace fidologon
