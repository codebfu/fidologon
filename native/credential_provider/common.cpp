#include "common.h"

#include <cstdarg>
#include <cstdio>

HRESULT CoTaskStrDup(const std::wstring& value, PWSTR* result) noexcept {
    if (result == nullptr) {
        return E_POINTER;
    }
    const std::size_t bytes = (value.size() + 1) * sizeof(wchar_t);
    *result = static_cast<PWSTR>(CoTaskMemAlloc(bytes));
    if (*result == nullptr) {
        return E_OUTOFMEMORY;
    }
    memcpy(*result, value.c_str(), bytes);
    return S_OK;
}

void DebugLog(const wchar_t* format, ...) noexcept {
    wchar_t buffer[1024];
    va_list args;
    va_start(args, format);
    _vsnwprintf_s(buffer, _TRUNCATE, format, args);
    va_end(args);
    OutputDebugStringW(buffer);
    OutputDebugStringW(L"\n");
}
