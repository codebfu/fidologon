#pragma once

// NTSTATUS values are needed alongside windows.h for the LSA structures.
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include <credentialprovider.h>
#include <ntsecapi.h>

#include <string>

extern HINSTANCE g_moduleInstance;

void DllAddRef() noexcept;
void DllRelease() noexcept;

// Copies a string into CoTaskMemAlloc'ed memory, as credential provider callers expect.
HRESULT CoTaskStrDup(const std::wstring& value, PWSTR* result) noexcept;

void DebugLog(const wchar_t* format, ...) noexcept;
