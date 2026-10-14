#include <windows.h>

#include <cstdio>

#include "fidologon/authenticator.h"
#include "fidologon/record_store.h"
#include "provider.h"
#include "test_framework.h"

// Symbols normally provided by the credential provider DLL entry point.
HINSTANCE g_moduleInstance = nullptr;
void DllAddRef() noexcept {}
void DllRelease() noexcept {}

namespace fltest {

std::vector<TestCase>& Registry() {
    static std::vector<TestCase> tests;
    return tests;
}

const std::wstring& TestStorageRoot() {
    static const std::wstring root =
        L"Software\\FidoLogonTests\\run-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::to_wstring(GetTickCount64());
    return root;
}

void ResetTestStorage() {
    RegDeleteTreeW(HKEY_CURRENT_USER, TestStorageRoot().c_str());
    fidologon::RecordStore::OverrideDefaultRoot(HKEY_CURRENT_USER, TestStorageRoot());
}

}  // namespace fltest

int wmain(int argc, wchar_t** argv) {
    // Optional argument: path to the built credential provider DLL (resource and export tests).
    if (argc > 1) {
        g_moduleInstance = LoadLibraryW(argv[1]);
        if (g_moduleInstance == nullptr) {
            std::fprintf(stderr, "cannot load %ls (error %lu)\n", argv[1], GetLastError());
            return 2;
        }
    }

    int failures = 0;
    for (const auto& test : fltest::Registry()) {
        fltest::ResetTestStorage();
        fidologon::ReplaceAuthenticatorForTests(nullptr);
        // Tests behave the same whether they run on the console or over Remote Desktop.
        fidologon::cp::SetRemoteSessionOverrideForTests(0);
        try {
            test.body();
            std::printf("[PASS] %s\n", test.name);
        } catch (const std::exception& e) {
            ++failures;
            std::printf("[FAIL] %s\n       %s\n", test.name, e.what());
        }
    }
    RegDeleteTreeW(HKEY_CURRENT_USER, fltest::TestStorageRoot().c_str());
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\FidoLogonTests");  // only succeeds when empty

    std::printf("\n%zu tests, %d failed\n", fltest::Registry().size(), failures);
    return failures == 0 ? 0 : 1;
}
