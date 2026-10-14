#include "kerb_logon.h"

#include <wincred.h>

#include <climits>

#include "fidologon/accounts.h"
#include "fidologon/bytes.h"

namespace fidologon::cp {

void SplitQualifiedName(const std::wstring& qualified, std::wstring& domain, std::wstring& user) {
    const auto separator = qualified.find(L'\\');
    if (separator == std::wstring::npos) {
        domain = ComputerName();
        user = qualified;
    } else {
        domain = qualified.substr(0, separator);
        user = qualified.substr(separator + 1);
    }
}

HRESULT ProtectPasswordIfNeeded(const std::wstring& password, std::wstring& protectedPassword) {
    std::wstring copy = password;
    WipeOnExit wipeCopy(copy);

    CRED_PROTECTION_TYPE type = CredUnprotected;
    if (!CredIsProtectedW(copy.data(), &type)) {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    if (type != CredUnprotected) {
        protectedPassword = password;
        return S_OK;
    }

    DWORD length = 0;
    CredProtectW(FALSE, copy.data(), static_cast<DWORD>(copy.size() + 1), nullptr, &length, nullptr);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || length == 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    std::wstring buffer(length, L'\0');
    if (!CredProtectW(FALSE, copy.data(), static_cast<DWORD>(copy.size() + 1), buffer.data(), &length, nullptr)) {
        const HRESULT hr = HRESULT_FROM_WIN32(GetLastError());
        Wipe(buffer);
        return hr;
    }
    buffer.resize(wcsnlen(buffer.c_str(), buffer.size()));
    protectedPassword = std::move(buffer);
    return S_OK;
}

HRESULT PackInteractiveLogon(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, const std::wstring& domain,
                             const std::wstring& user, const std::wstring& password, std::vector<BYTE>& packed) {
    const std::wstring* parts[] = {&domain, &user, &password};
    std::size_t total = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);
    for (const std::wstring* part : parts) {
        const std::size_t bytes = part->size() * sizeof(wchar_t);
        if (bytes > USHRT_MAX) {
            return E_INVALIDARG;
        }
        total += bytes;
    }

    packed.assign(total, 0);
    auto* logon = reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(packed.data());
    logon->Logon.MessageType =
        scenario == CPUS_UNLOCK_WORKSTATION ? KerbWorkstationUnlockLogon : KerbInteractiveLogon;

    std::size_t offset = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);
    auto place = [&](UNICODE_STRING& target, const std::wstring& value) {
        const auto bytes = static_cast<USHORT>(value.size() * sizeof(wchar_t));
        target.Length = bytes;
        target.MaximumLength = bytes;
        target.Buffer = reinterpret_cast<PWSTR>(static_cast<ULONG_PTR>(offset));
        if (bytes != 0) {
            memcpy(packed.data() + offset, value.data(), bytes);
        }
        offset += bytes;
    };
    place(logon->Logon.LogonDomainName, domain);
    place(logon->Logon.UserName, user);
    place(logon->Logon.Password, password);
    return S_OK;
}

HRESULT LookupNegotiatePackage(ULONG* package) {
    HANDLE lsa = nullptr;
    NTSTATUS status = LsaConnectUntrusted(&lsa);
    if (status != STATUS_SUCCESS) {
        return HRESULT_FROM_NT(status);
    }
    char name[] = "Negotiate";
    LSA_STRING packageName;
    packageName.Buffer = name;
    packageName.Length = static_cast<USHORT>(sizeof(name) - 1);
    packageName.MaximumLength = static_cast<USHORT>(sizeof(name));
    status = LsaLookupAuthenticationPackage(lsa, &packageName, package);
    LsaDeregisterLogonProcess(lsa);
    return status == STATUS_SUCCESS ? S_OK : HRESULT_FROM_NT(status);
}

}  // namespace fidologon::cp
