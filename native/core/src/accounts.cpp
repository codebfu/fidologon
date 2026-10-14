#include "fidologon/accounts.h"

#include <lm.h>
#include <lmjoin.h>
#include <sddl.h>

#include "fidologon/errors.h"

namespace fidologon {
namespace {

std::wstring LookupSidString(const std::wstring& qualifiedName) {
    BYTE sidBuffer[SECURITY_MAX_SID_SIZE];
    DWORD sidSize = sizeof(sidBuffer);
    wchar_t domain[256];
    DWORD domainSize = ARRAYSIZE(domain);
    SID_NAME_USE use{};
    if (!LookupAccountNameW(nullptr, qualifiedName.c_str(), sidBuffer, &sidSize, domain, &domainSize, &use)) {
        return {};
    }
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(sidBuffer, &text)) {
        return {};
    }
    std::wstring result = text;
    LocalFree(text);
    return result;
}

}  // namespace

bool IsJoinedToDomainOrEntra() noexcept {
    LPWSTR name = nullptr;
    NETSETUP_JOIN_STATUS status = NetSetupUnknownStatus;
    if (NetGetJoinInformation(nullptr, &name, &status) != NERR_Success) {
        return true;  // unknown: assume joined, the safe answer
    }
    NetApiBufferFree(name);
    if (status == NetSetupDomainName) {
        return true;
    }

    PDSREG_JOIN_INFO info = nullptr;
    if (FAILED(NetGetAadJoinInformation(nullptr, &info))) {
        return true;
    }
    // Only a device join lets Entra users sign in here; a workplace registration does not.
    const bool entraJoined = info != nullptr && info->joinType == DSREG_DEVICE_JOIN;
    if (info != nullptr) {
        NetFreeAadJoinInformation(info);
    }
    return entraJoined;
}

std::wstring ComputerName() {
    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = ARRAYSIZE(name);
    if (!GetComputerNameW(name, &size)) {
        throw Error(ErrorCode::Internal, "GetComputerName failed");
    }
    return std::wstring(name, size);
}

std::vector<LocalUser> ListLocalUsers() {
    std::vector<LocalUser> users;
    const std::wstring computer = ComputerName();
    DWORD resumeHandle = 0;
    NET_API_STATUS status;
    do {
        LPBYTE buffer = nullptr;
        DWORD read = 0;
        DWORD total = 0;
        status = NetUserEnum(nullptr, 20, FILTER_NORMAL_ACCOUNT, &buffer, MAX_PREFERRED_LENGTH, &read, &total,
                             &resumeHandle);
        if (status != NERR_Success && status != ERROR_MORE_DATA) {
            throw Error(ErrorCode::Internal, "NetUserEnum failed with error " + std::to_string(status));
        }
        const auto* entries = reinterpret_cast<const USER_INFO_20*>(buffer);
        for (DWORD i = 0; i < read; ++i) {
            LocalUser user;
            user.name = entries[i].usri20_name;
            user.fullName = entries[i].usri20_full_name != nullptr ? entries[i].usri20_full_name : L"";
            user.disabled = (entries[i].usri20_flags & UF_ACCOUNTDISABLE) != 0;
            user.sid = LookupSidString(computer + L"\\" + user.name);
            if (!user.sid.empty()) {
                users.push_back(std::move(user));
            }
        }
        NetApiBufferFree(buffer);
    } while (status == ERROR_MORE_DATA);
    return users;
}

DWORD VerifyLocalPassword(const std::wstring& userName, const std::wstring& password) {
    HANDLE token = nullptr;
    if (LogonUserW(userName.c_str(), L".", password.c_str(), LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT,
                   &token)) {
        CloseHandle(token);
        return ERROR_SUCCESS;
    }
    DWORD error = GetLastError();
    if (error == ERROR_LOGON_TYPE_NOT_GRANTED) {
        // Network logon may be denied by policy; interactive logon still validates the password.
        if (LogonUserW(userName.c_str(), L".", password.c_str(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
                       &token)) {
            CloseHandle(token);
            return ERROR_SUCCESS;
        }
        error = GetLastError();
    }
    return error;
}

}  // namespace fidologon
