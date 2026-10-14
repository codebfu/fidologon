#pragma once

#include <windows.h>

#include <string>
#include <vector>

namespace fidologon {

struct LocalUser {
    std::wstring name;
    std::wstring fullName;
    std::wstring sid;
    bool disabled = false;
};

// Normal (non-machine) local accounts of this computer.
std::vector<LocalUser> ListLocalUsers();

// Checks a local account's password without creating an interactive session.
// Returns ERROR_SUCCESS or the Win32 error reported by LogonUser.
DWORD VerifyLocalPassword(const std::wstring& userName, const std::wstring& password);

std::wstring ComputerName();

// True when the computer is joined to an Active Directory domain or to Microsoft Entra ID, or
// when that cannot be determined. Users of such machines may have no FidoLogon key at all.
bool IsJoinedToDomainOrEntra() noexcept;

}  // namespace fidologon
