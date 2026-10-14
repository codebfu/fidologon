#pragma once

#include "common.h"

#include <vector>

namespace fidologon::cp {

// Splits "DOMAIN\user" (or a bare "user", which gets the local computer name).
void SplitQualifiedName(const std::wstring& qualified, std::wstring& domain, std::wstring& user);

// Returns the password protected with CredProtect (unchanged if already protected).
HRESULT ProtectPasswordIfNeeded(const std::wstring& password, std::wstring& protectedPassword);

// Builds a packed KERB_INTERACTIVE_UNLOCK_LOGON: string buffers are stored as
// offsets relative to the start of the serialization, as LogonUI requires.
HRESULT PackInteractiveLogon(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, const std::wstring& domain,
                             const std::wstring& user, const std::wstring& password, std::vector<BYTE>& packed);

HRESULT LookupNegotiatePackage(ULONG* package);

}  // namespace fidologon::cp
