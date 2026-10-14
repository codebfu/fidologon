#pragma once

#include "common.h"

#include <vector>

#include "fidologon/accounts.h"
#include "fidologon/record_store.h"

namespace fidologon::cp {

// Hides the built-in password tile when the administrator disabled the password
// fallback. Safety rules keep the password available whenever the FidoLogon tile
// could be missing (safe mode, remote session, provider disabled, an enabled
// local account without any enrolled key, or a domain / Entra ID joined computer
// whose users cannot have FidoLogon keys).
class PasswordFilter final : public ICredentialProviderFilter {
public:
    PasswordFilter();

    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;

    IFACEMETHODIMP Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD flags, GUID* providers, BOOL* allow,
                          DWORD count) override;
    IFACEMETHODIMP UpdateRemoteCredential(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* in,
                                          CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* out) override;

private:
    ~PasswordFilter();
    LONG refs_ = 1;
};

// Pure decision logic, exposed for tests.
bool ShouldHidePasswordProvider(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, const GUID* providers,
                                const BOOL* allow, DWORD count, bool fallbackAllowed, bool everyUserEnrolled,
                                bool safeMode, bool remoteSession, bool providerDisabled, bool machineJoined);

}  // namespace fidologon::cp
