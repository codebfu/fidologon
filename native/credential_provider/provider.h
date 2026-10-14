#pragma once

#include "common.h"

#include <vector>

namespace fidologon::cp {

class Credential;

// Exposes one "FIDO2 security key" sign-in option for every user tile whose
// account has at least one enrolled key (V2 credential provider).
class Provider final : public ICredentialProvider, public ICredentialProviderSetUserArray {
public:
    Provider();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD flags) override;
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization) override;
    IFACEMETHODIMP Advise(ICredentialProviderEvents* events, UINT_PTR context) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* count) override;
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor) override;
    IFACEMETHODIMP GetCredentialCount(DWORD* count, DWORD* defaultIndex, BOOL* autoLogonWithDefault) override;
    IFACEMETHODIMP GetCredentialAt(DWORD index, ICredentialProviderCredential** credential) override;

    // ICredentialProviderSetUserArray
    IFACEMETHODIMP SetUserArray(ICredentialProviderUserArray* users) override;

private:
    ~Provider();
    void ReleaseCredentials();
    void BuildCredentials();
    void BuildCredentials(std::vector<Credential*>& previous);
    void OnCredentialReady();

    LONG refs_ = 1;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_ = CPUS_INVALID;
    ICredentialProviderUserArray* users_ = nullptr;
    ICredentialProviderEvents* events_ = nullptr;
    UINT_PTR adviseContext_ = 0;
    std::vector<Credential*> credentials_;
    bool built_ = false;
};

// True in a Remote Desktop session, where the provider stays inactive.
bool IsRemoteSession();

#ifdef FIDOLOGON_TESTING
// Test builds only: -1 uses the real detection, 0 or 1 forces the result.
void SetRemoteSessionOverrideForTests(int value);
#endif

}  // namespace fidologon::cp
