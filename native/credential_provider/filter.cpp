#include "filter.h"

#include "guids.h"

#include "fidologon/enrollment.h"
#include "fidologon/record_store.h"

namespace fidologon::cp {
namespace {

constexpr wchar_t kProviderKey[] =
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\"
    L"{FAAD8F12-6991-448B-BF78-892ED3E6A76B}";

bool IsProviderDisabledByPolicy() {
    DWORD value = 0;
    DWORD size = sizeof(value);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, kProviderKey, L"Disabled", RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY, nullptr,
                     &value, &size) != ERROR_SUCCESS) {
        return false;
    }
    return value != 0;
}

}  // namespace


bool ShouldHidePasswordProvider(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, const GUID* providers,
                                const BOOL* allow, DWORD count, bool fallbackAllowed, bool everyUserEnrolled,
                                bool safeMode, bool remoteSession, bool providerDisabled, bool machineJoined) {
    if (fallbackAllowed || !everyUserEnrolled || safeMode || remoteSession || providerDisabled || machineJoined) {
        return false;
    }
    if (scenario != CPUS_LOGON && scenario != CPUS_UNLOCK_WORKSTATION) {
        return false;
    }
    // Only hide the password tile if our own tile is going to be shown.
    for (DWORD i = 0; i < count; ++i) {
        if (IsEqualGUID(providers[i], CLSID_FidoLogonProvider) && allow[i]) {
            return true;
        }
    }
    return false;
}

PasswordFilter::PasswordFilter() { DllAddRef(); }

PasswordFilter::~PasswordFilter() { DllRelease(); }

IFACEMETHODIMP PasswordFilter::QueryInterface(REFIID riid, void** ppv) {
    if (ppv == nullptr) {
        return E_POINTER;
    }
    if (riid == IID_IUnknown || riid == IID_ICredentialProviderFilter) {
        *ppv = static_cast<ICredentialProviderFilter*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

IFACEMETHODIMP_(ULONG) PasswordFilter::AddRef() { return static_cast<ULONG>(InterlockedIncrement(&refs_)); }

IFACEMETHODIMP_(ULONG) PasswordFilter::Release() {
    const LONG refs = InterlockedDecrement(&refs_);
    if (refs == 0) {
        delete this;
    }
    return static_cast<ULONG>(refs);
}

IFACEMETHODIMP PasswordFilter::Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD, GUID* providers, BOOL* allow,
                              DWORD count) {
    if (providers == nullptr || allow == nullptr) {
        return E_POINTER;
    }
    try {
        RecordStore store = RecordStore::OpenDefault();
        const bool fallbackAllowed = store.AllowPasswordFallback();
        const bool hide =
            !fallbackAllowed &&
            ShouldHidePasswordProvider(scenario, providers, allow, count, fallbackAllowed,
                                       EveryEnabledUserEnrolled(ListLocalUsers(), store.List()),
                                       GetSystemMetrics(SM_CLEANBOOT) != 0, GetSystemMetrics(SM_REMOTESESSION) != 0,
                                       IsProviderDisabledByPolicy(), IsJoinedToDomainOrEntra());
        if (hide) {
            for (DWORD i = 0; i < count; ++i) {
                if (IsEqualGUID(providers[i], CLSID_WindowsPasswordProvider)) {
                    allow[i] = FALSE;
                }
            }
        }
    } catch (const std::exception& e) {
        // Never lock users out because of a configuration read error.
        DebugLog(L"FidoLogon: filter error, password provider kept: %hs", e.what());
    }
    return S_OK;
}

IFACEMETHODIMP PasswordFilter::UpdateRemoteCredential(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*,
                                              CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) {
    return E_NOTIMPL;
}

}  // namespace fidologon::cp
