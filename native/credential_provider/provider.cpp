#include "provider.h"

#include <initguid.h>
#include <propkey.h>

#include <new>

#include "credential.h"
#include "fields.h"

#include "fidologon/record_store.h"

namespace fidologon::cp {

#ifdef FIDOLOGON_TESTING
namespace {
int g_remoteSessionOverride = -1;
}  // namespace

void SetRemoteSessionOverrideForTests(int value) { g_remoteSessionOverride = value; }

bool IsRemoteSession() {
    return g_remoteSessionOverride >= 0 ? g_remoteSessionOverride != 0 : GetSystemMetrics(SM_REMOTESESSION) != 0;
}
#else
bool IsRemoteSession() { return GetSystemMetrics(SM_REMOTESESSION) != 0; }
#endif

Provider::Provider() { DllAddRef(); }

Provider::~Provider() {
    ReleaseCredentials();
    if (users_ != nullptr) {
        users_->Release();
    }
    if (events_ != nullptr) {
        events_->Release();
    }
    DllRelease();
}

IFACEMETHODIMP Provider::QueryInterface(REFIID riid, void** ppv) {
    if (ppv == nullptr) {
        return E_POINTER;
    }
    if (riid == IID_IUnknown || riid == IID_ICredentialProvider) {
        *ppv = static_cast<ICredentialProvider*>(this);
    } else if (riid == IID_ICredentialProviderSetUserArray) {
        *ppv = static_cast<ICredentialProviderSetUserArray*>(this);
    } else {
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    AddRef();
    return S_OK;
}

IFACEMETHODIMP_(ULONG) Provider::AddRef() { return static_cast<ULONG>(InterlockedIncrement(&refs_)); }

IFACEMETHODIMP_(ULONG) Provider::Release() {
    const LONG refs = InterlockedDecrement(&refs_);
    if (refs == 0) {
        delete this;
    }
    return static_cast<ULONG>(refs);
}

IFACEMETHODIMP Provider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD) {
    // Remote Desktop is out of scope: the key is not available in the remote session.
    if ((scenario != CPUS_LOGON && scenario != CPUS_UNLOCK_WORKSTATION) || IsRemoteSession()) {
        return E_NOTIMPL;
    }
    scenario_ = scenario;
    ReleaseCredentials();
    return S_OK;
}

IFACEMETHODIMP Provider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) { return E_NOTIMPL; }

IFACEMETHODIMP Provider::Advise(ICredentialProviderEvents* events, UINT_PTR context) {
    if (events_ != nullptr) {
        events_->Release();
    }
    events_ = events;
    adviseContext_ = context;
    if (events_ != nullptr) {
        events_->AddRef();
    }
    return S_OK;
}

IFACEMETHODIMP Provider::UnAdvise() {
    if (events_ != nullptr) {
        events_->Release();
        events_ = nullptr;
    }
    return S_OK;
}

void Provider::OnCredentialReady() {
    // LogonUI then calls GetCredentialCount, sees the ready tile as default with auto logon,
    // and asks it for its serialization.
    if (events_ != nullptr) {
        events_->CredentialsChanged(adviseContext_);
    }
}

IFACEMETHODIMP Provider::GetFieldDescriptorCount(DWORD* count) {
    if (count == nullptr) {
        return E_POINTER;
    }
    *count = FI_COUNT;
    return S_OK;
}

IFACEMETHODIMP Provider::GetFieldDescriptorAt(DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor) {
    if (descriptor == nullptr) {
        return E_POINTER;
    }
    *descriptor = nullptr;
    if (index >= FI_COUNT) {
        return E_INVALIDARG;
    }
    auto* result = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(
        CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
    if (result == nullptr) {
        return E_OUTOFMEMORY;
    }
    ZeroMemory(result, sizeof(*result));
    result->dwFieldID = index;
    result->cpft = kFields[index].type;
    result->guidFieldType = kFields[index].guidFieldType;
    const HRESULT hr = CoTaskStrDup(kFields[index].label, &result->pszLabel);
    if (FAILED(hr)) {
        CoTaskMemFree(result);
        return hr;
    }
    *descriptor = result;
    return S_OK;
}

IFACEMETHODIMP Provider::GetCredentialCount(DWORD* count, DWORD* defaultIndex, BOOL* autoLogonWithDefault) {
    if (count == nullptr || defaultIndex == nullptr || autoLogonWithDefault == nullptr) {
        return E_POINTER;
    }
    if (!built_) {
        BuildCredentials();
    }
    *count = static_cast<DWORD>(credentials_.size());
    *defaultIndex = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *autoLogonWithDefault = FALSE;
    for (std::size_t i = 0; i < credentials_.size(); ++i) {
        if (credentials_[i]->IsReady()) {
            *defaultIndex = static_cast<DWORD>(i);
            *autoLogonWithDefault = TRUE;
            break;
        }
    }
    return S_OK;
}

IFACEMETHODIMP Provider::GetCredentialAt(DWORD index, ICredentialProviderCredential** credential) {
    if (credential == nullptr) {
        return E_POINTER;
    }
    *credential = nullptr;
    if (index >= credentials_.size()) {
        return E_INVALIDARG;
    }
    return credentials_[index]->QueryInterface(IID_PPV_ARGS(credential));
}

IFACEMETHODIMP Provider::SetUserArray(ICredentialProviderUserArray* users) {
    if (users_ != nullptr) {
        users_->Release();
    }
    users_ = users;
    if (users_ != nullptr) {
        users_->AddRef();
    }
    built_ = false;  // rebuilt at the next enumeration, keeping the tiles of the same users
    return S_OK;
}

void Provider::ReleaseCredentials() {
    for (Credential* credential : credentials_) {
        credential->SetReadyCallback(nullptr);
        credential->Release();
    }
    credentials_.clear();
    built_ = false;
}

void Provider::BuildCredentials() {
    // A tile of the previous enumeration is kept for the same user: it may hold a password the
    // key just unlocked, waiting for LogonUI to submit it.
    std::vector<Credential*> previous = std::move(credentials_);
    credentials_.clear();
    BuildCredentials(previous);
    for (Credential* credential : previous) {
        if (credential != nullptr) {
            credential->SetReadyCallback(nullptr);
            credential->Release();
        }
    }
}

void Provider::BuildCredentials(std::vector<Credential*>& previous) {
    built_ = true;
    if (users_ == nullptr || scenario_ == CPUS_INVALID) {
        return;
    }
    std::vector<KeyRecord> records;
    try {
        records = RecordStore::OpenDefault().List();
    } catch (const std::exception& e) {
        DebugLog(L"FidoLogon: cannot read enrolled keys: %hs", e.what());
        return;
    }
    if (records.empty()) {
        return;
    }

    DWORD userCount = 0;
    if (FAILED(users_->GetCount(&userCount))) {
        return;
    }
    for (DWORD i = 0; i < userCount; ++i) {
        ICredentialProviderUser* user = nullptr;
        if (FAILED(users_->GetAt(i, &user))) {
            continue;
        }
        PWSTR sid = nullptr;
        PWSTR qualifiedName = nullptr;
        if (SUCCEEDED(user->GetSid(&sid)) &&
            SUCCEEDED(user->GetStringValue(PKEY_Identity_QualifiedUserName, &qualifiedName))) {
            bool enrolled = false;
            for (const KeyRecord& record : records) {
                if (_wcsicmp(record.userSid.c_str(), sid) == 0) {
                    enrolled = true;
                    break;
                }
            }
            if (enrolled) {
                Credential* credential = nullptr;
                for (Credential*& kept : previous) {
                    if (kept != nullptr && _wcsicmp(kept->userSid().c_str(), sid) == 0) {
                        credential = kept;
                        kept = nullptr;
                        break;
                    }
                }
                if (credential == nullptr) {
                    credential = new (std::nothrow) Credential(scenario_, sid, qualifiedName);
                }
                if (credential != nullptr) {
                    credential->SetReadyCallback([this] { OnCredentialReady(); });
                    credentials_.push_back(credential);
                }
            }
        }
        CoTaskMemFree(sid);
        CoTaskMemFree(qualifiedName);
        user->Release();
    }
}

}  // namespace fidologon::cp
