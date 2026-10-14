#include "common.h"

#include <propkey.h>
#include <wincred.h>

#include <functional>
#include <map>

#include "credential.h"
#include "fields.h"
#include "filter.h"
#include "guids.h"
#include "kerb_logon.h"
#include "provider.h"

#include "fidologon/enrollment.h"
#include "fidologon/errors.h"
#include "fidologon/fake_authenticator.h"
#include "test_framework.h"

using namespace fidologon;
using namespace fidologon::cp;

namespace {

constexpr wchar_t kSid[] = L"S-1-5-21-1-1001";

std::wstring ReadPacked(const std::vector<BYTE>& packed, const UNICODE_STRING& value) {
    const auto offset = reinterpret_cast<ULONG_PTR>(value.Buffer);
    CHECK(offset + value.Length <= packed.size());
    return std::wstring(reinterpret_cast<const wchar_t*>(packed.data() + offset), value.Length / sizeof(wchar_t));
}

std::wstring Unprotect(std::wstring protectedPassword) {
    DWORD length = 0;
    CredUnprotectW(FALSE, protectedPassword.data(), static_cast<DWORD>(protectedPassword.size() + 1), nullptr,
                   &length);
    std::wstring plain(length, L'\0');
    CHECK(CredUnprotectW(FALSE, protectedPassword.data(), static_cast<DWORD>(protectedPassword.size() + 1),
                         plain.data(), &length));
    plain.resize(wcsnlen(plain.c_str(), plain.size()));
    return plain;
}

// Minimal ICredentialProviderUser / ICredentialProviderUserArray for tests.
class FakeUser final : public ICredentialProviderUser {
public:
    FakeUser(std::wstring sid, std::wstring qualifiedName)
        : sid_(std::move(sid)), qualifiedName_(std::move(qualifiedName)) {}
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderUser) {
            *ppv = static_cast<ICredentialProviderUser*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++refs_; }
    IFACEMETHODIMP_(ULONG) Release() override {
        const ULONG refs = --refs_;
        if (refs == 0) {
            delete this;
        }
        return refs;
    }
    IFACEMETHODIMP GetSid(LPWSTR* sid) override { return CoTaskStrDup(sid_, sid); }
    IFACEMETHODIMP GetProviderID(GUID* id) override {
        *id = GUID_NULL;
        return S_OK;
    }
    IFACEMETHODIMP GetStringValue(REFPROPERTYKEY key, LPWSTR* value) override {
        if (key == PKEY_Identity_QualifiedUserName) {
            return CoTaskStrDup(qualifiedName_, value);
        }
        return E_INVALIDARG;
    }
    IFACEMETHODIMP GetValue(REFPROPERTYKEY, PROPVARIANT*) override { return E_NOTIMPL; }

private:
    ULONG refs_ = 1;
    std::wstring sid_;
    std::wstring qualifiedName_;
};

class FakeUserArray final : public ICredentialProviderUserArray {
public:
    void Add(FakeUser* user) { users_.push_back(user); }
    ~FakeUserArray() {
        for (auto* user : users_) {
            user->Release();
        }
    }
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderUserArray) {
            *ppv = static_cast<ICredentialProviderUserArray*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++refs_; }
    IFACEMETHODIMP_(ULONG) Release() override {
        const ULONG refs = --refs_;
        if (refs == 0) {
            delete this;
        }
        return refs;
    }
    IFACEMETHODIMP SetProviderFilter(REFGUID) override { return S_OK; }
    IFACEMETHODIMP GetAccountOptions(CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS* options) override {
        *options = CPAO_NONE;
        return S_OK;
    }
    IFACEMETHODIMP GetCount(DWORD* count) override {
        *count = static_cast<DWORD>(users_.size());
        return S_OK;
    }
    IFACEMETHODIMP GetAt(DWORD index, ICredentialProviderUser** user) override {
        if (index >= users_.size()) {
            return E_INVALIDARG;
        }
        return users_[index]->QueryInterface(IID_PPV_ARGS(user));
    }

private:
    ULONG refs_ = 1;
    std::vector<FakeUser*> users_;
};

FakeAuthenticator& InstallFakeWithEnrolledKey(const std::wstring& pin, bool requirePin) {
    auto fake = std::make_unique<FakeAuthenticator>();
    FakeAuthenticator& ref = *fake;
    ReplaceAuthenticatorForTests(std::move(fake));
    ref.PlugDevice(L"\\\\?\\hid#fake", pin);
    EnrollRequest request;
    request.devicePath = L"\\\\?\\hid#fake";
    request.userSid = kSid;
    request.userName = L"alice";
    request.requirePin = requirePin;
    request.pin = pin;
    request.password = L"S3cret-Password";
    RecordStore store = RecordStore::OpenDefault();
    Enroll(request, store);
    return ref;
}

// Builds a provider for the given scenario with users alice (enrolled) and bob (not enrolled).
Provider* CreateProvider(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario) {
    auto* provider = new Provider();
    CHECK(SUCCEEDED(provider->SetUsageScenario(scenario, 0)));
    auto* users = new FakeUserArray();
    users->Add(new FakeUser(kSid, L"MYPC\\alice"));
    users->Add(new FakeUser(L"S-1-5-21-1-1002", L"MYPC\\bob"));
    CHECK(SUCCEEDED(provider->SetUserArray(users)));
    users->Release();
    return provider;
}

struct SerializationResult {
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    std::vector<BYTE> packed;
    std::wstring status;
};

SerializationResult Submit(ICredentialProviderCredential* credential, const wchar_t* pin) {
    CHECK(SUCCEEDED(credential->SetStringValue(FI_PIN, pin)));
    SerializationResult result;
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION serialization{};
    PWSTR status = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON icon = CPSI_NONE;
    CHECK(SUCCEEDED(credential->GetSerialization(&result.response, &serialization, &status, &icon)));
    if (status != nullptr) {
        result.status = status;
        CoTaskMemFree(status);
    }
    if (serialization.rgbSerialization != nullptr) {
        CHECK(serialization.clsidCredentialProvider == CLSID_FidoLogonProvider);
        result.packed.assign(serialization.rgbSerialization,
                             serialization.rgbSerialization + serialization.cbSerialization);
        CoTaskMemFree(serialization.rgbSerialization);
    }
    return result;
}

}  // namespace

TEST(SplitQualifiedNameHandlesDomainAndBareNames) {
    std::wstring domain;
    std::wstring user;
    SplitQualifiedName(L"MYPC\\alice", domain, user);
    CHECK(domain == L"MYPC");
    CHECK(user == L"alice");
    SplitQualifiedName(L"bob", domain, user);
    CHECK(domain == ComputerName());
    CHECK(user == L"bob");
}

TEST(PackInteractiveLogonUsesRelativeOffsets) {
    std::vector<BYTE> packed;
    CHECK(SUCCEEDED(PackInteractiveLogon(CPUS_UNLOCK_WORKSTATION, L"MYPC", L"alice", L"pw", packed)));
    const auto* logon = reinterpret_cast<const KERB_INTERACTIVE_UNLOCK_LOGON*>(packed.data());
    CHECK(logon->Logon.MessageType == KerbWorkstationUnlockLogon);
    CHECK(ReadPacked(packed, logon->Logon.LogonDomainName) == L"MYPC");
    CHECK(ReadPacked(packed, logon->Logon.UserName) == L"alice");
    CHECK(ReadPacked(packed, logon->Logon.Password) == L"pw");
    CHECK_EQ(packed.size(), sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + (4 + 5 + 2) * sizeof(wchar_t));

    CHECK(SUCCEEDED(PackInteractiveLogon(CPUS_LOGON, L"D", L"U", L"P", packed)));
    CHECK(reinterpret_cast<const KERB_INTERACTIVE_UNLOCK_LOGON*>(packed.data())->Logon.MessageType ==
          KerbInteractiveLogon);
}

TEST(ProtectPasswordRoundTripsThroughCredUnprotect) {
    std::wstring protectedPassword;
    CHECK(SUCCEEDED(ProtectPasswordIfNeeded(L"hunter2", protectedPassword)));
    CHECK(protectedPassword != L"hunter2");
    CHECK(Unprotect(protectedPassword) == L"hunter2");

    std::wstring twice;
    CHECK(SUCCEEDED(ProtectPasswordIfNeeded(protectedPassword, twice)));
    CHECK(twice == protectedPassword);  // already protected: unchanged
}

TEST(FilterHidesPasswordOnlyWhenSafe) {
    GUID providers[] = {CLSID_WindowsPasswordProvider, CLSID_FidoLogonProvider};
    BOOL allow[] = {TRUE, TRUE};
    auto hide = [&](CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, bool fallback, bool everyUser, bool safeMode,
                    bool remote, bool disabled, bool joined = false) {
        return ShouldHidePasswordProvider(scenario, providers, allow, 2, fallback, everyUser, safeMode, remote,
                                          disabled, joined);
    };
    CHECK(hide(CPUS_LOGON, false, true, false, false, false));
    CHECK(hide(CPUS_UNLOCK_WORKSTATION, false, true, false, false, false));
    CHECK(!hide(CPUS_LOGON, true, true, false, false, false));   // fallback allowed
    CHECK(!hide(CPUS_LOGON, false, false, false, false, false)); // some account has no key
    CHECK(!hide(CPUS_LOGON, false, true, true, false, false));   // safe mode
    CHECK(!hide(CPUS_LOGON, false, true, false, true, false));   // remote session
    CHECK(!hide(CPUS_LOGON, false, true, false, false, true));   // our provider disabled
    CHECK(!hide(CPUS_LOGON, false, true, false, false, false, true));  // domain / Entra ID joined
    CHECK(!hide(CPUS_CREDUI, false, true, false, false, false)); // UAC / CredUI prompts untouched

    allow[1] = FALSE;  // our tile is filtered out by someone else
    CHECK(!hide(CPUS_LOGON, false, true, false, false, false));
}

TEST(ProviderRejectsUnsupportedScenarios) {
    auto* provider = new Provider();
    CHECK(provider->SetUsageScenario(CPUS_CREDUI, 0) == E_NOTIMPL);
    CHECK(provider->SetUsageScenario(CPUS_CHANGE_PASSWORD, 0) == E_NOTIMPL);
    SetRemoteSessionOverrideForTests(1);
    CHECK(provider->SetUsageScenario(CPUS_LOGON, 0) == E_NOTIMPL);  // never over Remote Desktop
    SetRemoteSessionOverrideForTests(0);
    CHECK(provider->SetUsageScenario(CPUS_LOGON, 0) == S_OK);
    provider->Release();
}

TEST(ProviderExposesTileOnlyForEnrolledUsers) {
    InstallFakeWithEnrolledKey(L"1234", true);
    Provider* provider = CreateProvider(CPUS_LOGON);

    DWORD count = 0;
    DWORD defaultIndex = 0;
    BOOL autoLogon = TRUE;
    CHECK(SUCCEEDED(provider->GetCredentialCount(&count, &defaultIndex, &autoLogon)));
    CHECK_EQ(count, 1u);
    CHECK_EQ(defaultIndex, CREDENTIAL_PROVIDER_NO_DEFAULT);
    CHECK(!autoLogon);

    ICredentialProviderCredential* credential = nullptr;
    CHECK(SUCCEEDED(provider->GetCredentialAt(0, &credential)));
    ICredentialProviderCredential2* credential2 = nullptr;
    CHECK(SUCCEEDED(credential->QueryInterface(IID_PPV_ARGS(&credential2))));
    PWSTR sid = nullptr;
    CHECK(SUCCEEDED(credential2->GetUserSid(&sid)));
    CHECK(std::wstring(sid) == kSid);
    CoTaskMemFree(sid);
    credential2->Release();
    credential->Release();
    provider->Release();
}

TEST(ProviderFieldDescriptorsAreConsistent) {
    auto* provider = new Provider();
    DWORD count = 0;
    CHECK(SUCCEEDED(provider->GetFieldDescriptorCount(&count)));
    CHECK_EQ(count, static_cast<DWORD>(FI_COUNT));
    for (DWORD i = 0; i < count; ++i) {
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* descriptor = nullptr;
        CHECK(SUCCEEDED(provider->GetFieldDescriptorAt(i, &descriptor)));
        CHECK_EQ(descriptor->dwFieldID, i);
        CHECK(descriptor->cpft == kFields[i].type);
        CoTaskMemFree(descriptor->pszLabel);
        CoTaskMemFree(descriptor);
    }
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* descriptor = nullptr;
    CHECK(provider->GetFieldDescriptorAt(count, &descriptor) == E_INVALIDARG);
    provider->Release();
}

TEST(GetSerializationProducesLogonForEnrolledKey) {
    InstallFakeWithEnrolledKey(L"1234", true);
    for (auto scenario : {CPUS_LOGON, CPUS_UNLOCK_WORKSTATION}) {
        Provider* provider = CreateProvider(scenario);
        DWORD count = 0;
        DWORD defaultIndex = 0;
        BOOL autoLogon = FALSE;
        CHECK(SUCCEEDED(provider->GetCredentialCount(&count, &defaultIndex, &autoLogon)));
        ICredentialProviderCredential* credential = nullptr;
        CHECK(SUCCEEDED(provider->GetCredentialAt(0, &credential)));

        const SerializationResult result = Submit(credential, L"1234");
        CHECK(result.response == CPGSR_RETURN_CREDENTIAL_FINISHED);
        const auto* logon = reinterpret_cast<const KERB_INTERACTIVE_UNLOCK_LOGON*>(result.packed.data());
        CHECK(logon->Logon.MessageType ==
              (scenario == CPUS_LOGON ? KerbInteractiveLogon : KerbWorkstationUnlockLogon));
        CHECK(ReadPacked(result.packed, logon->Logon.LogonDomainName) == L"MYPC");
        CHECK(ReadPacked(result.packed, logon->Logon.UserName) == L"alice");
        CHECK(Unprotect(ReadPacked(result.packed, logon->Logon.Password)) == L"S3cret-Password");

        // The service learns which key opened the session.
        const auto lastAuth = RecordStore::OpenDefault().TakeLastAuth();
        CHECK(lastAuth.has_value());
        CHECK(lastAuth->userSid == kSid);
        DWORD session = 0;
        ProcessIdToSessionId(GetCurrentProcessId(), &session);
        CHECK_EQ(lastAuth->sessionId, session);
        CHECK(lastAuth->devicePath == L"\\\\?\\hid#fake");

        credential->Release();
        provider->Release();
    }
}

TEST(GetSerializationReportsUserErrors) {
    FakeAuthenticator& fake = InstallFakeWithEnrolledKey(L"1234", true);
    Provider* provider = CreateProvider(CPUS_LOGON);
    DWORD count = 0;
    DWORD defaultIndex = 0;
    BOOL autoLogon = FALSE;
    CHECK(SUCCEEDED(provider->GetCredentialCount(&count, &defaultIndex, &autoLogon)));
    ICredentialProviderCredential* credential = nullptr;
    CHECK(SUCCEEDED(provider->GetCredentialAt(0, &credential)));

    SerializationResult result = Submit(credential, L"");
    CHECK(result.response == CPGSR_NO_CREDENTIAL_NOT_FINISHED);
    CHECK(result.status == DescribeError(ErrorCode::PinRequired));

    result = Submit(credential, L"9999");
    CHECK(result.status == DescribeError(ErrorCode::PinInvalid));

    fake.PlugDevice(L"\\\\?\\hid#other", L"5555");
    result = Submit(credential, L"1234");
    CHECK(result.status == DescribeError(ErrorCode::MultipleDevices));
    CHECK_EQ(fake.PinAttempts(L"\\\\?\\hid#other"), 0);
    fake.UnplugDevice(L"\\\\?\\hid#other");

    fake.UnplugDevice(L"\\\\?\\hid#fake");
    result = Submit(credential, L"1234");
    CHECK(result.status == DescribeError(ErrorCode::NoDevice));
    CHECK(!RecordStore::OpenDefault().TakeLastAuth().has_value());

    credential->Release();
    provider->Release();
}

TEST(ReportResultExplainsRejectedPasswordAndClearsBinding) {
    InstallFakeWithEnrolledKey(L"", false);
    RecordStore::OpenDefault().WriteLastAuth(LastAuth{kSid, L"p", L"r", 1});
    auto* credential = new Credential(CPUS_LOGON, kSid, L"MYPC\\alice");
    PWSTR status = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON icon = CPSI_NONE;
    CHECK(SUCCEEDED(credential->ReportResult(STATUS_LOGON_FAILURE, STATUS_WRONG_PASSWORD, &status, &icon)));
    CHECK(status != nullptr);
    CHECK(icon == CPSI_ERROR);
    CoTaskMemFree(status);
    CHECK(!RecordStore::OpenDefault().TakeLastAuth().has_value());

    CHECK(SUCCEEDED(credential->ReportResult(STATUS_SUCCESS, STATUS_SUCCESS, &status, &icon)));
    CHECK(status == nullptr);
    credential->Release();
}

TEST(TileBitmapResourceLoads) {
    if (g_moduleInstance == nullptr) {
        return;  // DLL path not provided
    }
    auto* credential = new Credential(CPUS_LOGON, kSid, L"MYPC\\alice");
    HBITMAP bitmap = nullptr;
    CHECK(SUCCEEDED(credential->GetBitmapValue(FI_TILE_IMAGE, &bitmap)));
    CHECK(bitmap != nullptr);
    // A 32-bit glyph with transparent pixels (white outline on a transparent background).
    DIBSECTION dib{};
    CHECK_EQ(GetObjectW(bitmap, sizeof(dib), &dib), static_cast<int>(sizeof(dib)));
    CHECK_EQ(dib.dsBm.bmBitsPixel, 32);
    const auto* pixels = static_cast<const BYTE*>(dib.dsBm.bmBits);
    CHECK(pixels != nullptr);
    CHECK_EQ(pixels[3], 0);  // corner pixel: alpha 0
    DeleteObject(bitmap);

    // LogonUI asks ICredentialProviderCredential3 for an encoded image, which keeps the alpha channel.
    ICredentialProviderCredential3* credential3 = nullptr;
    CHECK(SUCCEEDED(credential->QueryInterface(IID_PPV_ARGS(&credential3))));
    DWORD size = 0;
    BYTE* png = nullptr;
    CHECK(SUCCEEDED(credential3->GetBitmapBufferValue(FI_TILE_IMAGE, &size, &png)));
    CHECK(png != nullptr && size > 8);
    CHECK(memcmp(png, "\x89PNG\r\n\x1a\n", 8) == 0);
    CoTaskMemFree(png);
    CHECK(credential3->GetBitmapBufferValue(FI_TITLE, &size, &png) == E_INVALIDARG);
    credential3->Release();
    credential->Release();
}

TEST(DllExposesProviderAndFilterClasses) {
    if (g_moduleInstance == nullptr) {
        return;
    }
    using GetClassObjectFn = HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, void**);
    using CanUnloadFn = HRESULT(STDAPICALLTYPE*)();
    auto getClassObject =
        reinterpret_cast<GetClassObjectFn>(GetProcAddress(g_moduleInstance, "DllGetClassObject"));
    auto canUnload = reinterpret_cast<CanUnloadFn>(GetProcAddress(g_moduleInstance, "DllCanUnloadNow"));
    CHECK(getClassObject != nullptr && canUnload != nullptr);
    CHECK(GetProcAddress(g_moduleInstance, "DllRegisterServer") != nullptr);

    IClassFactory* factory = nullptr;
    CHECK(SUCCEEDED(getClassObject(CLSID_FidoLogonProvider, IID_PPV_ARGS(&factory))));
    ICredentialProvider* provider = nullptr;
    CHECK(SUCCEEDED(factory->CreateInstance(nullptr, IID_PPV_ARGS(&provider))));
    ICredentialProviderSetUserArray* setUserArray = nullptr;
    CHECK(SUCCEEDED(provider->QueryInterface(IID_PPV_ARGS(&setUserArray))));
    CHECK(canUnload() == S_FALSE);
    setUserArray->Release();
    provider->Release();
    factory->Release();

    CHECK(SUCCEEDED(getClassObject(CLSID_FidoLogonFilter, IID_PPV_ARGS(&factory))));
    ICredentialProviderFilter* filter = nullptr;
    CHECK(SUCCEEDED(factory->CreateInstance(nullptr, IID_PPV_ARGS(&filter))));
    filter->Release();
    factory->Release();
    CHECK(canUnload() == S_OK);

    void* unused = nullptr;
    CHECK(getClassObject(GUID_NULL, IID_IClassFactory, &unused) == CLASS_E_CLASSNOTAVAILABLE);
}

namespace {

// Records what the tile shows, like LogonUI would.
class FakeCredentialEvents final : public ICredentialProviderCredentialEvents {
public:
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredentialEvents) {
            *ppv = static_cast<ICredentialProviderCredentialEvents*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return 2; }  // owned by the test
    IFACEMETHODIMP_(ULONG) Release() override { return 1; }
    IFACEMETHODIMP SetFieldState(ICredentialProviderCredential*, DWORD field,
                                 CREDENTIAL_PROVIDER_FIELD_STATE state) override {
        states[field] = state;
        return S_OK;
    }
    IFACEMETHODIMP SetFieldInteractiveState(ICredentialProviderCredential*, DWORD,
                                            CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE) override {
        return S_OK;
    }
    IFACEMETHODIMP SetFieldString(ICredentialProviderCredential*, DWORD field, LPCWSTR text) override {
        strings[field] = text != nullptr ? text : L"";
        history.push_back(strings[field]);
        return S_OK;
    }
    IFACEMETHODIMP SetFieldCheckbox(ICredentialProviderCredential*, DWORD, BOOL, LPCWSTR) override { return S_OK; }
    IFACEMETHODIMP SetFieldBitmap(ICredentialProviderCredential*, DWORD, HBITMAP) override { return S_OK; }
    IFACEMETHODIMP SetFieldComboBoxSelectedItem(ICredentialProviderCredential*, DWORD, DWORD) override {
        return S_OK;
    }
    IFACEMETHODIMP DeleteFieldComboBoxItem(ICredentialProviderCredential*, DWORD, DWORD) override { return S_OK; }
    IFACEMETHODIMP AppendFieldComboBoxItem(ICredentialProviderCredential*, DWORD, LPCWSTR) override {
        return S_OK;
    }
    IFACEMETHODIMP SetFieldSubmitButton(ICredentialProviderCredential*, DWORD, DWORD) override { return S_OK; }
    IFACEMETHODIMP OnCreatingWindow(HWND* window) override {
        *window = nullptr;
        return S_OK;
    }

    std::map<DWORD, std::wstring> strings;
    std::map<DWORD, CREDENTIAL_PROVIDER_FIELD_STATE> states;
    std::vector<std::wstring> history;
};

class FakeProviderEvents final : public ICredentialProviderEvents {
public:
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderEvents) {
            *ppv = static_cast<ICredentialProviderEvents*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return 2; }  // owned by the test
    IFACEMETHODIMP_(ULONG) Release() override { return 1; }
    IFACEMETHODIMP CredentialsChanged(UINT_PTR context) override {
        CHECK_EQ(context, static_cast<UINT_PTR>(42));
        ++changes;
        return S_OK;
    }

    int changes = 0;
};

// Pumps the test thread messages (the reports of the tile) until `done` holds or 5 s passed.
bool PumpUntil(const std::function<bool()>& done) {
    const ULONGLONG deadline = GetTickCount64() + 5000;
    while (!done()) {
        if (GetTickCount64() > deadline) {
            return false;
        }
        MSG message;
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
            DispatchMessageW(&message);
        }
        Sleep(10);
    }
    return true;
}

bool Contains(const std::wstring& text, const wchar_t* part) { return text.find(part) != std::wstring::npos; }

// A provider and the alice tile, advised and selected as LogonUI does.
struct WatchedTile {
    Provider* provider = CreateProvider(CPUS_LOGON);
    FakeProviderEvents providerEvents;
    FakeCredentialEvents events;
    ICredentialProviderCredential* credential = nullptr;

    WatchedTile() {
        CHECK(SUCCEEDED(provider->Advise(&providerEvents, 42)));
        DWORD count = 0;
        DWORD defaultIndex = 0;
        BOOL autoLogon = FALSE;
        CHECK(SUCCEEDED(provider->GetCredentialCount(&count, &defaultIndex, &autoLogon)));
        CHECK(SUCCEEDED(provider->GetCredentialAt(0, &credential)));
        CHECK(SUCCEEDED(credential->Advise(&events)));
        BOOL selectedAutoLogon = TRUE;
        CHECK(SUCCEEDED(credential->SetSelected(&selectedAutoLogon)));
        CHECK(!selectedAutoLogon);
    }
    ~WatchedTile() {
        credential->SetDeselected();
        credential->UnAdvise();
        credential->Release();
        provider->UnAdvise();
        provider->Release();
    }
    std::wstring Hint() { return events.strings[FI_HINT]; }
    bool ShowsPin() { return events.states[FI_PIN] == CPFS_DISPLAY_IN_SELECTED_TILE; }
    bool AskedForTouch() {
        for (const std::wstring& text : events.history) {
            if (text == L"Touch your security key") {
                return true;
            }
        }
        return false;
    }
    // After the key unlocked the password, LogonUI submits the default tile automatically.
    void ExpectAutoLogon() {
        CHECK(PumpUntil([&] { return providerEvents.changes > 0; }));
        DWORD count = 0;
        DWORD defaultIndex = 99;
        BOOL autoLogon = FALSE;
        CHECK(SUCCEEDED(provider->GetCredentialCount(&count, &defaultIndex, &autoLogon)));
        CHECK_EQ(defaultIndex, 0u);
        CHECK(autoLogon);
        const SerializationResult result = Submit(credential, L"");
        CHECK(result.response == CPGSR_RETURN_CREDENTIAL_FINISHED);
        const auto* logon = reinterpret_cast<const KERB_INTERACTIVE_UNLOCK_LOGON*>(result.packed.data());
        CHECK(Unprotect(ReadPacked(result.packed, logon->Logon.Password)) == L"S3cret-Password");
        CHECK(SUCCEEDED(provider->GetCredentialCount(&count, &defaultIndex, &autoLogon)));
        CHECK(!autoLogon);
    }
};

}  // namespace

TEST(TileAsksForThePinOfTheDetectedKeyThenForTheTouch) {
    InstallFakeWithEnrolledKey(L"1234", true);
    WatchedTile tile;
    CHECK(PumpUntil([&] { return Contains(tile.Hint(), L"Enter the PIN"); }));
    CHECK(tile.ShowsPin());

    // Enter: the unlock runs in the background while the tile asks for the touch.
    const SerializationResult pending = Submit(tile.credential, L"1234");
    CHECK(pending.response == CPGSR_NO_CREDENTIAL_NOT_FINISHED);
    CHECK(pending.status.empty());
    CHECK(tile.AskedForTouch());
    tile.ExpectAutoLogon();
}

TEST(TileReportsAWrongPinAndAsksAgain) {
    InstallFakeWithEnrolledKey(L"1234", true);
    WatchedTile tile;
    CHECK(PumpUntil([&] { return tile.ShowsPin(); }));
    Submit(tile.credential, L"9999");
    CHECK(PumpUntil([&] { return Contains(tile.Hint(), L"Incorrect security key PIN"); }));
    CHECK(tile.ShowsPin());
    CHECK_EQ(tile.providerEvents.changes, 0);
}

TEST(TouchOnlyKeySignsInWithATouchAlone) {
    InstallFakeWithEnrolledKey(L"", false);
    WatchedTile tile;
    tile.ExpectAutoLogon();
    CHECK(tile.AskedForTouch());
    CHECK(!tile.ShowsPin());
}

TEST(TileFollowsThePluggedKeys) {
    FakeAuthenticator& fake = InstallFakeWithEnrolledKey(L"1234", true);
    fake.UnplugDevice(L"\\\\?\\hid#fake");
    WatchedTile tile;
    CHECK(PumpUntil([&] { return Contains(tile.Hint(), L"Plug in your security key"); }));
    CHECK(!tile.ShowsPin());

    fake.PlugDevice(L"\\\\?\\hid#fake", L"1234");
    fake.PlugDevice(L"\\\\?\\hid#other", L"5555");
    CHECK(PumpUntil([&] { return Contains(tile.Hint(), L"Leave only one plugged in"); }));
    CHECK(!tile.ShowsPin());

    fake.UnplugDevice(L"\\\\?\\hid#other");
    CHECK(PumpUntil([&] { return tile.ShowsPin(); }));
    CHECK_EQ(fake.PinAttempts(L"\\\\?\\hid#other"), 0);
}

TEST(KeyThatIsNotReadyYetIsProbedAgain) {
    // Plugged at boot: the first probes fail, the tile must not settle on "not enrolled".
    FakeAuthenticator& fake = InstallFakeWithEnrolledKey(L"", false);
    fake.FailNextExchanges(L"\\\\?\\hid#fake", 1);
    WatchedTile tile;
    tile.ExpectAutoLogon();
    CHECK(tile.AskedForTouch());
}

TEST(UnlockedTileSurvivesTheEnumerationThatFollowsCredentialsChanged) {
    // After CredentialsChanged, LogonUI may deselect and unadvise the tile, pass the users again,
    // then select it again: the unlocked password must still sign in, without another touch.
    FakeAuthenticator& fake = InstallFakeWithEnrolledKey(L"", false);
    WatchedTile tile;
    CHECK(PumpUntil([&] { return tile.providerEvents.changes > 0; }));
    const int exchanges = fake.Exchanges(L"\\\\?\\hid#fake");

    CHECK(SUCCEEDED(tile.credential->SetDeselected()));
    CHECK(SUCCEEDED(tile.credential->UnAdvise()));
    auto* users = new FakeUserArray();
    users->Add(new FakeUser(kSid, L"MYPC\\alice"));
    CHECK(SUCCEEDED(tile.provider->SetUserArray(users)));
    users->Release();

    DWORD count = 0;
    DWORD defaultIndex = 99;
    BOOL autoLogon = FALSE;
    CHECK(SUCCEEDED(tile.provider->GetCredentialCount(&count, &defaultIndex, &autoLogon)));
    CHECK_EQ(count, 1u);
    CHECK_EQ(defaultIndex, 0u);
    CHECK(autoLogon);
    ICredentialProviderCredential* again = nullptr;
    CHECK(SUCCEEDED(tile.provider->GetCredentialAt(0, &again)));
    CHECK(again == tile.credential);  // the same tile, with its unlocked password
    again->Release();
    CHECK(SUCCEEDED(tile.credential->Advise(&tile.events)));
    BOOL selectedAutoLogon = FALSE;
    CHECK(SUCCEEDED(tile.credential->SetSelected(&selectedAutoLogon)));
    CHECK(selectedAutoLogon);

    const SerializationResult result = Submit(tile.credential, L"");
    CHECK(result.response == CPGSR_RETURN_CREDENTIAL_FINISHED);
    const auto* logon = reinterpret_cast<const KERB_INTERACTIVE_UNLOCK_LOGON*>(result.packed.data());
    CHECK(Unprotect(ReadPacked(result.packed, logon->Logon.Password)) == L"S3cret-Password");
    CHECK_EQ(fake.Exchanges(L"\\\\?\\hid#fake"), exchanges);  // no second touch
    CHECK(SUCCEEDED(tile.provider->GetCredentialCount(&count, &defaultIndex, &autoLogon)));
    CHECK(!autoLogon);
}
