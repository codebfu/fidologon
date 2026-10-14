// DLL entry points: COM class factory and self-registration (used by the
// development install script; the MSI writes the same registry entries).

#include "common.h"

#include <new>

#include "credential.h"
#include "filter.h"
#include "guids.h"
#include "provider.h"

HINSTANCE g_moduleInstance = nullptr;

namespace {

LONG g_dllRefs = 0;

constexpr wchar_t kProviderClsid[] = L"{FAAD8F12-6991-448B-BF78-892ED3E6A76B}";
constexpr wchar_t kFilterClsid[] = L"{0D55732F-293A-41B1-90F3-D260B9C8EF94}";
constexpr wchar_t kProvidersKey[] =
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\";
constexpr wchar_t kFiltersKey[] =
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters\\";

enum class ClassKind { Provider, Filter };

class ClassFactory final : public IClassFactory {
public:
    explicit ClassFactory(ClassKind kind) : kind_(kind) { DllAddRef(); }

    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (ppv == nullptr) {
            return E_POINTER;
        }
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    IFACEMETHODIMP_(ULONG) AddRef() override { return static_cast<ULONG>(InterlockedIncrement(&refs_)); }

    IFACEMETHODIMP_(ULONG) Release() override {
        const LONG refs = InterlockedDecrement(&refs_);
        if (refs == 0) {
            delete this;
        }
        return static_cast<ULONG>(refs);
    }

    IFACEMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override {
        if (ppv == nullptr) {
            return E_POINTER;
        }
        *ppv = nullptr;
        if (outer != nullptr) {
            return CLASS_E_NOAGGREGATION;
        }
        if (kind_ == ClassKind::Provider) {
            auto* provider = new (std::nothrow) fidologon::cp::Provider();
            if (provider == nullptr) {
                return E_OUTOFMEMORY;
            }
            const HRESULT hr = provider->QueryInterface(riid, ppv);
            provider->Release();
            return hr;
        }
        auto* filter = new (std::nothrow) fidologon::cp::PasswordFilter();
        if (filter == nullptr) {
            return E_OUTOFMEMORY;
        }
        const HRESULT hr = filter->QueryInterface(riid, ppv);
        filter->Release();
        return hr;
    }

    IFACEMETHODIMP LockServer(BOOL lock) override {
        lock ? DllAddRef() : DllRelease();
        return S_OK;
    }

private:
    ~ClassFactory() { DllRelease(); }

    LONG refs_ = 1;
    ClassKind kind_;
};

HRESULT SetStringValue(HKEY root, const std::wstring& subkey, const wchar_t* name, const std::wstring& value) {
    const LSTATUS status =
        RegSetKeyValueW(root, subkey.c_str(), name, REG_SZ, value.c_str(),
                        static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
    return HRESULT_FROM_WIN32(status);
}

}  // namespace

void DllAddRef() noexcept { InterlockedIncrement(&g_dllRefs); }

void DllRelease() noexcept { InterlockedDecrement(&g_dllRefs); }

BOOL APIENTRY DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_moduleInstance = instance;
        DisableThreadLibraryCalls(instance);
    } else if (reason == DLL_PROCESS_DETACH) {
        fidologon::cp::UnregisterWatchWindowClass();
    }
    return TRUE;
}

STDAPI DllCanUnloadNow() { return g_dllRefs > 0 ? S_FALSE : S_OK; }

STDAPI DllGetClassObject(REFCLSID clsid, REFIID riid, void** ppv) {
    if (ppv == nullptr) {
        return E_POINTER;
    }
    *ppv = nullptr;
    ClassKind kind;
    if (IsEqualCLSID(clsid, CLSID_FidoLogonProvider)) {
        kind = ClassKind::Provider;
    } else if (IsEqualCLSID(clsid, CLSID_FidoLogonFilter)) {
        kind = ClassKind::Filter;
    } else {
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    auto* factory = new (std::nothrow) ClassFactory(kind);
    if (factory == nullptr) {
        return E_OUTOFMEMORY;
    }
    const HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}

STDAPI DllRegisterServer() {
    wchar_t modulePath[MAX_PATH];
    if (GetModuleFileNameW(g_moduleInstance, modulePath, ARRAYSIZE(modulePath)) == 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    const std::pair<const wchar_t*, const wchar_t*> classes[] = {
        {kProviderClsid, L"FidoLogon Credential Provider"},
        {kFilterClsid, L"FidoLogon Credential Provider Filter"},
    };
    for (const auto& [clsid, name] : classes) {
        const std::wstring classKey = std::wstring(L"CLSID\\") + clsid;
        HRESULT hr = SetStringValue(HKEY_CLASSES_ROOT, classKey, nullptr, name);
        if (SUCCEEDED(hr)) {
            hr = SetStringValue(HKEY_CLASSES_ROOT, classKey + L"\\InprocServer32", nullptr, modulePath);
        }
        if (SUCCEEDED(hr)) {
            hr = SetStringValue(HKEY_CLASSES_ROOT, classKey + L"\\InprocServer32", L"ThreadingModel", L"Apartment");
        }
        if (FAILED(hr)) {
            return hr;
        }
    }
    HRESULT hr = SetStringValue(HKEY_LOCAL_MACHINE, std::wstring(kProvidersKey) + kProviderClsid, nullptr,
                                L"FidoLogon Credential Provider");
    if (SUCCEEDED(hr)) {
        hr = SetStringValue(HKEY_LOCAL_MACHINE, std::wstring(kFiltersKey) + kFilterClsid, nullptr,
                            L"FidoLogon Credential Provider Filter");
    }
    return hr;
}

STDAPI DllUnregisterServer() {
    // Remove the filter first so a half-finished unregistration never hides passwords.
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, (std::wstring(kFiltersKey) + kFilterClsid).c_str());
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, (std::wstring(kProvidersKey) + kProviderClsid).c_str());
    RegDeleteTreeW(HKEY_CLASSES_ROOT, (std::wstring(L"CLSID\\") + kFilterClsid).c_str());
    RegDeleteTreeW(HKEY_CLASSES_ROOT, (std::wstring(L"CLSID\\") + kProviderClsid).c_str());
    return S_OK;
}
