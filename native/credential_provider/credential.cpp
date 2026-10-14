#include "credential.h"

#include <cfgmgr32.h>

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <new>
#include <thread>
#include <vector>

#include "fields.h"
#include "guids.h"
#include "kerb_logon.h"
#include "resource.h"

#include "fidologon/device_presence.h"
#include "fidologon/errors.h"

namespace fidologon::cp {

// State shared by a tile and its watch thread. The thread may outlive the tile selection (a key
// operation cannot be interrupted): it then finds `window` cleared and reports nothing.
struct KeyWatch {
    std::mutex mutex;
    std::condition_variable wake;
    HWND window = nullptr;  // cleared by the tile when it stops watching
    bool stop = false;
    bool unlockRequested = false;
    bool devicesChanged = false;  // set by the device arrival/removal notification
    std::wstring pin;  // PIN of the requested unlock
    // Result of the last successful unlock, taken by the tile.
    std::optional<KeyMatch> match;
    std::wstring password;

    ~KeyWatch() {
        Wipe(pin);
        Wipe(password);
    }
};

namespace {

// Reports of the watch thread to the tile (wParam: KeyPresence, ErrorCode or unused).
constexpr UINT kMsgPresence = WM_APP + 1;
constexpr UINT kMsgWaitingTouch = WM_APP + 2;
constexpr UINT kMsgUnlocked = WM_APP + 3;
constexpr UINT kMsgUnlockFailed = WM_APP + 4;

constexpr wchar_t kWindowClass[] = L"FidoLogonCredentialWatch";
// Device notifications wake the watch at once; the poll is a fallback.
constexpr auto kPollInterval = std::chrono::milliseconds(1000);
// A key that just arrived may not answer yet: let it settle before talking to it.
constexpr auto kArrivalSettleDelay = std::chrono::milliseconds(300);
// A key that could not be classified (error, or no matching credential found) is probed again.
constexpr auto kRetryInterval = std::chrono::seconds(2);
// An unlocked password that LogonUI did not submit within this delay is dropped.
constexpr ULONGLONG kReadyLifetimeMs = 30'000;

// GUID_DEVINTERFACE_HID (hidclass.h).
constexpr GUID kHidInterfaceClass = {0x4D1E55B2, 0xF16F, 0x11CF, {0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30}};

constexpr wchar_t kTitleText[] = L"FIDO2 security key";
constexpr wchar_t kTouchTitleText[] = L"Touch your security key";
constexpr wchar_t kPlugKeyText[] = L"Plug in your security key.";
constexpr wchar_t kMultipleKeysText[] =
    L"Several enrolled security keys are plugged in. Leave only one plugged in.";
constexpr wchar_t kNotEnrolledText[] = L"This security key is not enrolled for this account.";
constexpr wchar_t kEnterPinText[] =
    L"Enter the PIN of your security key, then press Enter. You will then have to touch the key.";
constexpr wchar_t kTouchNowText[] = L"Touch your security key now: it is blinking.";
constexpr wchar_t kTouchTimeoutText[] =
    L"No touch detected. Unplug the security key and plug it in again to retry.";
constexpr wchar_t kSigningInText[] = L"Signing in...";

constexpr wchar_t kPasswordRejectedText[] =
    L"Windows rejected the password stored for this security key. If the account password was changed, "
    L"enroll the key again (or sign in with the password).";

constexpr wchar_t kPasswordExpiredText[] =
    L"The account password has expired. Sign in with the password to change it, then enroll the key again.";

std::uint64_t NowFileTime() {
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    return (static_cast<std::uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
}

LRESULT CALLBACK WatchWindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message >= kMsgPresence && message <= kMsgUnlockFailed) {
        auto* credential = reinterpret_cast<Credential*>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (credential != nullptr) {
            credential->OnWatchMessage(message, wParam);
        }
        return 0;
    }
    return DefWindowProcW(window, message, wParam, lParam);
}

// Module holding this code (the DLL, or the test executable that links it).
HINSTANCE CodeModule() {
    HMODULE module = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&WatchWindowProc), &module);
    return module;
}

HWND CreateWatchWindow(Credential* credential) {
    // Registered once per DLL load; UnregisterWatchWindowClass removes it when the DLL unloads.
    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.lpfnWndProc = WatchWindowProc;
    windowClass.hInstance = CodeModule();
    windowClass.lpszClassName = kWindowClass;
    if (RegisterClassExW(&windowClass) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return nullptr;
    }
    HWND window = CreateWindowExW(0, kWindowClass, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, CodeModule(),
                                  nullptr);
    if (window != nullptr) {
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(credential));
    }
    return window;
}

void Post(KeyWatch& watch, UINT message, WPARAM wParam = 0) {
    std::lock_guard lock(watch.mutex);
    if (watch.window != nullptr) {
        PostMessageW(watch.window, message, wParam, 0);
    }
}

// Unlocks the password and keeps it for GetSerialization; reports the outcome to the tile.
void Unlock(KeyWatch& watch, const std::vector<KeyRecord>& records, const std::optional<KeyMatch>& known,
            const std::wstring& pin, bool& touchTimedOut) {
    try {
        std::optional<KeyMatch> match = known;
        if (!match) {
            match = FindEnrolledKey(records, &pin);  // no touch: silent probe or PIN check
        }
        if (!match) {
            throw Error(ErrorCode::NoDevice);
        }
        Post(watch, kMsgWaitingTouch);
        std::wstring password = UnlockPassword(*match, pin);
        WipeOnExit wipePassword(password);
        {
            std::lock_guard lock(watch.mutex);
            watch.match = std::move(match);
            Wipe(watch.password);
            watch.password = password;
        }
        Post(watch, kMsgUnlocked);
    } catch (const Error& e) {
        DebugLog(L"FidoLogon: unlock failed (%d): %hs", static_cast<int>(e.code()), e.what());
        touchTimedOut = e.code() == ErrorCode::Timeout;
        Post(watch, kMsgUnlockFailed, static_cast<WPARAM>(e.code()));
    } catch (const std::exception& e) {
        DebugLog(L"FidoLogon: unexpected unlock error: %hs", e.what());
        Post(watch, kMsgUnlockFailed, static_cast<WPARAM>(ErrorCode::Internal));
    }
}

DWORD CALLBACK OnHidInterfaceChange(HCMNOTIFICATION, PVOID context, CM_NOTIFY_ACTION action,
                                    PCM_NOTIFY_EVENT_DATA, DWORD) {
    if (action == CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL || action == CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL) {
        auto* watch = static_cast<KeyWatch*>(context);
        {
            std::lock_guard lock(watch->mutex);
            watch->devicesChanged = true;
        }
        watch->wake.notify_all();
    }
    return ERROR_SUCCESS;
}

void WatchKeys(std::shared_ptr<KeyWatch> watch, std::wstring userSid) {
    // Wakes the loop as soon as a HID device comes or goes (the shared_ptr outlives the
    // registration, which is removed before the thread ends).
    HCMNOTIFICATION notification = nullptr;
    CM_NOTIFY_FILTER filter{};
    filter.cbSize = sizeof(filter);
    filter.FilterType = CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE;
    filter.u.DeviceInterface.ClassGuid = kHidInterfaceClass;
    if (CM_Register_Notification(&filter, watch.get(), OnHidInterfaceChange, &notification) != CR_SUCCESS) {
        notification = nullptr;  // the poll still notices the change
    }

    std::vector<KeyRecord> records;
    try {
        records = RecordStore::OpenDefault().ListForUser(userSid);
    } catch (const std::exception& e) {
        DebugLog(L"FidoLogon: cannot read enrolled keys: %hs", e.what());
    }

    std::vector<std::wstring> knownPaths;
    bool first = true;
    bool touchTimedOut = false;  // do not wait again for the same plugged key
    bool retryDetection = false;  // the plugged key could not be classified yet
    auto lastDetection = std::chrono::steady_clock::now();
    for (;;) {
        std::wstring pin;
        bool unlock = false;
        bool arrival = false;
        {
            std::unique_lock lock(watch->mutex);
            if (!first) {
                watch->wake.wait_for(lock, kPollInterval, [&] {
                    return watch->stop || watch->unlockRequested || watch->devicesChanged;
                });
            }
            if (watch->stop) {
                break;
            }
            arrival = watch->devicesChanged;
            watch->devicesChanged = false;
            if (watch->unlockRequested) {
                watch->unlockRequested = false;
                unlock = true;
                pin = std::move(watch->pin);
                watch->pin.clear();
            }
        }
        WipeOnExit wipePin(pin);
        if (unlock) {
            Unlock(*watch, records, std::nullopt, pin, touchTimedOut);
            continue;
        }

        if (arrival) {
            std::this_thread::sleep_for(kArrivalSettleDelay);
        }
        std::vector<std::wstring> paths;
        try {
            paths = ListMatchingDevicePaths(records);
        } catch (const std::exception&) {
            // enumeration failure: treated as no key, retried at the next poll
        }
        const bool changed = first || paths != knownPaths;
        const bool retryDue =
            retryDetection && std::chrono::steady_clock::now() - lastDetection >= kRetryInterval;
        if (!changed && !retryDue) {
            continue;
        }
        first = false;
        if (changed) {
            knownPaths = paths;
            touchTimedOut = false;
        }

        // A key that does not answer yet (just plugged, or present at boot before it is ready)
        // must not be reported as not enrolled for good: it is probed again until it is classified.
        PresenceResult presence;
        lastDetection = std::chrono::steady_clock::now();
        try {
            presence = DetectEnrolledKey(records);
            retryDetection = presence.presence == KeyPresence::NotEnrolled;
        } catch (const std::exception& e) {
            DebugLog(L"FidoLogon: key detection failed: %hs", e.what());
            retryDetection = !paths.empty();
        }
        Post(*watch, kMsgPresence, static_cast<WPARAM>(presence.presence));
        if (presence.presence == KeyPresence::TouchOnly && !touchTimedOut) {
            Unlock(*watch, records, presence.match, L"", touchTimedOut);
        }
    }
    if (notification != nullptr) {
        CM_Unregister_Notification(notification);
    }
    DllRelease();
}

struct WatchStart {
    HMODULE module = nullptr;  // reference held by the thread, released as it exits
    std::shared_ptr<KeyWatch> watch;
    std::wstring userSid;
};

// The thread holds its own reference on the module: LogonUI may free the DLL as soon as
// DllCanUnloadNow allows it, and the end of the thread still runs code of the DLL. The reference
// is released by FreeLibraryAndExitThread, which does not return into the module.
DWORD WINAPI WatchThread(void* parameter) {
    HMODULE module = nullptr;
    {
        std::unique_ptr<WatchStart> start(static_cast<WatchStart*>(parameter));
        module = start->module;
        WatchKeys(std::move(start->watch), std::move(start->userSid));
    }
    FreeLibraryAndExitThread(module, 0);
}

void DestroyWatchWindow(HWND window) {
    // Detach first: a window of another thread cannot be destroyed from here, but it must never
    // call back into a deleted tile.
    SetWindowLongPtrW(window, GWLP_USERDATA, 0);
    DestroyWindow(window);
}

}  // namespace

void UnregisterWatchWindowClass() noexcept { UnregisterClassW(kWindowClass, CodeModule()); }

Credential::Credential(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, std::wstring userSid,
                       std::wstring qualifiedUserName)
    : scenario_(scenario), userSid_(std::move(userSid)), qualifiedUserName_(std::move(qualifiedUserName)) {
    DllAddRef();
}

Credential::~Credential() {
    StopWatch();
    if (window_ != nullptr) {
        DestroyWatchWindow(window_);
    }
    ClearPin();
    ClearReady();
    if (events_ != nullptr) {
        events_->Release();
    }
    DllRelease();
}

IFACEMETHODIMP Credential::QueryInterface(REFIID riid, void** ppv) {
    if (ppv == nullptr) {
        return E_POINTER;
    }
    if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredential ||
        riid == IID_ICredentialProviderCredential2 || riid == __uuidof(ICredentialProviderCredential3)) {
        *ppv = static_cast<ICredentialProviderCredential3*>(this);
    } else if (riid == IID_ICredentialProviderCredentialWithFieldOptions) {
        *ppv = static_cast<ICredentialProviderCredentialWithFieldOptions*>(this);
    } else {
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    AddRef();
    return S_OK;
}

IFACEMETHODIMP_(ULONG) Credential::AddRef() { return static_cast<ULONG>(InterlockedIncrement(&refs_)); }

IFACEMETHODIMP_(ULONG) Credential::Release() {
    const LONG refs = InterlockedDecrement(&refs_);
    if (refs == 0) {
        delete this;
    }
    return static_cast<ULONG>(refs);
}

IFACEMETHODIMP Credential::Advise(ICredentialProviderCredentialEvents* events) {
    if (events_ != nullptr) {
        events_->Release();
    }
    events_ = events;
    if (events_ != nullptr) {
        events_->AddRef();
        if (window_ == nullptr) {
            window_ = CreateWatchWindow(this);  // on the LogonUI thread, which pumps its messages
        }
    }
    return S_OK;
}

IFACEMETHODIMP Credential::UnAdvise() {
    StopWatch();
    if (window_ != nullptr) {
        DestroyWatchWindow(window_);  // on the LogonUI thread, which created it
        window_ = nullptr;
    }
    if (events_ != nullptr) {
        events_->Release();
        events_ = nullptr;
    }
    return S_OK;
}

IFACEMETHODIMP Credential::SetSelected(BOOL* autoLogon) {
    if (autoLogon == nullptr) {
        return E_POINTER;
    }
    // Selected again while an unlocked password waits (LogonUI enumerated the tiles again after
    // CredentialsChanged): sign in right away instead of asking for the key once more.
    *autoLogon = IsReady() ? TRUE : FALSE;
    if (!*autoLogon) {
        StartWatch();
    }
    return S_OK;
}

IFACEMETHODIMP Credential::SetDeselected() {
    StopWatch();
    ClearPin();
    return S_OK;
}

void Credential::StartWatch() {
    if (events_ == nullptr || window_ == nullptr || watch_ != nullptr) {
        return;  // synchronous mode (no LogonUI events) or already watching
    }
    auto watch = std::make_shared<KeyWatch>();
    watch->window = window_;
    auto start = std::make_unique<WatchStart>();
    start->watch = watch;
    start->userSid = userSid_;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(&WatchThread),
                            &start->module)) {
        DebugLog(L"FidoLogon: cannot reference the module for the key watch (%lu)", GetLastError());
        return;
    }
    DllAddRef();  // released by the thread
    HANDLE thread = CreateThread(nullptr, 0, WatchThread, start.get(), 0, nullptr);
    if (thread == nullptr) {
        DebugLog(L"FidoLogon: cannot start the key watch (%lu)", GetLastError());
        DllRelease();
        FreeLibrary(start->module);
        return;
    }
    start.release();  // owned by the thread
    CloseHandle(thread);
    watch_ = std::move(watch);
    SetTile(TileState::PlugKey, kPlugKeyText);
}

void Credential::StopWatch() {
    if (watch_ != nullptr) {
        {
            std::lock_guard lock(watch_->mutex);
            watch_->stop = true;
            watch_->window = nullptr;
            Wipe(watch_->password);
            watch_->match.reset();
        }
        watch_->wake.notify_all();
        watch_.reset();
    }
    if (window_ != nullptr) {
        // Drop reports already queued by the stopped thread.
        MSG message;
        while (PeekMessageW(&message, window_, kMsgPresence, kMsgUnlockFailed, PM_REMOVE)) {
        }
    }
    tile_ = TileState::Idle;
}

bool Credential::IsReady() const noexcept {
    return readyMatch_.has_value() && GetTickCount64() - readyAt_ < kReadyLifetimeMs;
}

void Credential::ClearReady() {
    readyMatch_.reset();
    Wipe(readyPassword_);
    readyPassword_.clear();
}

void Credential::SetTile(TileState state, std::wstring hint) {
    tile_ = state;
    hint_ = std::move(hint);
    ApplyTile();
}

void Credential::ApplyTile() {
    if (events_ == nullptr) {
        return;
    }
    const bool askPin = tile_ == TileState::EnterPin;
    events_->SetFieldString(this, FI_TITLE, tile_ == TileState::WaitingTouch ? kTouchTitleText : kTitleText);
    events_->SetFieldString(this, FI_HINT, hint_.c_str());
    events_->SetFieldState(this, FI_PIN, askPin ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN);
    events_->SetFieldState(this, FI_SUBMIT, askPin ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN);
    if (askPin) {
        events_->SetFieldInteractiveState(this, FI_PIN, CPFIS_FOCUSED);
    }
}

void Credential::OnWatchMessage(UINT message, WPARAM wParam) {
    if (watch_ == nullptr) {
        return;  // report of a stopped watch
    }
    switch (message) {
        case kMsgPresence:
            switch (static_cast<KeyPresence>(wParam)) {
                case KeyPresence::None:
                    SetTile(TileState::PlugKey, kPlugKeyText);
                    break;
                case KeyPresence::Multiple:
                    SetTile(TileState::MultipleKeys, kMultipleKeysText);
                    break;
                case KeyPresence::NotEnrolled:
                    SetTile(TileState::NotEnrolled, kNotEnrolledText);
                    break;
                case KeyPresence::PinNeeded:
                    SetTile(TileState::EnterPin, kEnterPinText);
                    break;
                case KeyPresence::TouchOnly:
                    break;  // followed by kMsgWaitingTouch
            }
            break;
        case kMsgWaitingTouch:
            SetTile(TileState::WaitingTouch, kTouchNowText);
            break;
        case kMsgUnlocked: {
            // Kept by the tile, not the watch: LogonUI may unadvise or deselect the tile before
            // it asks for the serialization.
            ClearReady();
            {
                std::lock_guard lock(watch_->mutex);
                readyMatch_ = std::move(watch_->match);
                watch_->match.reset();
                readyPassword_ = std::move(watch_->password);
                watch_->password.clear();
            }
            if (!readyMatch_) {
                break;
            }
            readyAt_ = GetTickCount64();
            SetTile(TileState::Ready, kSigningInText);
            if (onReady_) {
                onReady_();
            }
            break;
        }
        case kMsgUnlockFailed:
            OnUnlockFailed(static_cast<ErrorCode>(wParam));
            break;
        default:
            break;
    }
}

void Credential::OnUnlockFailed(ErrorCode code) {
    switch (code) {
        case ErrorCode::Timeout:
            SetTile(TileState::NotEnrolled, kTouchTimeoutText);
            break;
        case ErrorCode::PinInvalid:
        case ErrorCode::PinRequired:
            SetTile(TileState::EnterPin, std::wstring(DescribeError(code)) + L" " + kEnterPinText);
            break;
        case ErrorCode::MultipleDevices:
            SetTile(TileState::MultipleKeys, kMultipleKeysText);
            break;
        default:
            SetTile(TileState::NotEnrolled, DescribeError(code));
            break;
    }
}

void Credential::ClearPin() {
    Wipe(pin_);
    if (events_ != nullptr) {
        events_->SetFieldString(this, FI_PIN, L"");
    }
}

IFACEMETHODIMP Credential::GetFieldState(DWORD fieldId, CREDENTIAL_PROVIDER_FIELD_STATE* state,
                                         CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactiveState) {
    if (fieldId >= FI_COUNT || state == nullptr || interactiveState == nullptr) {
        return E_INVALIDARG;
    }
    *state = kFields[fieldId].state;
    *interactiveState = kFields[fieldId].interactiveState;
    // While watching, the PIN and the submit button only show when a PIN is needed.
    if (watch_ != nullptr && (fieldId == FI_PIN || fieldId == FI_SUBMIT) && tile_ != TileState::EnterPin) {
        *state = CPFS_HIDDEN;
    }
    return S_OK;
}

IFACEMETHODIMP Credential::GetStringValue(DWORD fieldId, PWSTR* value) {
    if (value == nullptr) {
        return E_POINTER;
    }
    *value = nullptr;
    switch (fieldId) {
        case FI_LABEL:
            return CoTaskStrDup(kFields[fieldId].label, value);
        case FI_TITLE:
            return CoTaskStrDup(tile_ == TileState::WaitingTouch ? kTouchTitleText : kTitleText, value);
        case FI_HINT:
            return CoTaskStrDup(watch_ != nullptr ? hint_ : std::wstring(kHintText), value);
        case FI_PIN:
            return CoTaskStrDup(pin_, value);
        default:
            return E_INVALIDARG;
    }
}

IFACEMETHODIMP Credential::GetBitmapValue(DWORD fieldId, HBITMAP* bitmap) {
    if (bitmap == nullptr) {
        return E_POINTER;
    }
    *bitmap = nullptr;
    if (fieldId != FI_TILE_IMAGE) {
        return E_INVALIDARG;
    }
    // DIB section: keeps the alpha channel of the white glyph (LoadBitmap would drop it).
    *bitmap = static_cast<HBITMAP>(
        LoadImageW(g_moduleInstance, MAKEINTRESOURCEW(IDB_TILE_IMAGE), IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION));
    return *bitmap != nullptr ? S_OK : HRESULT_FROM_WIN32(GetLastError());
}

IFACEMETHODIMP Credential::GetBitmapBufferValue(DWORD fieldId, DWORD* size, BYTE** buffer) {
    if (size == nullptr || buffer == nullptr) {
        return E_POINTER;
    }
    *size = 0;
    *buffer = nullptr;
    if (fieldId != FI_TILE_IMAGE) {
        return E_INVALIDARG;
    }
    HRSRC resource = FindResourceW(g_moduleInstance, MAKEINTRESOURCEW(IDR_TILE_IMAGE_PNG), RT_RCDATA);
    HGLOBAL loaded = resource != nullptr ? LoadResource(g_moduleInstance, resource) : nullptr;
    const void* data = loaded != nullptr ? LockResource(loaded) : nullptr;
    const DWORD length = resource != nullptr ? SizeofResource(g_moduleInstance, resource) : 0;
    if (data == nullptr || length == 0) {
        return HRESULT_FROM_WIN32(ERROR_RESOURCE_DATA_NOT_FOUND);
    }
    *buffer = static_cast<BYTE*>(CoTaskMemAlloc(length));
    if (*buffer == nullptr) {
        return E_OUTOFMEMORY;
    }
    memcpy(*buffer, data, length);
    *size = length;
    return S_OK;
}

IFACEMETHODIMP Credential::GetCheckboxValue(DWORD, BOOL*, PWSTR*) { return E_NOTIMPL; }

IFACEMETHODIMP Credential::GetSubmitButtonValue(DWORD fieldId, DWORD* adjacentTo) {
    if (adjacentTo == nullptr) {
        return E_POINTER;
    }
    if (fieldId != FI_SUBMIT) {
        return E_INVALIDARG;
    }
    *adjacentTo = FI_PIN;
    return S_OK;
}

IFACEMETHODIMP Credential::GetComboBoxValueCount(DWORD, DWORD*, DWORD*) { return E_NOTIMPL; }

IFACEMETHODIMP Credential::GetComboBoxValueAt(DWORD, DWORD, PWSTR*) { return E_NOTIMPL; }

IFACEMETHODIMP Credential::SetStringValue(DWORD fieldId, PCWSTR value) {
    if (fieldId != FI_PIN) {
        return E_INVALIDARG;
    }
    Wipe(pin_);
    pin_ = value != nullptr ? value : L"";
    return S_OK;
}

IFACEMETHODIMP Credential::SetCheckboxValue(DWORD, BOOL) { return E_NOTIMPL; }

IFACEMETHODIMP Credential::SetComboBoxSelectedValue(DWORD, DWORD) { return E_NOTIMPL; }

IFACEMETHODIMP Credential::CommandLinkClicked(DWORD) { return E_NOTIMPL; }

IFACEMETHODIMP Credential::GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
                                            CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization,
                                            PWSTR* statusText, CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) {
    if (response == nullptr || serialization == nullptr || statusText == nullptr || statusIcon == nullptr) {
        return E_POINTER;
    }
    *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *statusText = nullptr;
    *statusIcon = CPSI_NONE;
    ZeroMemory(serialization, sizeof(*serialization));

    // Auto logon after the key unlocked the password.
    if (IsReady()) {
        const KeyMatch match = std::move(*readyMatch_);
        std::wstring password = std::move(readyPassword_);
        WipeOnExit wipePassword(password);
        ClearReady();
        const HRESULT hr = Serialize(match, password, response, serialization);
        if (watch_ != nullptr) {
            SetTile(TileState::PlugKey, kPlugKeyText);
        }
        return hr;
    }
    ClearReady();  // expired

    if (watch_ == nullptr) {
        return SignInNow(response, serialization, statusText, statusIcon);
    }

    // Enter on the PIN field: unlock in the background while the tile asks for the touch.
    if (tile_ != TileState::EnterPin) {
        return S_OK;
    }
    if (pin_.empty()) {
        *statusIcon = CPSI_ERROR;
        return CoTaskStrDup(DescribeError(ErrorCode::PinRequired), statusText);
    }
    {
        std::lock_guard lock(watch_->mutex);
        Wipe(watch_->pin);
        watch_->pin = pin_;
        watch_->unlockRequested = true;
    }
    watch_->wake.notify_all();
    ClearPin();
    SetTile(TileState::WaitingTouch, kTouchNowText);
    return S_OK;
}

HRESULT Credential::SignInNow(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
                              CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization, PWSTR* statusText,
                              CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) {
    std::wstring pin = pin_;
    WipeOnExit wipePin(pin);
    ClearPin();

    try {
        const std::vector<KeyRecord> records = RecordStore::OpenDefault().ListForUser(userSid_);
        if (records.empty()) {
            throw Error(ErrorCode::NotFound, "no key enrolled for this account");
        }
        const std::optional<KeyMatch> match = FindEnrolledKey(records, &pin);
        if (!match) {
            throw Error(ErrorCode::NoDevice);
        }
        std::wstring password = UnlockPassword(*match, pin);
        WipeOnExit wipePassword(password);
        return Serialize(*match, password, response, serialization);
    } catch (const Error& e) {
        DebugLog(L"FidoLogon: sign-in failed (%d): %hs", static_cast<int>(e.code()), e.what());
        const wchar_t* text = e.code() == ErrorCode::NotFound ? L"No security key is enrolled for this account."
                                                              : DescribeError(e.code());
        *statusIcon = CPSI_ERROR;
        return CoTaskStrDup(text, statusText);
    } catch (const std::bad_alloc&) {
        return E_OUTOFMEMORY;
    } catch (const std::exception& e) {
        DebugLog(L"FidoLogon: unexpected error: %hs", e.what());
        *statusIcon = CPSI_ERROR;
        return CoTaskStrDup(DescribeError(ErrorCode::Internal), statusText);
    }
}

HRESULT Credential::Serialize(const KeyMatch& match, const std::wstring& password,
                              CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
                              CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization) {
    try {
        std::wstring domain;
        std::wstring user;
        SplitQualifiedName(qualifiedUserName_, domain, user);

        std::wstring protectedPassword;
        WipeOnExit wipeProtected(protectedPassword);
        HRESULT hr = ProtectPasswordIfNeeded(password, protectedPassword);
        if (FAILED(hr)) {
            return hr;
        }

        std::vector<BYTE> packed;
        hr = PackInteractiveLogon(scenario_, domain, user, protectedPassword, packed);
        if (FAILED(hr)) {
            return hr;
        }
        WipeOnExit wipePacked(packed);

        ULONG package = 0;
        hr = LookupNegotiatePackage(&package);
        if (FAILED(hr)) {
            return hr;
        }

        auto* buffer = static_cast<BYTE*>(CoTaskMemAlloc(packed.size()));
        if (buffer == nullptr) {
            return E_OUTOFMEMORY;
        }
        memcpy(buffer, packed.data(), packed.size());

        try {
            DWORD sessionId = 0;
            ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
            // The arrival time is read now, while the key that signed in is plugged: the service
            // then notices a key swapped before it binds the session (or before it restarts).
            RecordStore::OpenDefault().WriteLastAuth(LastAuth{userSid_, match.device.path, match.record.id,
                                                              NowFileTime(), sessionId,
                                                              HidDeviceArrivalTime(match.device.path)});
        } catch (const std::exception& e) {
            // Logon must still work; only the lock-on-removal binding is lost.
            DebugLog(L"FidoLogon: WriteLastAuth failed: %hs", e.what());
        }

        serialization->ulAuthenticationPackage = package;
        serialization->clsidCredentialProvider = CLSID_FidoLogonProvider;
        serialization->rgbSerialization = buffer;
        serialization->cbSerialization = static_cast<ULONG>(packed.size());
        *response = CPGSR_RETURN_CREDENTIAL_FINISHED;
        return S_OK;
    } catch (const std::bad_alloc&) {
        return E_OUTOFMEMORY;
    }
}

IFACEMETHODIMP Credential::ReportResult(NTSTATUS status, NTSTATUS subStatus, PWSTR* statusText,
                                        CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) {
    if (statusText == nullptr || statusIcon == nullptr) {
        return E_POINTER;
    }
    *statusText = nullptr;
    *statusIcon = CPSI_NONE;
    if (status >= 0) {
        return S_OK;
    }

    // The logon failed after we released credentials: drop the pending session binding.
    try {
        RecordStore::OpenDefault().ClearLastAuth();
    } catch (const std::exception&) {
    }

    const bool wrongPassword = status == STATUS_LOGON_FAILURE &&
                               (subStatus == STATUS_WRONG_PASSWORD || subStatus == STATUS_SUCCESS);
    const bool expired = status == STATUS_PASSWORD_EXPIRED || status == STATUS_PASSWORD_MUST_CHANGE ||
                         subStatus == STATUS_PASSWORD_EXPIRED || subStatus == STATUS_PASSWORD_MUST_CHANGE;
    if (wrongPassword) {
        *statusIcon = CPSI_ERROR;
        return CoTaskStrDup(kPasswordRejectedText, statusText);
    }
    if (expired) {
        *statusIcon = CPSI_WARNING;
        return CoTaskStrDup(kPasswordExpiredText, statusText);
    }
    return S_OK;  // let Windows display its own message (account locked, disabled, ...)
}

IFACEMETHODIMP Credential::GetUserSid(PWSTR* sid) {
    if (sid == nullptr) {
        return E_POINTER;
    }
    return CoTaskStrDup(userSid_, sid);
}

IFACEMETHODIMP Credential::GetFieldOptions(DWORD fieldId, CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS* options) {
    if (options == nullptr) {
        return E_POINTER;
    }
    // No reveal button: the PIN must not be readable over the user's shoulder.
    *options = fieldId == FI_PIN ? CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE
                                 : CPCFO_NONE;
    return S_OK;
}

}  // namespace fidologon::cp
