#pragma once

#include "common.h"

#include <functional>
#include <memory>

#include "fidologon/enrollment.h"
#include "fidologon/errors.h"

namespace fidologon::cp {

struct KeyWatch;

// Undocumented extension of ICredentialProviderCredential2 (Windows 10 and later LogonUI, see
// credprovhost.dll): the tile image is passed as an encoded image (PNG) instead of an HBITMAP,
// which keeps its transparency. Hosts that do not know it call GetBitmapValue.
MIDL_INTERFACE("64A5010E-4363-41F8-9738-19045C20DABC")
ICredentialProviderCredential3 : public ICredentialProviderCredential2 {
public:
    // Returns a CoTaskMemAlloc'ed buffer the caller frees.
    virtual HRESULT STDMETHODCALLTYPE GetBitmapBufferValue(DWORD fieldId, DWORD* size, BYTE** buffer) = 0;
};

// Called when the DLL unloads (window classes of a DLL are not removed automatically).
void UnregisterWatchWindowClass() noexcept;

// One "FIDO2 security key" sign-in option attached to one Windows user tile.
//
// Once LogonUI advises the tile and selects it, a background thread watches the plugged keys
// (HID enumeration, once a second) and adapts the tile: it asks to plug in a key, to leave only
// one key, or for the PIN, and waits for the touch of a touch-only key right away. Every wait for
// a touch is announced on the tile. The thread reports to a message-only window owned by the
// LogonUI thread, which updates the fields; when the key unlocked the password, the provider
// asks LogonUI to submit this tile (auto logon). Without advise (tests), GetSerialization does
// the whole sign-in synchronously.
class Credential final : public ICredentialProviderCredential3, public ICredentialProviderCredentialWithFieldOptions {
public:
    Credential(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, std::wstring userSid, std::wstring qualifiedUserName);

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* events) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP SetSelected(BOOL* autoLogon) override;
    IFACEMETHODIMP SetDeselected() override;
    IFACEMETHODIMP GetFieldState(DWORD fieldId, CREDENTIAL_PROVIDER_FIELD_STATE* state,
                                 CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactiveState) override;
    IFACEMETHODIMP GetStringValue(DWORD fieldId, PWSTR* value) override;
    IFACEMETHODIMP GetBitmapValue(DWORD fieldId, HBITMAP* bitmap) override;
    IFACEMETHODIMP GetCheckboxValue(DWORD fieldId, BOOL* checked, PWSTR* label) override;
    IFACEMETHODIMP GetSubmitButtonValue(DWORD fieldId, DWORD* adjacentTo) override;
    IFACEMETHODIMP GetComboBoxValueCount(DWORD fieldId, DWORD* count, DWORD* selected) override;
    IFACEMETHODIMP GetComboBoxValueAt(DWORD fieldId, DWORD item, PWSTR* value) override;
    IFACEMETHODIMP SetStringValue(DWORD fieldId, PCWSTR value) override;
    IFACEMETHODIMP SetCheckboxValue(DWORD fieldId, BOOL checked) override;
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD fieldId, DWORD selected) override;
    IFACEMETHODIMP CommandLinkClicked(DWORD fieldId) override;
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
                                    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization,
                                    PWSTR* statusText, CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override;
    IFACEMETHODIMP ReportResult(NTSTATUS status, NTSTATUS subStatus, PWSTR* statusText,
                                CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override;

    // ICredentialProviderCredential2
    IFACEMETHODIMP GetUserSid(PWSTR* sid) override;

    // ICredentialProviderCredential3
    IFACEMETHODIMP GetBitmapBufferValue(DWORD fieldId, DWORD* size, BYTE** buffer) override;

    // ICredentialProviderCredentialWithFieldOptions
    IFACEMETHODIMP GetFieldOptions(DWORD fieldId, CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS* options) override;

    const std::wstring& userSid() const noexcept { return userSid_; }

    // Called (on the LogonUI thread) when the key unlocked the password: the provider then asks
    // LogonUI to submit this tile. Cleared by the provider before it releases the tile.
    void SetReadyCallback(std::function<void()> callback) { onReady_ = std::move(callback); }
    // True while an unlocked password waits for GetSerialization. It survives the UnAdvise /
    // Advise and deselect / select cycles LogonUI runs when it enumerates the tiles again.
    bool IsReady() const noexcept;

    // Handles a report of the watch thread (message window procedure, LogonUI thread).
    void OnWatchMessage(UINT message, WPARAM wParam);

private:
    enum class TileState { Idle, PlugKey, MultipleKeys, NotEnrolled, EnterPin, WaitingTouch, Ready };

    ~Credential();
    void ClearPin();
    void StartWatch();
    void StopWatch();
    void SetTile(TileState state, std::wstring hint);
    void ApplyTile();
    void OnUnlockFailed(ErrorCode code);
    void ClearReady();
    HRESULT Serialize(const KeyMatch& match, const std::wstring& password,
                      CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
                      CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization);
    HRESULT SignInNow(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
                      CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization, PWSTR* statusText,
                      CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon);

    LONG refs_ = 1;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_;
    std::wstring userSid_;
    std::wstring qualifiedUserName_;
    std::wstring pin_;
    ICredentialProviderCredentialEvents* events_ = nullptr;
    HWND window_ = nullptr;
    std::shared_ptr<KeyWatch> watch_;
    std::function<void()> onReady_;
    TileState tile_ = TileState::Idle;
    std::wstring hint_;
    // Unlocked credential waiting for GetSerialization (see IsReady).
    std::optional<KeyMatch> readyMatch_;
    std::wstring readyPassword_;
    ULONGLONG readyAt_ = 0;
};

}  // namespace fidologon::cp
