#pragma once

#include <credentialprovider.h>
#include <shlguid.h>

// Fields of the FidoLogon credential tile, in display order.
enum FieldId : DWORD {
    FI_TILE_IMAGE = 0,  // provider logo shown in "Sign-in options"
    FI_LABEL,           // provider tooltip (hidden field, V2 tile label)
    FI_TITLE,
    FI_HINT,
    FI_PIN,
    FI_SUBMIT,
    FI_COUNT
};

struct FieldDefinition {
    CREDENTIAL_PROVIDER_FIELD_TYPE type;
    const wchar_t* label;
    GUID guidFieldType;
    CREDENTIAL_PROVIDER_FIELD_STATE state;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE interactiveState;
};

inline const FieldDefinition kFields[FI_COUNT] = {
    {CPFT_TILE_IMAGE, L"Image", CPFG_CREDENTIAL_PROVIDER_LOGO, CPFS_DISPLAY_IN_BOTH, CPFIS_NONE},
    {CPFT_SMALL_TEXT, L"FIDO2 security key", CPFG_CREDENTIAL_PROVIDER_LABEL, CPFS_HIDDEN, CPFIS_NONE},
    {CPFT_LARGE_TEXT, L"FIDO2 security key", GUID_NULL, CPFS_DISPLAY_IN_BOTH, CPFIS_NONE},
    {CPFT_SMALL_TEXT, L"Hint", GUID_NULL, CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE},
    {CPFT_PASSWORD_TEXT, L"Security key PIN", GUID_NULL, CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED},
    {CPFT_SUBMIT_BUTTON, L"Submit", GUID_NULL, CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE},
};

inline constexpr wchar_t kHintText[] =
    L"Plug in your security key, enter its PIN if it asks for one, press Enter, then touch the key.";
