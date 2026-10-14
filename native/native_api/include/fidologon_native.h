/*
 * FidoLogon native API: flat C interface used by the .NET tools and service.
 *
 * Every function returns 0 on success or a fidologon error code (see
 * fidologon/errors.h). fl_last_error_message() returns details about the last
 * failure on the calling thread. Strings are UTF-16, fixed-size buffers are
 * always null-terminated.
 */
#pragma once

#include <stdint.h>
#include <wchar.h>

#ifdef FIDOLOGON_NATIVE_EXPORTS
#define FL_API __declspec(dllexport)
#else
#define FL_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define FL_PATH_MAX 512
#define FL_TEXT_MAX 256
#define FL_ID_MAX 64
#define FL_SID_MAX 192

/* Per-key session lock on removal. */
#define FL_LOCK_DEFAULT (-1) /* follow the machine-wide option */
#define FL_LOCK_NEVER 0
#define FL_LOCK_ALWAYS 1

typedef struct fl_device {
    wchar_t path[FL_PATH_MAX];
    wchar_t product[FL_TEXT_MAX];
    wchar_t manufacturer[FL_TEXT_MAX];
    int32_t vendor_id;
    int32_t product_id;
} fl_device;

typedef struct fl_device_caps {
    int32_t fido2;
    int32_t has_pin;
    int32_t hmac_secret;
    int32_t cred_protect; /* required for PIN mode */
} fl_device_caps;

typedef struct fl_record {
    wchar_t id[FL_ID_MAX];
    wchar_t user_sid[FL_SID_MAX];
    wchar_t user_name[FL_TEXT_MAX];
    wchar_t label[FL_TEXT_MAX];
    int32_t require_pin;
    int64_t created_unix;
    int32_t lock_on_removal; /* FL_LOCK_DEFAULT, FL_LOCK_NEVER or FL_LOCK_ALWAYS */
    wchar_t aaguid[FL_ID_MAX]; /* key model, empty if unknown */
} fl_record;

typedef struct fl_allowed_model {
    wchar_t aaguid[FL_ID_MAX];
    wchar_t description[FL_TEXT_MAX];
    wchar_t status[FL_TEXT_MAX];
    int32_t root_count;
} fl_allowed_model;

/* Input of fl_replace_certified_models: one key model with its DER attestation roots. */
typedef struct fl_model_input {
    const wchar_t* aaguid;
    const wchar_t* description;
    const wchar_t* status;
    const uint8_t* const* roots;
    const int32_t* root_lengths;
    int32_t root_count;
} fl_model_input;

typedef struct fl_local_user {
    wchar_t name[FL_TEXT_MAX];
    wchar_t full_name[FL_TEXT_MAX];
    wchar_t sid[FL_SID_MAX];
    int32_t disabled;
} fl_local_user;

typedef struct fl_last_auth {
    wchar_t user_sid[FL_SID_MAX];
    wchar_t device_path[FL_PATH_MAX];
    wchar_t record_id[FL_ID_MAX];
    uint64_t timestamp_filetime;
    uint32_t session_id;
    uint64_t device_arrival; /* when the key arrived, read at sign-in (FILETIME, 0 if unknown) */
} fl_last_auth;

typedef struct fl_session_binding {
    uint32_t session_id;
    wchar_t user_sid[FL_SID_MAX];
    wchar_t device_path[FL_PATH_MAX];
    wchar_t record_id[FL_ID_MAX];
    uint64_t device_arrival; /* from the sign-in's fl_last_auth */
} fl_session_binding;

#define FL_LAST_AUTH_NONE 0
#define FL_LAST_AUTH_TAKEN 1         /* belonged to the requested session, now consumed */
#define FL_LAST_AUTH_OTHER_SESSION 2 /* belongs to another session, left in place */

/* Diagnostics */
FL_API int32_t fl_last_error_message(wchar_t* buffer, int32_t capacity);
FL_API int32_t fl_describe_error(int32_t code, wchar_t* buffer, int32_t capacity);

/* Devices (administrator rights required for FIDO access) */
FL_API int32_t fl_list_devices(fl_device* devices, int32_t capacity, int32_t* count);
FL_API int32_t fl_get_device_caps(const wchar_t* device_path, fl_device_caps* caps);
FL_API int32_t fl_is_device_present(const wchar_t* device_path, int32_t* present);
/* When the device behind this path last arrived (FILETIME), 0 when absent or unknown: it changes
   when a key is unplugged and plugged back, even on the same path. */
FL_API int32_t fl_get_device_arrival(const wchar_t* device_path, uint64_t* arrival);

/* Accounts */
FL_API int32_t fl_list_local_users(fl_local_user* users, int32_t capacity, int32_t* count);
FL_API int32_t fl_verify_password(const wchar_t* user_name, const wchar_t* password, uint32_t* win32_error);

/* Called (on the calling thread) just before each operation that waits for a touch on the key. */
typedef void (*fl_touch_callback)(int32_t touch, int32_t total, void* context);

/* Enrolled keys */
FL_API int32_t fl_enroll(const wchar_t* device_path, const wchar_t* user_sid, const wchar_t* user_name,
                         const wchar_t* label, int32_t require_pin, const wchar_t* pin, const wchar_t* password,
                         wchar_t* record_id, int32_t record_id_capacity);
/* fl_enroll, reporting the two touches it waits for (callback may be NULL). */
FL_API int32_t fl_enroll_ex(const wchar_t* device_path, const wchar_t* user_sid, const wchar_t* user_name,
                            const wchar_t* label, int32_t require_pin, const wchar_t* pin, const wchar_t* password,
                            wchar_t* record_id, int32_t record_id_capacity, fl_touch_callback callback,
                            void* context);
FL_API int32_t fl_list_records(fl_record* records, int32_t capacity, int32_t* count);
FL_API int32_t fl_remove_record(const wchar_t* record_id);
/* Checks that a plugged key can decrypt the record's stored password (touch, plus PIN if required). */
FL_API int32_t fl_test_record(const wchar_t* record_id, const wchar_t* pin);
/* fl_test_record, reporting the touch it waits for (callback may be NULL). */
FL_API int32_t fl_test_record_ex(const wchar_t* record_id, const wchar_t* pin, fl_touch_callback callback,
                                 void* context);

/* Allowed key models (checked at enrollment; an empty list with certified models not allowed
   accepts every model) */
FL_API int32_t fl_list_allowed_models(fl_allowed_model* models, int32_t capacity, int32_t* count);
/* roots: root_count DER certificates (pointers and lengths) published by the FIDO Metadata Service. */
FL_API int32_t fl_set_allowed_model(const wchar_t* aaguid, const wchar_t* description, const wchar_t* status,
                                    const uint8_t* const* roots, const int32_t* root_lengths, int32_t root_count);
FL_API int32_t fl_remove_allowed_model(const wchar_t* aaguid);
/* Every FIDO2 model of the last imported FIDO Metadata Service BLOB, replaced as a whole. */
FL_API int32_t fl_replace_certified_models(const fl_model_input* models, int32_t count);
FL_API int32_t fl_count_certified_models(int32_t* count);
FL_API int32_t fl_list_certified_models(fl_allowed_model* models, int32_t capacity, int32_t* count);
/* Copies a certified model (with its attestation roots) to the allowed list; not found if unknown. */
FL_API int32_t fl_allow_certified_model(const wchar_t* aaguid);
/* Number and next update date (yyyy-MM-dd) of the BLOB the certified models come from.
   *present is 0 when none was imported. */
FL_API int32_t fl_get_metadata_info(int32_t* present, int32_t* number, wchar_t* next_update, int32_t capacity);
FL_API int32_t fl_set_metadata_info(int32_t number, const wchar_t* next_update);
/* Sets the certified-models policy and the metadata auto-sync to `enable`, each only if never set
   before (the installation choice, applied once by the service). */
FL_API int32_t fl_apply_default_model_policy(int32_t enable);
/* 1: enrollment also accepts every certified model (its attestation is still verified). */
FL_API int32_t fl_get_allow_certified_models(int32_t* allow);
FL_API int32_t fl_set_allow_certified_models(int32_t allow);
/* 1: the service downloads a new FIDO Metadata Service BLOB when the imported one is outdated. */
FL_API int32_t fl_get_auto_sync_metadata(int32_t* enabled);
FL_API int32_t fl_set_auto_sync_metadata(int32_t enabled);

/* Options */
FL_API int32_t fl_get_allow_password_fallback(int32_t* allow);
FL_API int32_t fl_set_allow_password_fallback(int32_t allow);
/* Machine-wide default: lock the session when the key that opened it is removed (1 when unset). */
FL_API int32_t fl_get_lock_on_key_removal(int32_t* lock);
FL_API int32_t fl_set_lock_on_key_removal(int32_t lock);
/* Per-key override: FL_LOCK_DEFAULT, FL_LOCK_NEVER or FL_LOCK_ALWAYS. */
FL_API int32_t fl_set_record_lock_on_removal(const wchar_t* record_id, int32_t mode);
/* Effective behavior for a record (machine-wide option for unknown or empty ids). */
FL_API int32_t fl_should_lock_on_removal(const wchar_t* record_id, int32_t* lock);
/* 1 when every enabled local account has at least one key (password tile can be hidden safely). */
FL_API int32_t fl_every_user_enrolled(int32_t* result);
/* 1 when the computer is joined to AD or Entra ID (or unknown): the password tile is never hidden. */
FL_API int32_t fl_is_machine_joined(int32_t* joined);

/* Session binding (used by the service) */
/* Takes the credential provider's last key sign-in record if it belongs to session_id;
 * status receives one of the FL_LAST_AUTH_* values (last_auth is filled unless NONE). */
FL_API int32_t fl_take_last_auth(uint32_t session_id, fl_last_auth* last_auth, int32_t* status);
FL_API int32_t fl_save_session_binding(const fl_session_binding* binding);
FL_API int32_t fl_remove_session_binding(uint32_t session_id);
FL_API int32_t fl_list_session_bindings(fl_session_binding* bindings, int32_t capacity, int32_t* count);

/* Test hooks: affect only the calling process. Exported only by the test build of this DLL
 * (native_api_testing), never by the shipped one. */
FL_API int32_t fl_test_set_storage_root(const wchar_t* current_user_path); /* NULL restores HKLM default */
FL_API int32_t fl_test_use_fake_authenticator(int32_t enable);
FL_API int32_t fl_test_fake_plug(const wchar_t* device_path, const wchar_t* pin);
FL_API int32_t fl_test_fake_unplug(const wchar_t* device_path);

#ifdef __cplusplus
}
#endif
