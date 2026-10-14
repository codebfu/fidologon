#define FIDOLOGON_NATIVE_EXPORTS
#include "fidologon_native.h"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <mutex>
#include <new>

#include "fidologon/accounts.h"
#include "fidologon/device_presence.h"
#include "fidologon/enrollment.h"
#include "fidologon/errors.h"
#include "fidologon/record_store.h"
#ifdef FIDOLOGON_TESTING
#include "fidologon/fake_authenticator.h"
#endif

using namespace fidologon;

namespace {

thread_local std::wstring t_lastError;

#ifdef FIDOLOGON_TESTING
std::mutex g_fakeMutex;
std::shared_ptr<FakeAuthenticator> g_fake;
#endif

template <class Body>
int32_t Guard(Body&& body) noexcept {
    try {
        body();
        t_lastError.clear();
        return 0;
    } catch (const Error& e) {
        try {
            t_lastError = FromUtf8(e.what());
        } catch (...) {
            t_lastError = DescribeError(e.code());
        }
        return static_cast<int32_t>(e.code());
    } catch (const std::bad_alloc&) {
        t_lastError = L"out of memory";
        return static_cast<int32_t>(ErrorCode::Internal);
    } catch (const std::exception& e) {
        t_lastError.assign(e.what(), e.what() + strlen(e.what()));
        return static_cast<int32_t>(ErrorCode::Internal);
    } catch (...) {
        t_lastError = L"unknown error";
        return static_cast<int32_t>(ErrorCode::Internal);
    }
}

void Require(bool condition, const char* message) {
    if (!condition) {
        throw Error(ErrorCode::InvalidArgument, message);
    }
}

// Copies a string into a fixed buffer; fails instead of truncating.
void CopyTo(const std::wstring& value, wchar_t* buffer, std::size_t capacity) {
    if (value.size() + 1 > capacity) {
        throw Error(ErrorCode::BufferTooSmall, "value does not fit in the output buffer");
    }
    wmemcpy(buffer, value.c_str(), value.size() + 1);
}

std::wstring Arg(const wchar_t* value) { return value != nullptr ? std::wstring(value) : std::wstring(); }

int32_t CopyMessage(const std::wstring& message, wchar_t* buffer, int32_t capacity) {
    if (buffer == nullptr || capacity <= 0) {
        return static_cast<int32_t>(ErrorCode::InvalidArgument);
    }
    const std::size_t count = std::min<std::size_t>(message.size(), static_cast<std::size_t>(capacity) - 1);
    wmemcpy(buffer, message.c_str(), count);
    buffer[count] = L'\0';
    return 0;
}

}  // namespace

extern "C" {

FL_API int32_t fl_last_error_message(wchar_t* buffer, int32_t capacity) {
    return CopyMessage(t_lastError, buffer, capacity);
}

FL_API int32_t fl_describe_error(int32_t code, wchar_t* buffer, int32_t capacity) {
    return CopyMessage(DescribeError(static_cast<ErrorCode>(code)), buffer, capacity);
}

FL_API int32_t fl_list_devices(fl_device* devices, int32_t capacity, int32_t* count) {
    return Guard([&] {
        Require(count != nullptr && (devices != nullptr || capacity == 0), "invalid output buffer");
        const auto list = GetAuthenticator()->ListDevices();
        *count = static_cast<int32_t>(list.size());
        if (list.size() > static_cast<std::size_t>(capacity)) {
            throw Error(ErrorCode::BufferTooSmall, "too many devices for the output buffer");
        }
        for (std::size_t i = 0; i < list.size(); ++i) {
            CopyTo(list[i].path, devices[i].path, FL_PATH_MAX);
            CopyTo(list[i].product.substr(0, FL_TEXT_MAX - 1), devices[i].product, FL_TEXT_MAX);
            CopyTo(list[i].manufacturer.substr(0, FL_TEXT_MAX - 1), devices[i].manufacturer, FL_TEXT_MAX);
            devices[i].vendor_id = list[i].vendorId;
            devices[i].product_id = list[i].productId;
        }
    });
}

FL_API int32_t fl_get_device_caps(const wchar_t* device_path, fl_device_caps* caps) {
    return Guard([&] {
        Require(device_path != nullptr && caps != nullptr, "device path and output are required");
        const DeviceCaps value = GetAuthenticator()->GetCaps(device_path);
        caps->fido2 = value.fido2;
        caps->has_pin = value.hasPin;
        caps->hmac_secret = value.hmacSecret;
        caps->cred_protect = value.credProtect;
    });
}

FL_API int32_t fl_is_device_present(const wchar_t* device_path, int32_t* present) {
    return Guard([&] {
        Require(device_path != nullptr && present != nullptr, "device path and output are required");
        *present = IsHidDevicePresent(device_path) ? 1 : 0;
    });
}

FL_API int32_t fl_get_device_arrival(const wchar_t* device_path, uint64_t* arrival) {
    return Guard([&] {
        Require(device_path != nullptr && arrival != nullptr, "device path and output are required");
        *arrival = HidDeviceArrivalTime(device_path);
    });
}

FL_API int32_t fl_list_local_users(fl_local_user* users, int32_t capacity, int32_t* count) {
    return Guard([&] {
        Require(count != nullptr && (users != nullptr || capacity == 0), "invalid output buffer");
        const auto list = ListLocalUsers();
        *count = static_cast<int32_t>(list.size());
        if (list.size() > static_cast<std::size_t>(capacity)) {
            throw Error(ErrorCode::BufferTooSmall, "too many users for the output buffer");
        }
        for (std::size_t i = 0; i < list.size(); ++i) {
            CopyTo(list[i].name, users[i].name, FL_TEXT_MAX);
            CopyTo(list[i].fullName.substr(0, FL_TEXT_MAX - 1), users[i].full_name, FL_TEXT_MAX);
            CopyTo(list[i].sid, users[i].sid, FL_SID_MAX);
            users[i].disabled = list[i].disabled ? 1 : 0;
        }
    });
}

FL_API int32_t fl_verify_password(const wchar_t* user_name, const wchar_t* password, uint32_t* win32_error) {
    return Guard([&] {
        Require(user_name != nullptr && password != nullptr, "user name and password are required");
        const DWORD error = VerifyLocalPassword(user_name, password);
        if (win32_error != nullptr) {
            *win32_error = error;
        }
        if (error != ERROR_SUCCESS) {
            throw Error(ErrorCode::PasswordInvalid, "LogonUser failed with error " + std::to_string(error));
        }
    });
}

FL_API int32_t fl_enroll(const wchar_t* device_path, const wchar_t* user_sid, const wchar_t* user_name,
                         const wchar_t* label, int32_t require_pin, const wchar_t* pin, const wchar_t* password,
                         wchar_t* record_id, int32_t record_id_capacity) {
    return fl_enroll_ex(device_path, user_sid, user_name, label, require_pin, pin, password, record_id,
                        record_id_capacity, nullptr, nullptr);
}

FL_API int32_t fl_enroll_ex(const wchar_t* device_path, const wchar_t* user_sid, const wchar_t* user_name,
                            const wchar_t* label, int32_t require_pin, const wchar_t* pin, const wchar_t* password,
                            wchar_t* record_id, int32_t record_id_capacity, fl_touch_callback callback,
                            void* context) {
    return Guard([&] {
        Require(record_id != nullptr && record_id_capacity > 0, "record id buffer is required");
        EnrollRequest request;
        request.devicePath = Arg(device_path);
        request.userSid = Arg(user_sid);
        request.userName = Arg(user_name);
        request.label = Arg(label);
        request.requirePin = require_pin != 0;
        request.pin = Arg(pin);
        request.password = Arg(password);
        if (callback != nullptr) {
            request.onTouch = [callback, context](int touch, int total) { callback(touch, total, context); };
        }
        WipeOnExit wipePin(request.pin);
        WipeOnExit wipePassword(request.password);

        // Checked before enrolling: a record whose id cannot be returned would stay in the store,
        // working, while the caller believes the enrollment failed.
        if (static_cast<std::size_t>(record_id_capacity) < kRecordIdLength + 1) {
            throw Error(ErrorCode::BufferTooSmall, "the record id buffer is too small");
        }
        RecordStore store = RecordStore::OpenDefault();
        const std::wstring id = Enroll(request, store);
        try {
            CopyTo(id, record_id, static_cast<std::size_t>(record_id_capacity));
        } catch (...) {
            store.Remove(id);
            throw;
        }
    });
}

FL_API int32_t fl_list_records(fl_record* records, int32_t capacity, int32_t* count) {
    return Guard([&] {
        Require(count != nullptr && (records != nullptr || capacity == 0), "invalid output buffer");
        const auto list = RecordStore::OpenDefault().List();
        *count = static_cast<int32_t>(list.size());
        if (list.size() > static_cast<std::size_t>(capacity)) {
            throw Error(ErrorCode::BufferTooSmall, "too many records for the output buffer");
        }
        for (std::size_t i = 0; i < list.size(); ++i) {
            CopyTo(list[i].id, records[i].id, FL_ID_MAX);
            CopyTo(list[i].userSid, records[i].user_sid, FL_SID_MAX);
            CopyTo(list[i].userName.substr(0, FL_TEXT_MAX - 1), records[i].user_name, FL_TEXT_MAX);
            CopyTo(list[i].label.substr(0, FL_TEXT_MAX - 1), records[i].label, FL_TEXT_MAX);
            records[i].require_pin = list[i].requirePin ? 1 : 0;
            records[i].created_unix = list[i].createdUnix;
            CopyTo(list[i].aaguid, records[i].aaguid, FL_ID_MAX);
            records[i].lock_on_removal = !list[i].lockOnRemoval.has_value() ? FL_LOCK_DEFAULT
                                         : *list[i].lockOnRemoval      ? FL_LOCK_ALWAYS
                                                                       : FL_LOCK_NEVER;
        }
    });
}

FL_API int32_t fl_remove_record(const wchar_t* record_id) {
    return Guard([&] {
        Require(record_id != nullptr, "record id is required");
        if (!RecordStore::OpenDefault().Remove(record_id)) {
            throw Error(ErrorCode::NotFound, "no such record");
        }
    });
}

FL_API int32_t fl_test_record(const wchar_t* record_id, const wchar_t* pin) {
    return fl_test_record_ex(record_id, pin, nullptr, nullptr);
}

FL_API int32_t fl_test_record_ex(const wchar_t* record_id, const wchar_t* pin, fl_touch_callback callback,
                                 void* context) {
    return Guard([&] {
        Require(record_id != nullptr, "record id is required");
        const auto record = RecordStore::OpenDefault().Get(record_id);
        if (!record) {
            throw Error(ErrorCode::NotFound, "no such record");
        }
        std::wstring pinValue = Arg(pin);
        WipeOnExit wipePin(pinValue);
        const auto match = FindEnrolledKey({*record}, &pinValue);
        if (!match) {
            throw Error(ErrorCode::NoDevice);
        }
        if (callback != nullptr) {
            callback(1, 1, context);
        }
        std::wstring password = UnlockPassword(*match, pinValue);
        Wipe(password);
    });
}

FL_API int32_t fl_list_allowed_models(fl_allowed_model* models, int32_t capacity, int32_t* count) {
    return Guard([&] {
        Require(count != nullptr && (models != nullptr || capacity == 0), "invalid output buffer");
        const auto list = RecordStore::OpenDefault().ListAllowedModels();
        *count = static_cast<int32_t>(list.size());
        if (list.size() > static_cast<std::size_t>(capacity)) {
            throw Error(ErrorCode::BufferTooSmall, "too many key models for the output buffer");
        }
        for (std::size_t i = 0; i < list.size(); ++i) {
            CopyTo(list[i].aaguid, models[i].aaguid, FL_ID_MAX);
            CopyTo(list[i].description.substr(0, FL_TEXT_MAX - 1), models[i].description, FL_TEXT_MAX);
            CopyTo(list[i].status.substr(0, FL_TEXT_MAX - 1), models[i].status, FL_TEXT_MAX);
            models[i].root_count = static_cast<int32_t>(list[i].rootCertificates.size());
        }
    });
}

FL_API int32_t fl_set_allowed_model(const wchar_t* aaguid, const wchar_t* description, const wchar_t* status,
                                    const uint8_t* const* roots, const int32_t* root_lengths, int32_t root_count) {
    return Guard([&] {
        Require(aaguid != nullptr && root_count > 0 && roots != nullptr && root_lengths != nullptr,
                "AAGUID and root certificates are required");
        AllowedModel model;
        model.aaguid = aaguid;
        model.description = Arg(description);
        model.status = Arg(status);
        for (int32_t i = 0; i < root_count; ++i) {
            Require(roots[i] != nullptr && root_lengths[i] > 0, "empty root certificate");
            model.rootCertificates.emplace_back(roots[i], roots[i] + root_lengths[i]);
        }
        RecordStore::OpenDefault().SaveAllowedModel(model);
    });
}

FL_API int32_t fl_remove_allowed_model(const wchar_t* aaguid) {
    return Guard([&] {
        Require(aaguid != nullptr, "AAGUID is required");
        if (!RecordStore::OpenDefault().RemoveAllowedModel(aaguid)) {
            throw Error(ErrorCode::NotFound, "this key model is not in the allowed list");
        }
    });
}

FL_API int32_t fl_replace_certified_models(const fl_model_input* models, int32_t count) {
    return Guard([&] {
        Require(count >= 0 && (models != nullptr || count == 0), "invalid model list");
        std::vector<AllowedModel> list;
        list.reserve(static_cast<std::size_t>(count));
        for (int32_t i = 0; i < count; ++i) {
            const fl_model_input& input = models[i];
            Require(input.aaguid != nullptr && input.root_count > 0 && input.roots != nullptr &&
                        input.root_lengths != nullptr,
                    "AAGUID and root certificates are required");
            AllowedModel model;
            model.aaguid = input.aaguid;
            model.description = Arg(input.description);
            model.status = Arg(input.status);
            for (int32_t r = 0; r < input.root_count; ++r) {
                Require(input.roots[r] != nullptr && input.root_lengths[r] > 0, "empty root certificate");
                model.rootCertificates.emplace_back(input.roots[r], input.roots[r] + input.root_lengths[r]);
            }
            list.push_back(std::move(model));
        }
        RecordStore::OpenDefault().ReplaceCertifiedModels(list);
    });
}

FL_API int32_t fl_count_certified_models(int32_t* count) {
    return Guard([&] {
        Require(count != nullptr, "output is required");
        *count = static_cast<int32_t>(RecordStore::OpenDefault().ListCertifiedModels().size());
    });
}

FL_API int32_t fl_list_certified_models(fl_allowed_model* models, int32_t capacity, int32_t* count) {
    return Guard([&] {
        Require(count != nullptr && (models != nullptr || capacity == 0), "invalid output buffer");
        const auto list = RecordStore::OpenDefault().ListCertifiedModels();
        *count = static_cast<int32_t>(list.size());
        if (list.size() > static_cast<std::size_t>(capacity)) {
            throw Error(ErrorCode::BufferTooSmall, "too many key models for the output buffer");
        }
        for (std::size_t i = 0; i < list.size(); ++i) {
            CopyTo(list[i].aaguid, models[i].aaguid, FL_ID_MAX);
            CopyTo(list[i].description.substr(0, FL_TEXT_MAX - 1), models[i].description, FL_TEXT_MAX);
            CopyTo(list[i].status.substr(0, FL_TEXT_MAX - 1), models[i].status, FL_TEXT_MAX);
            models[i].root_count = static_cast<int32_t>(list[i].rootCertificates.size());
        }
    });
}

FL_API int32_t fl_allow_certified_model(const wchar_t* aaguid) {
    return Guard([&] {
        Require(aaguid != nullptr, "AAGUID is required");
        if (!RecordStore::OpenDefault().AllowCertifiedModel(aaguid)) {
            throw Error(ErrorCode::NotFound, "no certified key model has this AAGUID");
        }
    });
}

FL_API int32_t fl_get_metadata_info(int32_t* present, int32_t* number, wchar_t* next_update, int32_t capacity) {
    return Guard([&] {
        Require(present != nullptr && number != nullptr && next_update != nullptr && capacity > 0,
                "outputs are required");
        const auto info = RecordStore::OpenDefault().GetMetadataInfo();
        *present = info ? 1 : 0;
        *number = info ? info->number : 0;
        CopyTo(info ? info->nextUpdate : std::wstring(), next_update, static_cast<std::size_t>(capacity));
    });
}

FL_API int32_t fl_set_metadata_info(int32_t number, const wchar_t* next_update) {
    return Guard([&] {
        Require(next_update != nullptr, "next update date is required");
        RecordStore::OpenDefault().SetMetadataInfo(MetadataInfo{number, next_update});
    });
}

FL_API int32_t fl_apply_default_model_policy(int32_t enable) {
    return Guard([&] { RecordStore::OpenDefault().ApplyDefaultModelPolicy(enable != 0); });
}

FL_API int32_t fl_get_allow_certified_models(int32_t* allow) {
    return Guard([&] {
        Require(allow != nullptr, "output is required");
        *allow = RecordStore::OpenDefault().AllowCertifiedModels() ? 1 : 0;
    });
}

FL_API int32_t fl_set_allow_certified_models(int32_t allow) {
    return Guard([&] { RecordStore::OpenDefault().SetAllowCertifiedModels(allow != 0); });
}

FL_API int32_t fl_get_auto_sync_metadata(int32_t* enabled) {
    return Guard([&] {
        Require(enabled != nullptr, "output is required");
        *enabled = RecordStore::OpenDefault().AutoSyncMetadata() ? 1 : 0;
    });
}

FL_API int32_t fl_set_auto_sync_metadata(int32_t enabled) {
    return Guard([&] { RecordStore::OpenDefault().SetAutoSyncMetadata(enabled != 0); });
}

FL_API int32_t fl_get_allow_password_fallback(int32_t* allow) {
    return Guard([&] {
        Require(allow != nullptr, "output is required");
        *allow = RecordStore::OpenDefault().AllowPasswordFallback() ? 1 : 0;
    });
}

FL_API int32_t fl_set_allow_password_fallback(int32_t allow) {
    return Guard([&] { RecordStore::OpenDefault().SetAllowPasswordFallback(allow != 0); });
}

FL_API int32_t fl_get_lock_on_key_removal(int32_t* lock) {
    return Guard([&] {
        Require(lock != nullptr, "output is required");
        *lock = RecordStore::OpenDefault().LockOnKeyRemoval() ? 1 : 0;
    });
}

FL_API int32_t fl_set_lock_on_key_removal(int32_t lock) {
    return Guard([&] { RecordStore::OpenDefault().SetLockOnKeyRemoval(lock != 0); });
}

FL_API int32_t fl_set_record_lock_on_removal(const wchar_t* record_id, int32_t mode) {
    return Guard([&] {
        Require(record_id != nullptr, "record id is required");
        Require(mode == FL_LOCK_DEFAULT || mode == FL_LOCK_NEVER || mode == FL_LOCK_ALWAYS, "invalid lock mode");
        std::optional<bool> lock;
        if (mode != FL_LOCK_DEFAULT) {
            lock = mode == FL_LOCK_ALWAYS;
        }
        RecordStore::OpenDefault().SetRecordLockOnRemoval(record_id, lock);
    });
}

FL_API int32_t fl_should_lock_on_removal(const wchar_t* record_id, int32_t* lock) {
    return Guard([&] {
        Require(lock != nullptr, "output is required");
        *lock = RecordStore::OpenDefault().ShouldLockOnRemoval(Arg(record_id)) ? 1 : 0;
    });
}

FL_API int32_t fl_every_user_enrolled(int32_t* result) {
    return Guard([&] {
        Require(result != nullptr, "output is required");
        *result = EveryEnabledUserEnrolled(ListLocalUsers(), RecordStore::OpenDefault().List()) ? 1 : 0;
    });
}

FL_API int32_t fl_is_machine_joined(int32_t* joined) {
    return Guard([&] {
        Require(joined != nullptr, "output is required");
        *joined = IsJoinedToDomainOrEntra() ? 1 : 0;
    });
}

FL_API int32_t fl_take_last_auth(uint32_t session_id, fl_last_auth* last_auth, int32_t* status) {
    return Guard([&] {
        Require(last_auth != nullptr && status != nullptr, "outputs are required");
        *status = FL_LAST_AUTH_NONE;
        std::optional<LastAuth> other;
        auto value = RecordStore::OpenDefault().TakeLastAuthForSession(session_id, &other);
        int32_t result = FL_LAST_AUTH_TAKEN;
        if (!value) {
            if (!other) {
                return;
            }
            value = std::move(other);
            result = FL_LAST_AUTH_OTHER_SESSION;
        }
        CopyTo(value->userSid, last_auth->user_sid, FL_SID_MAX);
        CopyTo(value->devicePath, last_auth->device_path, FL_PATH_MAX);
        CopyTo(value->recordId, last_auth->record_id, FL_ID_MAX);
        last_auth->timestamp_filetime = value->timestampFileTime;
        last_auth->session_id = value->sessionId;
        last_auth->device_arrival = value->deviceArrival;
        *status = result;
    });
}

FL_API int32_t fl_save_session_binding(const fl_session_binding* binding) {
    return Guard([&] {
        Require(binding != nullptr, "binding is required");
        RecordStore::OpenDefault().SaveSessionBinding(
            SessionBinding{binding->session_id, binding->user_sid, binding->device_path, binding->record_id,
                           binding->device_arrival});
    });
}

FL_API int32_t fl_remove_session_binding(uint32_t session_id) {
    return Guard([&] { RecordStore::OpenDefault().RemoveSessionBinding(session_id); });
}

FL_API int32_t fl_list_session_bindings(fl_session_binding* bindings, int32_t capacity, int32_t* count) {
    return Guard([&] {
        Require(count != nullptr && (bindings != nullptr || capacity == 0), "invalid output buffer");
        const auto list = RecordStore::OpenDefault().ListSessionBindings();
        *count = static_cast<int32_t>(list.size());
        if (list.size() > static_cast<std::size_t>(capacity)) {
            throw Error(ErrorCode::BufferTooSmall, "too many session bindings for the output buffer");
        }
        for (std::size_t i = 0; i < list.size(); ++i) {
            bindings[i].session_id = list[i].sessionId;
            CopyTo(list[i].userSid, bindings[i].user_sid, FL_SID_MAX);
            CopyTo(list[i].devicePath, bindings[i].device_path, FL_PATH_MAX);
            CopyTo(list[i].recordId, bindings[i].record_id, FL_ID_MAX);
            bindings[i].device_arrival = list[i].deviceArrival;
        }
    });
}

#ifdef FIDOLOGON_TESTING
FL_API int32_t fl_test_set_storage_root(const wchar_t* current_user_path) {
    return Guard([&] {
        if (current_user_path == nullptr) {
            RecordStore::ResetDefaultRoot();
        } else {
            RecordStore::OverrideDefaultRoot(HKEY_CURRENT_USER, current_user_path);
        }
    });
}

FL_API int32_t fl_test_use_fake_authenticator(int32_t enable) {
    return Guard([&] {
        std::lock_guard lock(g_fakeMutex);
        if (enable != 0) {
            g_fake = std::make_shared<FakeAuthenticator>();
            ReplaceAuthenticatorForTests(g_fake);
        } else {
            ReplaceAuthenticatorForTests(nullptr);
            g_fake = nullptr;
        }
    });
}

FL_API int32_t fl_test_fake_plug(const wchar_t* device_path, const wchar_t* pin) {
    return Guard([&] {
        std::lock_guard lock(g_fakeMutex);
        Require(g_fake != nullptr && device_path != nullptr, "fake authenticator not enabled");
        g_fake->PlugDevice(device_path, Arg(pin));
    });
}

FL_API int32_t fl_test_fake_unplug(const wchar_t* device_path) {
    return Guard([&] {
        std::lock_guard lock(g_fakeMutex);
        Require(g_fake != nullptr && device_path != nullptr, "fake authenticator not enabled");
        g_fake->UnplugDevice(device_path);
    });
}
#endif  // FIDOLOGON_TESTING

}  // extern "C"
