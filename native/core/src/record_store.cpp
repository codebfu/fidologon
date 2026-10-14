#include "fidologon/record_store.h"

#include <aclapi.h>
#include <combaseapi.h>
#include <sddl.h>

#include <algorithm>
#include <cwctype>
#include <mutex>

#include "fidologon/errors.h"

namespace fidologon {
namespace {

constexpr wchar_t kDefaultRootPath[] = L"SOFTWARE\\FidoLogon";
constexpr wchar_t kKeysSubkey[] = L"Keys";
constexpr wchar_t kModelsSubkey[] = L"AllowedModels";
constexpr wchar_t kCertifiedSubkey[] = L"CertifiedModels";
constexpr wchar_t kCertifiedNewSubkey[] = L"CertifiedModels.new";
constexpr wchar_t kRuntimeSubkey[] = L"Runtime";
constexpr wchar_t kLastAuthSubkey[] = L"Runtime\\LastAuth";
constexpr wchar_t kSessionsSubkey[] = L"Runtime\\Sessions";
constexpr wchar_t kAllowPasswordFallback[] = L"AllowPasswordFallback";
constexpr wchar_t kLockOnKeyRemoval[] = L"LockOnKeyRemoval";
constexpr wchar_t kAllowCertifiedModels[] = L"AllowCertifiedModels";
constexpr wchar_t kAutoSyncMetadata[] = L"AutoSyncMetadata";
constexpr wchar_t kMetadataNumber[] = L"MetadataNumber";
constexpr wchar_t kMetadataNextUpdate[] = L"MetadataNextUpdate";
constexpr wchar_t kRecordLockOnRemoval[] = L"LockOnRemoval";

// SYSTEM and Administrators only, inherited by every subkey.
constexpr wchar_t kHardenedSddl[] = L"D:P(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)";

std::mutex g_rootMutex;
HKEY g_rootHive = HKEY_LOCAL_MACHINE;
std::wstring g_rootPath = kDefaultRootPath;

class RegKey {
public:
    RegKey() = default;
    explicit RegKey(HKEY key) : key_(key) {}
    ~RegKey() { Reset(); }
    RegKey(const RegKey&) = delete;
    RegKey& operator=(const RegKey&) = delete;
    RegKey(RegKey&& other) noexcept : key_(other.key_) { other.key_ = nullptr; }

    HKEY get() const { return key_; }
    HKEY* put() {
        Reset();
        return &key_;
    }
    explicit operator bool() const { return key_ != nullptr; }

private:
    void Reset() {
        if (key_ != nullptr) {
            RegCloseKey(key_);
            key_ = nullptr;
        }
    }
    HKEY key_ = nullptr;
};

[[noreturn]] void ThrowRegistry(LSTATUS status, const char* what) {
    if (status == ERROR_ACCESS_DENIED) {
        throw Error(ErrorCode::AccessDenied, std::string(what) + ": access denied");
    }
    throw Error(ErrorCode::StorageError, std::string(what) + " failed with error " + std::to_string(status));
}

std::optional<std::wstring> ReadString(HKEY key, const wchar_t* name) {
    DWORD size = 0;
    LSTATUS status = RegGetValueW(key, nullptr, name, RRF_RT_REG_SZ, nullptr, nullptr, &size);
    if (status != ERROR_SUCCESS) {
        return std::nullopt;
    }
    std::wstring value(size / sizeof(wchar_t), L'\0');
    status = RegGetValueW(key, nullptr, name, RRF_RT_REG_SZ, nullptr, value.data(), &size);
    if (status != ERROR_SUCCESS) {
        return std::nullopt;
    }
    value.resize(wcsnlen(value.c_str(), value.size()));
    return value;
}

std::optional<Bytes> ReadBinary(HKEY key, const wchar_t* name) {
    DWORD size = 0;
    LSTATUS status = RegGetValueW(key, nullptr, name, RRF_RT_REG_BINARY, nullptr, nullptr, &size);
    if (status != ERROR_SUCCESS) {
        return std::nullopt;
    }
    Bytes value(size);
    status = RegGetValueW(key, nullptr, name, RRF_RT_REG_BINARY, nullptr, value.data(), &size);
    if (status != ERROR_SUCCESS) {
        return std::nullopt;
    }
    value.resize(size);
    return value;
}

std::optional<DWORD> ReadDword(HKEY key, const wchar_t* name) {
    DWORD value = 0;
    DWORD size = sizeof(value);
    if (RegGetValueW(key, nullptr, name, RRF_RT_REG_DWORD, nullptr, &value, &size) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    return value;
}

std::optional<ULONGLONG> ReadQword(HKEY key, const wchar_t* name) {
    ULONGLONG value = 0;
    DWORD size = sizeof(value);
    if (RegGetValueW(key, nullptr, name, RRF_RT_REG_QWORD, nullptr, &value, &size) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    return value;
}

void WriteValue(HKEY key, const wchar_t* name, DWORD type, const void* data, std::size_t size) {
    const LSTATUS status = RegSetValueExW(key, name, 0, type, static_cast<const BYTE*>(data), static_cast<DWORD>(size));
    if (status != ERROR_SUCCESS) {
        ThrowRegistry(status, "RegSetValueEx");
    }
}

void WriteString(HKEY key, const wchar_t* name, const std::wstring& value) {
    WriteValue(key, name, REG_SZ, value.c_str(), (value.size() + 1) * sizeof(wchar_t));
}

void WriteBinary(HKEY key, const wchar_t* name, const Bytes& value) {
    WriteValue(key, name, REG_BINARY, value.data(), value.size());
}

void WriteDword(HKEY key, const wchar_t* name, DWORD value) { WriteValue(key, name, REG_DWORD, &value, sizeof(value)); }

void WriteQword(HKEY key, const wchar_t* name, ULONGLONG value) {
    WriteValue(key, name, REG_QWORD, &value, sizeof(value));
}

void WriteLockOverride(HKEY key, std::optional<bool> lock) {
    if (lock.has_value()) {
        WriteDword(key, kRecordLockOnRemoval, *lock ? 1 : 0);
        return;
    }
    const LSTATUS status = RegDeleteValueW(key, kRecordLockOnRemoval);
    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND) {
        ThrowRegistry(status, "RegDeleteValue");
    }
}

// Applies the hardened DACL to the root and propagates it to existing subkeys.
void HardenRoot(HKEY root) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(kHardenedSddl, SDDL_REVISION_1, &descriptor, nullptr)) {
        throw Error(ErrorCode::Internal, "ConvertStringSecurityDescriptorToSecurityDescriptor failed");
    }
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL dacl = nullptr;
    GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted);
    const DWORD status = SetSecurityInfo(root, SE_REGISTRY_KEY,
                                         DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr,
                                         nullptr, dacl, nullptr);
    LocalFree(descriptor);
    if (status != ERROR_SUCCESS) {
        ThrowRegistry(static_cast<LSTATUS>(status), "SetSecurityInfo");
    }
}

std::optional<KeyRecord> ReadRecord(HKEY keys, const std::wstring& id) {
    RegKey key;
    if (RegOpenKeyExW(keys, id.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, key.put()) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    KeyRecord record;
    record.id = id;
    auto sid = ReadString(key.get(), L"UserSid");
    auto userName = ReadString(key.get(), L"UserName");
    auto credentialId = ReadBinary(key.get(), L"CredentialId");
    auto salt = ReadBinary(key.get(), L"HmacSalt");
    auto encrypted = ReadBinary(key.get(), L"EncryptedPassword");
    if (!sid || !userName || !credentialId || !salt || !encrypted) {
        return std::nullopt;  // incomplete record: ignore rather than fail every logon
    }
    record.userSid = *sid;
    record.userName = *userName;
    record.credentialId = std::move(*credentialId);
    record.hmacSalt = std::move(*salt);
    record.encryptedPassword = std::move(*encrypted);
    record.label = ReadString(key.get(), L"Label").value_or(L"");
    record.rpId = ReadString(key.get(), L"RpId").value_or(kDefaultRpId);
    record.requirePin = ReadDword(key.get(), L"RequirePin").value_or(1) != 0;
    record.createdUnix = static_cast<std::int64_t>(ReadQword(key.get(), L"CreatedUnix").value_or(0));
    record.aaguid = ReadString(key.get(), L"Aaguid").value_or(L"");
    record.vendorId = static_cast<std::uint16_t>(ReadDword(key.get(), L"VendorId").value_or(0));
    record.productId = static_cast<std::uint16_t>(ReadDword(key.get(), L"ProductId").value_or(0));
    if (const auto lock = ReadDword(key.get(), kRecordLockOnRemoval)) {
        record.lockOnRemoval = *lock != 0;
    }
    return record;
}

}  // namespace

RecordStore::RecordStore(HKEY hive, std::wstring path) : hive_(hive), path_(std::move(path)) {}

RecordStore RecordStore::OpenDefault() {
    std::lock_guard lock(g_rootMutex);
    return RecordStore(g_rootHive, g_rootPath);
}

#ifdef FIDOLOGON_TESTING
void RecordStore::OverrideDefaultRoot(HKEY hive, const std::wstring& path) {
    std::lock_guard lock(g_rootMutex);
    g_rootHive = hive;
    g_rootPath = path;
}

void RecordStore::ResetDefaultRoot() { OverrideDefaultRoot(HKEY_LOCAL_MACHINE, kDefaultRootPath); }
#endif

HKEY RecordStore::OpenRoot(REGSAM access, bool create) const {
    HKEY key = nullptr;
    if (!create) {
        const LSTATUS status = RegOpenKeyExW(hive_, path_.c_str(), 0, access | KEY_WOW64_64KEY, &key);
        if (status == ERROR_FILE_NOT_FOUND) {
            return nullptr;
        }
        if (status != ERROR_SUCCESS) {
            ThrowRegistry(status, "RegOpenKeyEx(root)");
        }
        return key;
    }

    DWORD disposition = 0;
    const LSTATUS status = RegCreateKeyExW(hive_, path_.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                                           access | KEY_WOW64_64KEY | WRITE_DAC | READ_CONTROL, nullptr, &key,
                                           &disposition);
    if (status != ERROR_SUCCESS) {
        ThrowRegistry(status, "RegCreateKeyEx(root)");
    }
    if (hive_ == HKEY_LOCAL_MACHINE) {
        try {
            HardenRoot(key);
        } catch (...) {
            RegCloseKey(key);
            throw;
        }
    }
    return key;
}

std::vector<KeyRecord> RecordStore::List() const {
    std::vector<KeyRecord> records;
    RegKey root(OpenRoot(KEY_READ, false));
    if (!root) {
        return records;
    }
    RegKey keys;
    if (RegOpenKeyExW(root.get(), kKeysSubkey, 0, KEY_READ | KEY_WOW64_64KEY, keys.put()) != ERROR_SUCCESS) {
        return records;
    }
    for (DWORD index = 0;; ++index) {
        wchar_t name[256];
        DWORD nameLength = ARRAYSIZE(name);
        const LSTATUS status = RegEnumKeyExW(keys.get(), index, name, &nameLength, nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (status != ERROR_SUCCESS) {
            ThrowRegistry(status, "RegEnumKeyEx");
        }
        if (auto record = ReadRecord(keys.get(), name)) {
            records.push_back(std::move(*record));
        }
    }
    return records;
}

std::vector<KeyRecord> RecordStore::ListForUser(const std::wstring& userSid) const {
    std::vector<KeyRecord> result;
    for (auto& record : List()) {
        if (_wcsicmp(record.userSid.c_str(), userSid.c_str()) == 0) {
            result.push_back(std::move(record));
        }
    }
    return result;
}

std::optional<KeyRecord> RecordStore::Get(const std::wstring& id) const {
    RegKey root(OpenRoot(KEY_READ, false));
    if (!root) {
        return std::nullopt;
    }
    RegKey keys;
    if (RegOpenKeyExW(root.get(), kKeysSubkey, 0, KEY_READ | KEY_WOW64_64KEY, keys.put()) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    return ReadRecord(keys.get(), id);
}

void RecordStore::Save(const KeyRecord& record) {
    if (record.id.empty() || record.userSid.empty() || record.credentialId.empty() || record.hmacSalt.empty() ||
        record.encryptedPassword.empty()) {
        throw Error(ErrorCode::InvalidArgument, "incomplete key record");
    }
    RegKey root(OpenRoot(KEY_ALL_ACCESS, true));
    const std::wstring subkey = std::wstring(kKeysSubkey) + L"\\" + record.id;
    RegKey key;
    const LSTATUS status = RegCreateKeyExW(root.get(), subkey.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                                           KEY_ALL_ACCESS | KEY_WOW64_64KEY, nullptr, key.put(), nullptr);
    if (status != ERROR_SUCCESS) {
        ThrowRegistry(status, "RegCreateKeyEx(record)");
    }
    WriteString(key.get(), L"UserSid", record.userSid);
    WriteString(key.get(), L"UserName", record.userName);
    WriteString(key.get(), L"Label", record.label);
    WriteString(key.get(), L"RpId", record.rpId);
    WriteBinary(key.get(), L"CredentialId", record.credentialId);
    WriteBinary(key.get(), L"HmacSalt", record.hmacSalt);
    WriteBinary(key.get(), L"EncryptedPassword", record.encryptedPassword);
    WriteDword(key.get(), L"RequirePin", record.requirePin ? 1 : 0);
    WriteQword(key.get(), L"CreatedUnix", static_cast<ULONGLONG>(record.createdUnix));
    WriteString(key.get(), L"Aaguid", record.aaguid);
    WriteDword(key.get(), L"VendorId", record.vendorId);
    WriteDword(key.get(), L"ProductId", record.productId);
    WriteLockOverride(key.get(), record.lockOnRemoval);
}

bool RecordStore::Remove(const std::wstring& id) {
    if (id.empty() || id.find(L'\\') != std::wstring::npos) {
        throw Error(ErrorCode::InvalidArgument, "invalid record id");
    }
    RegKey root(OpenRoot(KEY_ALL_ACCESS, false));
    if (!root) {
        return false;
    }
    const std::wstring subkey = std::wstring(kKeysSubkey) + L"\\" + id;
    const LSTATUS status = RegDeleteTreeW(root.get(), subkey.c_str());
    if (status == ERROR_FILE_NOT_FOUND) {
        return false;
    }
    if (status != ERROR_SUCCESS) {
        ThrowRegistry(status, "RegDeleteTree(record)");
    }
    return true;
}

bool RecordStore::AllowPasswordFallback() const {
    RegKey root(OpenRoot(KEY_READ, false));
    if (!root) {
        return true;
    }
    return ReadDword(root.get(), kAllowPasswordFallback).value_or(1) != 0;
}

void RecordStore::SetAllowPasswordFallback(bool allow) {
    RegKey root(OpenRoot(KEY_ALL_ACCESS, true));
    WriteDword(root.get(), kAllowPasswordFallback, allow ? 1 : 0);
}

namespace {

bool IsValidAaguid(const std::wstring& aaguid) {
    if (aaguid.size() != 36) {
        return false;
    }
    for (std::size_t i = 0; i < aaguid.size(); ++i) {
        const bool dash = i == 8 || i == 13 || i == 18 || i == 23;
        if (dash ? aaguid[i] != L'-' : !iswxdigit(aaguid[i])) {
            return false;
        }
    }
    return true;
}

}  // namespace

namespace {

std::wstring LowerAaguid(std::wstring aaguid) {
    for (wchar_t& c : aaguid) {
        c = static_cast<wchar_t>(towlower(c));
    }
    return aaguid;
}

std::vector<AllowedModel> ReadModels(HKEY root, const wchar_t* subkey) {
    std::vector<AllowedModel> models;
    RegKey list;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, list.put()) != ERROR_SUCCESS) {
        return models;
    }
    for (DWORD index = 0;; ++index) {
        wchar_t name[64];
        DWORD nameLength = ARRAYSIZE(name);
        const LSTATUS status = RegEnumKeyExW(list.get(), index, name, &nameLength, nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (status != ERROR_SUCCESS) {
            ThrowRegistry(status, "RegEnumKeyEx(models)");
        }
        RegKey key;
        if (!IsValidAaguid(name) ||
            RegOpenKeyExW(list.get(), name, 0, KEY_READ | KEY_WOW64_64KEY, key.put()) != ERROR_SUCCESS) {
            continue;
        }
        AllowedModel model;
        model.aaguid = name;
        model.description = ReadString(key.get(), L"Description").value_or(L"");
        model.status = ReadString(key.get(), L"Status").value_or(L"");
        for (int i = 0;; ++i) {
            auto certificate = ReadBinary(key.get(), (L"Root" + std::to_wstring(i)).c_str());
            if (!certificate) {
                break;
            }
            model.rootCertificates.push_back(std::move(*certificate));
        }
        models.push_back(std::move(model));
    }
    return models;
}

void ValidateModel(const AllowedModel& model) {
    if (!IsValidAaguid(model.aaguid)) {
        throw Error(ErrorCode::InvalidArgument, "invalid AAGUID");
    }
    if (model.rootCertificates.empty()) {
        throw Error(ErrorCode::InvalidArgument, "a key model needs at least one attestation root certificate");
    }
}

void WriteModel(HKEY root, const std::wstring& listSubkey, const AllowedModel& model) {
    const std::wstring subkey = listSubkey + L"\\" + LowerAaguid(model.aaguid);
    RegDeleteTreeW(root, subkey.c_str());  // drop roots of a previous version
    RegKey key;
    const LSTATUS status = RegCreateKeyExW(root, subkey.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                                           KEY_ALL_ACCESS | KEY_WOW64_64KEY, nullptr, key.put(), nullptr);
    if (status != ERROR_SUCCESS) {
        ThrowRegistry(status, "RegCreateKeyEx(model)");
    }
    WriteString(key.get(), L"Description", model.description);
    WriteString(key.get(), L"Status", model.status);
    for (std::size_t i = 0; i < model.rootCertificates.size(); ++i) {
        WriteBinary(key.get(), (L"Root" + std::to_wstring(i)).c_str(), model.rootCertificates[i]);
    }
}

}  // namespace

std::vector<AllowedModel> RecordStore::ListAllowedModels() const {
    RegKey root(OpenRoot(KEY_READ, false));
    return root ? ReadModels(root.get(), kModelsSubkey) : std::vector<AllowedModel>{};
}

void RecordStore::SaveAllowedModel(const AllowedModel& model) {
    ValidateModel(model);
    RegKey root(OpenRoot(KEY_ALL_ACCESS, true));
    WriteModel(root.get(), kModelsSubkey, model);
}

bool RecordStore::RemoveAllowedModel(const std::wstring& aaguid) {
    if (!IsValidAaguid(aaguid)) {
        throw Error(ErrorCode::InvalidArgument, "invalid AAGUID");
    }
    RegKey root(OpenRoot(KEY_ALL_ACCESS, false));
    if (!root) {
        return false;
    }
    const std::wstring subkey = std::wstring(kModelsSubkey) + L"\\" + aaguid;
    const LSTATUS status = RegDeleteTreeW(root.get(), subkey.c_str());
    if (status == ERROR_FILE_NOT_FOUND) {
        return false;
    }
    if (status != ERROR_SUCCESS) {
        ThrowRegistry(status, "RegDeleteTree(model)");
    }
    return true;
}

std::vector<AllowedModel> RecordStore::ListCertifiedModels() const {
    RegKey root(OpenRoot(KEY_READ, false));
    return root ? ReadModels(root.get(), kCertifiedSubkey) : std::vector<AllowedModel>{};
}

void RecordStore::ReplaceCertifiedModels(const std::vector<AllowedModel>& models) {
    for (const AllowedModel& model : models) {
        ValidateModel(model);
    }
    RegKey root(OpenRoot(KEY_ALL_ACCESS, true));
    // Build the new list aside, then swap it in with a rename.
    RegDeleteTreeW(root.get(), kCertifiedNewSubkey);
    {
        RegKey staging;
        const LSTATUS created = RegCreateKeyExW(root.get(), kCertifiedNewSubkey, 0, nullptr, REG_OPTION_NON_VOLATILE,
                                                KEY_ALL_ACCESS | KEY_WOW64_64KEY, nullptr, staging.put(), nullptr);
        if (created != ERROR_SUCCESS) {
            ThrowRegistry(created, "RegCreateKeyEx(certified models)");
        }
    }
    for (const AllowedModel& model : models) {
        WriteModel(root.get(), kCertifiedNewSubkey, model);
    }
    LSTATUS status = RegDeleteTreeW(root.get(), kCertifiedSubkey);
    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND) {
        ThrowRegistry(status, "RegDeleteTree(certified models)");
    }
    status = RegRenameKey(root.get(), kCertifiedNewSubkey, kCertifiedSubkey);
    if (status != ERROR_SUCCESS) {
        ThrowRegistry(status, "RegRenameKey(certified models)");
    }
}

bool RecordStore::AllowCertifiedModel(const std::wstring& aaguid) {
    for (const AllowedModel& model : ListCertifiedModels()) {
        if (_wcsicmp(model.aaguid.c_str(), aaguid.c_str()) == 0) {
            SaveAllowedModel(model);
            return true;
        }
    }
    return false;
}

std::optional<MetadataInfo> RecordStore::GetMetadataInfo() const {
    RegKey root(OpenRoot(KEY_READ, false));
    if (!root) {
        return std::nullopt;
    }
    const auto number = ReadDword(root.get(), kMetadataNumber);
    auto nextUpdate = ReadString(root.get(), kMetadataNextUpdate);
    if (!number || !nextUpdate) {
        return std::nullopt;
    }
    return MetadataInfo{static_cast<std::int32_t>(*number), std::move(*nextUpdate)};
}

void RecordStore::SetMetadataInfo(const MetadataInfo& info) {
    if (info.number < 0 || info.nextUpdate.size() != 10) {
        throw Error(ErrorCode::InvalidArgument, "invalid metadata number or date");
    }
    RegKey root(OpenRoot(KEY_ALL_ACCESS, true));
    WriteString(root.get(), kMetadataNextUpdate, info.nextUpdate);
    WriteDword(root.get(), kMetadataNumber, static_cast<DWORD>(info.number));
}

void RecordStore::ApplyDefaultModelPolicy(bool enable) {
    RegKey root(OpenRoot(KEY_ALL_ACCESS, true));
    for (const wchar_t* name : {kAllowCertifiedModels, kAutoSyncMetadata}) {
        if (!ReadDword(root.get(), name)) {
            WriteDword(root.get(), name, enable ? 1 : 0);
        }
    }
}

bool RecordStore::AllowCertifiedModels() const {
    RegKey root(OpenRoot(KEY_READ, false));
    return root && ReadDword(root.get(), kAllowCertifiedModels).value_or(0) != 0;
}

void RecordStore::SetAllowCertifiedModels(bool allow) {
    RegKey root(OpenRoot(KEY_ALL_ACCESS, true));
    WriteDword(root.get(), kAllowCertifiedModels, allow ? 1 : 0);
}

std::vector<AllowedModel> RecordStore::EnrollmentModels(bool& enforced) const {
    std::vector<AllowedModel> models = ListAllowedModels();
    const bool certified = AllowCertifiedModels();
    enforced = certified || !models.empty();
    if (certified) {
        // An explicitly allowed model keeps its own entry; the certified list adds the others.
        for (AllowedModel& model : ListCertifiedModels()) {
            const bool known = std::any_of(models.begin(), models.end(), [&](const AllowedModel& m) {
                return _wcsicmp(m.aaguid.c_str(), model.aaguid.c_str()) == 0;
            });
            if (!known) {
                models.push_back(std::move(model));
            }
        }
    }
    return models;
}

bool RecordStore::AutoSyncMetadata() const {
    RegKey root(OpenRoot(KEY_READ, false));
    return root && ReadDword(root.get(), kAutoSyncMetadata).value_or(0) != 0;
}

void RecordStore::SetAutoSyncMetadata(bool enabled) {
    RegKey root(OpenRoot(KEY_ALL_ACCESS, true));
    WriteDword(root.get(), kAutoSyncMetadata, enabled ? 1 : 0);
}

bool RecordStore::LockOnKeyRemoval() const {
    RegKey root(OpenRoot(KEY_READ, false));
    if (!root) {
        return true;
    }
    return ReadDword(root.get(), kLockOnKeyRemoval).value_or(1) != 0;
}

void RecordStore::SetLockOnKeyRemoval(bool lock) {
    RegKey root(OpenRoot(KEY_ALL_ACCESS, true));
    WriteDword(root.get(), kLockOnKeyRemoval, lock ? 1 : 0);
}

void RecordStore::SetRecordLockOnRemoval(const std::wstring& id, std::optional<bool> lock) {
    if (id.empty() || id.find(L'\\') != std::wstring::npos) {
        throw Error(ErrorCode::InvalidArgument, "invalid record id");
    }
    RegKey root(OpenRoot(KEY_ALL_ACCESS, false));
    const std::wstring subkey = std::wstring(kKeysSubkey) + L"\\" + id;
    RegKey key;
    const LSTATUS status =
        root ? RegOpenKeyExW(root.get(), subkey.c_str(), 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, key.put())
             : ERROR_FILE_NOT_FOUND;
    if (status == ERROR_FILE_NOT_FOUND) {
        throw Error(ErrorCode::NotFound, "no such record");
    }
    if (status != ERROR_SUCCESS) {
        ThrowRegistry(status, "RegOpenKeyEx(record)");
    }
    WriteLockOverride(key.get(), lock);
}

bool RecordStore::ShouldLockOnRemoval(const std::wstring& recordId) const {
    if (!recordId.empty() && recordId.find(L'\\') == std::wstring::npos) {
        if (const auto record = Get(recordId); record && record->lockOnRemoval.has_value()) {
            return *record->lockOnRemoval;
        }
    }
    return LockOnKeyRemoval();
}

namespace {

// Creates (volatile) Runtime and the given volatile subkey path below the root.
RegKey CreateVolatile(HKEY root, const std::wstring& path) {
    RegKey runtime;
    LSTATUS status = RegCreateKeyExW(root, kRuntimeSubkey, 0, nullptr, REG_OPTION_VOLATILE,
                                     KEY_ALL_ACCESS | KEY_WOW64_64KEY, nullptr, runtime.put(), nullptr);
    if (status != ERROR_SUCCESS) {
        ThrowRegistry(status, "RegCreateKeyEx(runtime)");
    }
    RegKey key;
    status = RegCreateKeyExW(root, path.c_str(), 0, nullptr, REG_OPTION_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY,
                             nullptr, key.put(), nullptr);
    if (status != ERROR_SUCCESS) {
        ThrowRegistry(status, "RegCreateKeyEx(volatile)");
    }
    return key;
}

std::optional<LastAuth> ReadLastAuth(HKEY root) {
    RegKey key;
    if (RegOpenKeyExW(root, kLastAuthSubkey, 0, KEY_READ | KEY_WOW64_64KEY, key.put()) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    auto sid = ReadString(key.get(), L"UserSid");
    auto path = ReadString(key.get(), L"DevicePath");
    auto timestamp = ReadQword(key.get(), L"Timestamp");
    if (!sid || !path || !timestamp) {
        return std::nullopt;
    }
    return LastAuth{*sid, *path, ReadString(key.get(), L"RecordId").value_or(L""), *timestamp,
                    ReadDword(key.get(), L"SessionId").value_or(0), ReadQword(key.get(), L"DeviceArrival").value_or(0)};
}

std::wstring SessionPath(std::uint32_t sessionId) {
    return std::wstring(kSessionsSubkey) + L"\\" + std::to_wstring(sessionId);
}

}  // namespace

void RecordStore::WriteLastAuth(const LastAuth& value) {
    RegKey root(OpenRoot(KEY_ALL_ACCESS, true));
    RegKey key = CreateVolatile(root.get(), kLastAuthSubkey);
    WriteString(key.get(), L"UserSid", value.userSid);
    WriteString(key.get(), L"DevicePath", value.devicePath);
    WriteString(key.get(), L"RecordId", value.recordId);
    WriteQword(key.get(), L"Timestamp", value.timestampFileTime);
    WriteDword(key.get(), L"SessionId", value.sessionId);
    WriteQword(key.get(), L"DeviceArrival", value.deviceArrival);
}

std::optional<LastAuth> RecordStore::TakeLastAuth() {
    RegKey root(OpenRoot(KEY_ALL_ACCESS, false));
    if (!root) {
        return std::nullopt;
    }
    std::optional<LastAuth> result = ReadLastAuth(root.get());
    RegDeleteTreeW(root.get(), kLastAuthSubkey);
    return result;
}

std::optional<LastAuth> RecordStore::TakeLastAuthForSession(std::uint32_t sessionId, std::optional<LastAuth>* other) {
    RegKey root(OpenRoot(KEY_ALL_ACCESS, false));
    if (!root) {
        return std::nullopt;
    }
    std::optional<LastAuth> value = ReadLastAuth(root.get());
    if (!value) {
        return std::nullopt;
    }
    if (value->sessionId != sessionId) {
        if (other != nullptr) {
            *other = std::move(value);
        }
        return std::nullopt;
    }
    RegDeleteTreeW(root.get(), kLastAuthSubkey);
    return value;
}

void RecordStore::ClearLastAuth() {
    RegKey root(OpenRoot(KEY_ALL_ACCESS, false));
    if (root) {
        RegDeleteTreeW(root.get(), kLastAuthSubkey);
    }
}

void RecordStore::SaveSessionBinding(const SessionBinding& binding) {
    RegKey root(OpenRoot(KEY_ALL_ACCESS, true));
    RegKey key = CreateVolatile(root.get(), SessionPath(binding.sessionId));
    WriteString(key.get(), L"UserSid", binding.userSid);
    WriteString(key.get(), L"DevicePath", binding.devicePath);
    WriteString(key.get(), L"RecordId", binding.recordId);
    WriteQword(key.get(), L"DeviceArrival", binding.deviceArrival);
}

void RecordStore::RemoveSessionBinding(std::uint32_t sessionId) {
    RegKey root(OpenRoot(KEY_ALL_ACCESS, false));
    if (root) {
        RegDeleteTreeW(root.get(), SessionPath(sessionId).c_str());
    }
}

std::vector<SessionBinding> RecordStore::ListSessionBindings() const {
    std::vector<SessionBinding> result;
    RegKey root(OpenRoot(KEY_READ, false));
    if (!root) {
        return result;
    }
    RegKey sessions;
    if (RegOpenKeyExW(root.get(), kSessionsSubkey, 0, KEY_READ | KEY_WOW64_64KEY, sessions.put()) != ERROR_SUCCESS) {
        return result;
    }
    for (DWORD index = 0;; ++index) {
        wchar_t name[32];
        DWORD nameLength = ARRAYSIZE(name);
        const LSTATUS status =
            RegEnumKeyExW(sessions.get(), index, name, &nameLength, nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (status != ERROR_SUCCESS) {
            ThrowRegistry(status, "RegEnumKeyEx(sessions)");
        }
        RegKey key;
        if (RegOpenKeyExW(sessions.get(), name, 0, KEY_READ | KEY_WOW64_64KEY, key.put()) != ERROR_SUCCESS) {
            continue;
        }
        wchar_t* end = nullptr;
        const unsigned long id = wcstoul(name, &end, 10);
        auto sid = ReadString(key.get(), L"UserSid");
        auto path = ReadString(key.get(), L"DevicePath");
        if (end == name || *end != L'\0' || !sid || !path) {
            continue;
        }
        result.push_back(SessionBinding{static_cast<std::uint32_t>(id), *sid, *path,
                                        ReadString(key.get(), L"RecordId").value_or(L""),
                                        ReadQword(key.get(), L"DeviceArrival").value_or(0)});
    }
    return result;
}

std::wstring NewRecordId() {
    GUID guid{};
    if (FAILED(CoCreateGuid(&guid))) {
        throw Error(ErrorCode::Internal, "CoCreateGuid failed");
    }
    wchar_t text[64] = {};
    StringFromGUID2(guid, text, ARRAYSIZE(text));
    return text;
}

}  // namespace fidologon
