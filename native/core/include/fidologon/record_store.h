#pragma once

#include <windows.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "fidologon/bytes.h"

namespace fidologon {

// Relying party identifier used for every credential created by FidoLogon.
inline constexpr wchar_t kDefaultRpId[] = L"fidologon.local";

// One security key enrolled for one Windows account.
struct KeyRecord {
    std::wstring id;  // "{GUID}"
    std::wstring userSid;
    std::wstring userName;
    std::wstring label;
    std::wstring rpId = kDefaultRpId;
    Bytes credentialId;
    Bytes hmacSalt;
    Bytes encryptedPassword;
    bool requirePin = true;
    std::int64_t createdUnix = 0;
    // Key model from the attestation (lower-case GUID form), empty if unknown.
    std::wstring aaguid;
    // USB identifiers of the enrolled key: only devices with the same ones are probed at sign-in.
    std::uint16_t vendorId = 0;
    std::uint16_t productId = 0;
    // Session lock when this key is removed: nullopt follows the machine-wide LockOnKeyRemoval option.
    std::optional<bool> lockOnRemoval;
};

// Key model allowed at enrollment, with the attestation roots published for it by the FIDO
// Metadata Service (imported by the administrator). With an empty list and AllowCertifiedModels
// off, every model is allowed.
struct AllowedModel {
    std::wstring aaguid;  // lower-case GUID form
    std::wstring description;
    std::wstring status;  // latest FIDO Metadata Service status, e.g. FIDO_CERTIFIED_L1
    std::vector<Bytes> rootCertificates;  // DER
};

// The FIDO Metadata Service BLOB the certified models come from. The BLOB itself is not kept:
// it is verified when imported, and only what enrollment needs is stored.
struct MetadataInfo {
    std::int32_t number = 0;   // serial number, increased by every release
    std::wstring nextUpdate;   // yyyy-MM-dd, date by which a newer BLOB is published
};

// Written by the credential provider just before handing credentials to Windows,
// consumed by the service to bind the new session to the key that opened it.
struct LastAuth {
    std::wstring userSid;
    std::wstring devicePath;
    std::wstring recordId;
    std::uint64_t timestampFileTime = 0;
    // Session of the LogonUI instance that signed in: the session being unlocked, or the one the
    // user logs on to.
    std::uint32_t sessionId = 0;
    // When the key that signed in arrived (HidDeviceArrivalTime), read at sign-in; 0 if unknown.
    std::uint64_t deviceArrival = 0;
};

// Session bound to the key that opened it, kept by the service in volatile storage so that a
// service restart does not drop the lock-on-removal protection of open sessions.
struct SessionBinding {
    std::uint32_t sessionId = 0;
    std::wstring userSid;
    std::wstring devicePath;
    std::wstring recordId;
    // Arrival time of the bound key, from its LastAuth: kept so that a service restart compares
    // with the time of the sign-in, not with the time of the restart. 0 if unknown.
    std::uint64_t deviceArrival = 0;
};

// Registry-backed storage. Layout (default root HKLM\SOFTWARE\FidoLogon):
//   AllowPasswordFallback  REG_DWORD   (absent = 1)
//   LockOnKeyRemoval       REG_DWORD   (absent = 1)
//   Keys\{id}\...          one subkey per KeyRecord
//   AllowCertifiedModels   REG_DWORD   (absent = 0) also allow every CertifiedModels entry
//   AutoSyncMetadata       REG_DWORD   (absent = 0) the service downloads the FIDO MDS BLOB
//   AllowedModels\{aaguid}  one subkey per AllowedModel (Root0..RootN binary values)
//   CertifiedModels\{aaguid} same format: every model of the last FIDO MDS BLOB, replaced at
//                          each import
//   MetadataNumber         REG_DWORD   serial number of that BLOB (absent = none imported)
//   MetadataNextUpdate     REG_SZ      its next update date (yyyy-MM-dd)
//   Runtime\               volatile key: LastAuth\ (last key sign-in) and Sessions\{id}\ (bindings)
class RecordStore {
public:
    RecordStore(HKEY hive, std::wstring path);

    // Store at the process-wide root (HKLM\SOFTWARE\FidoLogon unless overridden for tests).
    static RecordStore OpenDefault();
#ifdef FIDOLOGON_TESTING
    static void OverrideDefaultRoot(HKEY hive, const std::wstring& path);
    static void ResetDefaultRoot();
#endif

    std::vector<KeyRecord> List() const;
    std::vector<KeyRecord> ListForUser(const std::wstring& userSid) const;
    std::optional<KeyRecord> Get(const std::wstring& id) const;
    void Save(const KeyRecord& record);
    bool Remove(const std::wstring& id);

    bool AllowPasswordFallback() const;
    void SetAllowPasswordFallback(bool allow);

    std::vector<AllowedModel> ListAllowedModels() const;
    void SaveAllowedModel(const AllowedModel& model);  // replaces an existing entry
    bool RemoveAllowedModel(const std::wstring& aaguid);

    std::vector<AllowedModel> ListCertifiedModels() const;
    // Replaces the whole list at once: readers see either the old or the new list.
    void ReplaceCertifiedModels(const std::vector<AllowedModel>& models);
    // Copies a certified model to the allowed list. False when no certified model has this AAGUID.
    bool AllowCertifiedModel(const std::wstring& aaguid);
    std::optional<MetadataInfo> GetMetadataInfo() const;
    void SetMetadataInfo(const MetadataInfo& info);
    bool AllowCertifiedModels() const;
    void SetAllowCertifiedModels(bool allow);
    // Sets AllowCertifiedModels and AutoSyncMetadata to `enable`, each only if it was never set:
    // the choice made at installation, applied once, without overriding a later one.
    void ApplyDefaultModelPolicy(bool enable);
    // Models enrollment accepts: allowed models, plus certified models when AllowCertifiedModels
    // is on. `enforced` is false when the policy accepts every model.
    std::vector<AllowedModel> EnrollmentModels(bool& enforced) const;

    bool AutoSyncMetadata() const;
    void SetAutoSyncMetadata(bool enabled);

    bool LockOnKeyRemoval() const;
    void SetLockOnKeyRemoval(bool lock);
    // Changes the per-key override of an existing record (nullopt = follow LockOnKeyRemoval).
    void SetRecordLockOnRemoval(const std::wstring& id, std::optional<bool> lock);
    // Effective behavior for the key of a record: its override, else the machine-wide option.
    // Unknown or empty ids (record removed meanwhile) use the machine-wide option.
    bool ShouldLockOnRemoval(const std::wstring& recordId) const;

    void WriteLastAuth(const LastAuth& value);
    std::optional<LastAuth> TakeLastAuth();
    // Consumes the record only if it belongs to sessionId. A record of another session is left in
    // place (it may be consumed by that session's event) and copied to `other` when given.
    std::optional<LastAuth> TakeLastAuthForSession(std::uint32_t sessionId, std::optional<LastAuth>* other = nullptr);
    void ClearLastAuth();

    void SaveSessionBinding(const SessionBinding& binding);
    void RemoveSessionBinding(std::uint32_t sessionId);
    std::vector<SessionBinding> ListSessionBindings() const;

    HKEY hive() const noexcept { return hive_; }
    const std::wstring& path() const noexcept { return path_; }

private:
    HKEY OpenRoot(REGSAM access, bool create) const;

    HKEY hive_;
    std::wstring path_;
};

// Record ids are GUID strings in braces: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}.
inline constexpr std::size_t kRecordIdLength = 38;
std::wstring NewRecordId();

}  // namespace fidologon
