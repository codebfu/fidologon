#pragma once

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "fidologon/accounts.h"
#include "fidologon/authenticator.h"
#include "fidologon/record_store.h"

namespace fidologon {

struct EnrollRequest {
    std::wstring devicePath;
    std::wstring userSid;
    std::wstring userName;
    std::wstring label;
    bool requirePin = true;
    std::wstring pin;       // required when the device has a PIN set
    std::wstring password;  // the account's current Windows password (already verified by the caller)
    // Called just before each operation that waits for a touch on the key (touch 1..total).
    std::function<void(int touch, int total)> onTouch;
};

// Creates a credential on the key, derives the encryption key from hmac-secret and
// stores the encrypted password. Returns the new record id.
std::wstring Enroll(const EnrollRequest& request, RecordStore& store);

struct KeyMatch {
    DeviceInfo device;
    KeyRecord record;
};

// Finds a plugged device holding one of the given records' credentials (no touch needed).
// Only devices with the USB vendor/product id of a candidate record are opened.
// Touch-only credentials are found silently. PIN-mode credentials are protected by the key
// (credProtect) and need the PIN: it is sent only when exactly one matching PIN-capable key is
// plugged (MultipleDevices otherwise). PinRequired is thrown before any device exchange when every
// candidate needs the PIN and none was given.
std::optional<KeyMatch> FindEnrolledKey(const std::vector<KeyRecord>& candidates, const std::wstring* pin = nullptr);

// What the sign-in tile must ask for, given the keys plugged right now.
enum class KeyPresence {
    None,         // no plugged key of an enrolled model
    Multiple,     // several plugged keys of enrolled models: the user must leave only one
    NotEnrolled,  // one key of an enrolled model, but it holds none of the touch-only credentials
                  // and no PIN-mode record matches its model
    PinNeeded,    // one key whose model matches a PIN-mode record: ask for the PIN
    TouchOnly,    // one key holding a touch-only credential: a touch is enough (see `match`)
};

struct PresenceResult {
    KeyPresence presence = KeyPresence::None;
    std::optional<KeyMatch> match;  // set for TouchOnly
};

// USB paths of the plugged keys whose vendor/product id matches one of the records (HID
// enumeration only: no data is exchanged with the devices).
std::vector<std::wstring> ListMatchingDevicePaths(const std::vector<KeyRecord>& candidates);

// Classifies the plugged keys for the sign-in tile. With a single key of an enrolled model, its
// touch-only credentials are looked for silently (no touch, no PIN); PIN-mode credentials are
// hidden by the key without the PIN, so a key of a PIN-mode model is assumed to hold one.
PresenceResult DetectEnrolledKey(const std::vector<KeyRecord>& candidates);

// Asks the key for its hmac-secret (touch, plus PIN when the record requires it)
// and decrypts the stored Windows password.
std::wstring UnlockPassword(const KeyMatch& match, const std::wstring& pin);

// True when at least one enabled local account exists and every enabled account
// has a key. Hiding the password tile is only safe in that case.
bool EveryEnabledUserEnrolled(const std::vector<LocalUser>& users, const std::vector<KeyRecord>& records);

}  // namespace fidologon
