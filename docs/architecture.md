# Architecture

## Components

| Component | Language | Runs as | Role |
|---|---|---|---|
| `FidoLogonCredentialProvider.dll` | C++ (COM) | SYSTEM, inside LogonUI | V2 credential provider: adds a *FIDO2 security key* sign-in option to every user tile whose account has an enrolled key; also a credential provider filter that can hide the password tile. |
| `fidologon_native.dll` | C++ | caller | Flat C API over the shared core, used by the .NET tools and service. |
| `FidoLogon.Service.exe` | C# (.NET 10) | LocalSystem service | Binds sessions to the key that opened them and locks them when that key disappears. |
| `FidoLogon.Lock.exe` | C++ | the user, in the user's session | Calls `LockWorkStation` (started by the service). |
| `fidologon.exe` / `FidoLogon.Config.exe` | C# | administrator | Enroll, test and remove keys; options. |

The C++ core (`native/core`) holds all security-sensitive logic: FIDO2 operations (libfido2),
cryptography (Windows CNG), attestation checks (CryptoAPI) and the registry layout. The credential
provider links it statically; the .NET side only calls it through `fidologon_native.dll`, so there
is a single implementation of the storage format.

Every native library is built twice. The shipped variant has no test code. The test variant
(`*_testing` targets, `FIDOLOGON_TESTING` defined) adds the simulated authenticator and the test
hooks (`fl_test_*`, storage redirection to `HKCU`); it is used by the native tests and, as
`build/native/native_api_testing/fidologon_native.dll`, by the .NET tests, and never packaged.

## Enrollment

1. The administrator selects a local account, a plugged key and a mode (*PIN + touch* or *touch only*),
   and types the account's current Windows password. The password is checked with `LogonUser`.
2. A non-discoverable ES256 credential is created on the key (relying party `fidologon.local`) with
   the `hmac-secret` extension. The key PIN is needed for this step whenever the key has one.
   In *PIN + touch* mode the credential is also created with `credProtect` level 3
   (*user verification required*): the key itself then refuses every assertion made without its
   PIN, so the PIN is enforced by the key rather than by FidoLogon. Keys that do not advertise
   `credProtect` (CTAP 2.0) are refused for this mode, and enrollment checks right after creation
   that a silent probe without PIN no longer finds the credential.
3. An assertion with a random 32-byte salt returns the `hmac-secret` output, with the PIN in
   *PIN + touch* mode and without it in *touch only* mode (CTAP 2.1 keys return different
   outputs with and without user verification, so sign-in must use the same mode).
4. `key = HMAC-SHA256(hmac-secret output, "fidologon/v1/password-key")`.
5. The password (UTF-16LE) is encrypted with AES-256-GCM, random 96-bit nonce, and
   AAD = `"fidologon/v1|" + record id + "|" + user SID` (a blob cannot be moved to another record or account).
6. The record is stored in the registry, with the key's USB vendor/product id and its AAGUID (model).

When the administrator restricted the key models (see *Key models* below), step 2 also checks the
attestation returned by the key before anything is stored.

## Sign-in

1. LogonUI loads the provider for `CPUS_LOGON` / `CPUS_UNLOCK_WORKSTATION` (never for Remote Desktop).
2. For each user tile with enrolled keys, a credential is shown under *Sign-in options*.
3. While the tile is selected, a background thread lists the plugged FIDO HID devices once a second
   and keeps those whose USB vendor/product id matches an enrolled key of the account (no data is
   exchanged). The tile shows what to do: *plug in your security key*, *leave only one plugged in*
   when several such keys are plugged, or the PIN field when the key's model matches a
   *PIN + touch* key. For a single key, its *touch only* credentials are probed silently
   (`up=false`); when one is found, the tile announces the touch and waits for it right away: no
   PIN, no Enter. The thread reports to a message-only window of the LogonUI thread, which updates
   the fields; it never calls LogonUI itself.
4. After Enter on the PIN (or right away for a *touch only* key), the same thread unlocks the
   password while the tile shows *Touch your security key*, then the provider raises
   `CredentialsChanged`: LogonUI gets this tile as default with auto logon and asks it for the
   serialization. To unlock, the thread lists the plugged FIDO HID devices and keeps only those whose USB
   vendor/product id matches an enrolled key: other devices, possibly hostile, are never opened
   (the HID enumeration itself does not exchange data with them). If every enrolled key of the
   account needs the PIN and none was typed, it stops here. It then silently probes (`up=false`,
   no PIN, 3-second timeout) each enrolled credential to find the key. This finds *touch only* credentials only:
   `credProtect` hides *PIN + touch* credentials from requests without the PIN. If none is found
   and the account has *PIN + touch* keys, the provider requires the PIN and exactly one plugged
   FIDO2 key with a PIN set (otherwise it asks to unplug the other keys, so the PIN is never tried
   on a foreign key), then probes that key with the PIN, still without touch.
5. It requests the `hmac-secret` output (touch, plus PIN when required), decrypts the password and
   returns a `KERB_INTERACTIVE_UNLOCK_LOGON` (password protected with `CredProtect`) for the
   *Negotiate* package. Windows performs the actual logon.
6. Before returning, it writes the device path, user SID, record id and its own session id to the
   volatile key `HKLM\SOFTWARE\FidoLogon\Runtime\LastAuth`.

## Lock on removal

The service handles session events:

- *logon*, *unlock*, *console connect*: it consumes the `Runtime\LastAuth` record only if it was
  written for this session (a record of another session is left for that session's event). If it
  belongs to the session's user and is less than 2 minutes old, the session is bound to that
  device path; the binding is also saved in `Runtime\Sessions\{session id}`. An activation
  without such a record (password, other provider) removes any binding of the session.
- *lock*, *logoff*, *disconnect*: the binding is dropped.

At start, the service reloads the saved bindings whose session still belongs to the same user, so
a service restart does not drop the protection of open sessions (the key is volatile: a reboot
clears it).

Every 500 ms, the service checks that each bound device path is still a present HID interface
(`CM_Get_Device_Interface_List`). Three failed checks in a row count as a removal (fail closed).
When the key is gone, the service reads the lock-on-removal option of the record that opened the
session: the key's `LockOnRemoval` override if set, else the machine-wide `LockOnKeyRemoval`
(records removed meanwhile use the machine-wide option; if the options cannot be read, the session
is locked). When the option is off, the binding is dropped. When it is on, it starts
`FidoLogon.Lock.exe` in the session (`CreateProcessAsUser`); if that fails, it disconnects the
session, which also returns to the sign-in screen. The binding is kept until the session lock event
arrives, and the lock is attempted again every 5 seconds until then. Failures are logged as warnings
in the *Application* event log (source *FidoLogon*).

The option is read when the key disappears, so changing it applies to sessions already open.

Sessions opened or unlocked with the password are never bound, so removing a key does not affect them.

## Registry layout

`HKLM\SOFTWARE\FidoLogon` (DACL: SYSTEM and Administrators only, applied by FidoLogon):

| Value / key | Type | Meaning |
|---|---|---|
| `AllowPasswordFallback` | DWORD | 1 (default) keeps the password tile, 0 hides it (see below) |
| `LockOnKeyRemoval` | DWORD | 1 (default) locks the session when the key that opened it is removed, 0 does not |
| `Keys\{id}\UserSid`, `UserName`, `Label`, `RpId` | SZ | account and display data |
| `Keys\{id}\CredentialId`, `HmacSalt`, `EncryptedPassword` | BINARY | FIDO2 credential id, hmac-secret salt, `version(1) ‖ nonce(12) ‖ ciphertext ‖ tag(16)` |
| `Keys\{id}\RequirePin` | DWORD | 1 = PIN + touch, 0 = touch only |
| `Keys\{id}\CreatedUnix` | QWORD | enrollment time |
| `Keys\{id}\LockOnRemoval` | DWORD | optional override of `LockOnKeyRemoval` for this key (1 lock, 0 do nothing; absent = default) |
| `Keys\{id}\VendorId`, `ProductId` | DWORD | USB identifiers of the key: only matching devices are opened at sign-in |
| `Keys\{id}\Aaguid` | SZ | key model reported by the attestation |
| `AllowedModels\{aaguid}\Description`, `Status` | SZ | allowed key model and its latest FIDO Metadata Service status |
| `AllowedModels\{aaguid}\Root0`… | BINARY | attestation root certificates published for the model |
| `AllowCertifiedModels` | DWORD | 1 also allows every `CertifiedModels` entry (absent: 0, but the service sets it from the installer choice, on by default) |
| `CertifiedModels\{aaguid}\…` | | same layout as `AllowedModels`: every FIDO2 model of the last imported BLOB (about 350 models, 550 KB of certificates), replaced as a whole at each import |
| `MetadataNumber`, `MetadataNextUpdate` | DWORD, SZ | serial number and next update date (yyyy-MM-dd) of the BLOB the certified models come from |
| `AutoSyncMetadata` | DWORD | 1 lets the service download a new BLOB when the imported one is outdated (absent: 0, set like `AllowCertifiedModels`) |
| `Runtime\LastAuth\` (volatile) | | last key sign-in, consumed by the service |
| `Runtime\Sessions\{session id}\` (volatile) | | sessions bound to a key, reloaded if the service restarts |

The BLOB itself is never written to disk: it is verified in memory, and only its number, its next
update date and its certified models are kept, in this registry key (which only SYSTEM and
Administrators can write). Versions before 0.1.0-rc.5 kept it in `%ProgramData%\FidoLogon\mds.jwt`,
a folder a standard user could create first; that file is no longer read and can be deleted.

The installer option *Enroll only key models certified by the FIDO Alliance* (`MODEL_POLICY`, on by
default) is recorded in `HKLM\SOFTWARE\FidoLogon Installer` (`ModelPolicyOff` when unticked). At
start, the service sets `AllowCertifiedModels` and `AutoSyncMetadata` from it, each only if it was
never set: later changes made with the CLI or the configuration tool are kept.

## Password fallback filter

With `AllowPasswordFallback = 0`, the filter removes the Windows password provider from the sign-in
and unlock screens, **unless** any of these is true (to avoid lock-outs):

- the computer is in safe mode;
- the session is a Remote Desktop session;
- the FidoLogon provider is disabled (`Disabled` value) or filtered out;
- an enabled local account has no enrolled key;
- the computer is joined to an Active Directory domain or to Microsoft Entra ID (or the join state
  cannot be read): domain and Entra users cannot have FidoLogon keys;
- the configuration cannot be read.

Windows Hello PIN/biometrics and UAC prompts are not affected.

## Key models (attestation)

By default only models certified by the FIDO Alliance can be enrolled (step 3 below, turned on by
the installer). Until the service has downloaded the metadata (about 2 minutes after it starts),
enrollment is refused with a message that says so. With the policy turned off and no allowed
model, any FIDO2 key with `hmac-secret` can be enrolled. An administrator can also restrict
enrollment to chosen models:

1. Download the FIDO Metadata Service BLOB and import it: `fidologon models sync` or
   *Key models… → Synchronize* downloads it from https://mds3.fidoalliance.org/; on an offline
   computer, download it elsewhere and use `fidologon models import <file>` or *Import metadata…*.
   With `AutoSyncMetadata`, the service checks once a day and downloads a new BLOB once the
   imported one has reached its *next update* date (failures are logged as warnings). The BLOB is
   a JWT: FidoLogon checks its signature and that the signing certificate is issued to
   `mds.fidoalliance.org` and chains to the embedded *GlobalSign Root CA - R3* (expires 2029-03-18;
   revocation is not checked, the computer may be offline). An older BLOB than the imported one is
   refused, and importing refreshes the roots and status of the allowed models.
2. Allow models by AAGUID (`fidologon models search` / `allow`). Their attestation root
   certificates and status are copied to `AllowedModels`. Revoked or compromised models
   (`REVOKED`, `USER_VERIFICATION_BYPASS`, `ATTESTATION_KEY_COMPROMISE`,
   `USER_KEY_REMOTE_COMPROMISE`, `USER_KEY_PHYSICAL_COMPROMISE`) cannot be allowed, and are
   refused at enrollment if a later BLOB reports them.

3. Or allow every model the BLOB describes with attestation roots: `fidologon models certified on`
   or *Also allow every model certified in the FIDO metadata*. Each import replaces the
   `CertifiedModels` list, so new models are accepted and revoked ones refused after the next
   synchronization; explicitly allowed models still count.

While the list is not empty, or certified models are allowed, enrollment requires: an attestation with a certificate chain whose
signature libfido2 verified (`fido_cred_verify`), an AAGUID in the list, a leaf certificate whose
AAGUID extension (`1.3.6.1.4.1.45724.1.1.4`), when present, matches, and a chain (CryptoAPI, with
only the model's roots trusted) to one of the model's roots. Certificate expiry and revocation are
not checked. Keys already enrolled are not affected by later changes of the list.

## Security notes

- The encrypted password is useless without the physical key (and its PIN in *PIN + touch* mode).
  In *PIN + touch* mode the PIN is enforced by the key (`credProtect`): changing `RequirePin` in the
  registry does not let anyone use the key without it.
  An administrator of the machine can still reset any local password; FidoLogon does not protect
  against local administrators.
- In *touch only* mode, anyone holding the key can sign in: use it only where that is acceptable.
- The key PIN is protected by the key itself (retry counter, lockout).
- Device paths are USB HID interface paths: NFC and Bluetooth keys are not supported.
- The plaintext password exists briefly in LogonUI memory before being protected and passed to
  LSA, as with any password-based credential provider. Buffers are wiped after use.
- In the .NET tools, passwords and PINs never become `string`s (except when the CLI reads piped
  input): they are copied from the console or from WPF's `SecurePassword` into pinned buffers that
  are passed to the native API without copies, excluded from Windows Error Reporting dumps
  (`WerRegisterExcludedMemoryBlock`) and zeroed after use.
- The PIN field of the sign-in tile has no *reveal* button.
