# Testing

## Automated tests

`scripts/build.ps1` runs both suites; they need no security key.

- **Native** (`native/tests`, CTest): cryptography against RFC 4231 / NIST GCM vectors, registry
  storage, enrollment and unlock with a simulated authenticator (PIN, touch-only, wrong PIN,
  unplugged key, backup key, record tampering), `KERB_INTERACTIVE_UNLOCK_LOGON` packing,
  `CredProtect`, the password filter rules, and the credential provider end to end
  (user tiles, `GetSerialization`, `ReportResult`, DLL exports and resources).
- **.NET** (`tests/FidoLogon.Tests`, xUnit): the native API wrapper, the command-line tool
  (full key lifecycle with a simulated key), the service's session/key binding logic, secret
  buffers, and FIDO Metadata Service BLOB verification and key model policy (with a test PKI).

Both suites use the test build of the native code (simulated authenticator and test hooks), which
is never packaged. The native tests also generate real attestation certificate chains with
CryptoAPI.

The real FIDO Metadata Service BLOB can be checked against the embedded trust anchor by setting
`FIDOLOGON_TEST_MDS_BLOB` to a file downloaded from https://mds3.fidoalliance.org/ before running
the .NET tests (the test passes without doing anything when the variable is not set).

Tests write only under `HKCU\Software\FidoLogonTests` and remove it afterwards.

## Manual test on a virtual machine

Credential providers run inside the sign-in screen: always test a new build in a virtual machine
with a snapshot, never first on your workstation. Hyper-V does not pass USB devices through
easily; VMware Workstation or VirtualBox (with its extension pack) do.

Setup:

1. Windows 10/11 x64 VM, a local administrator account with a password, and a second local account.
2. Take a snapshot.
3. Pass the security key through to the VM.
4. Install the MSI. Check that the *FidoLogon* service is running.

Checklist:

| # | Scenario | Expected |
|---|---|---|
| 1 | `fidologon devices` (admin prompt) | The key is listed with *hmac-secret: yes* |
| 2 | Enroll the key in *PIN + touch* mode from the GUI | Two touches; key listed |
| 3 | `fidologon test <id>` with the right PIN, then a wrong PIN | OK, then *Incorrect security key PIN* |
| 4 | Sign out; at sign-in pick the account → *Sign-in options* → key icon, PIN, touch | Signed in |
| 5 | Unplug the key | Session locks within about 1 second |
| 6 | Unlock with the key | Unlocked; unplugging locks again |
| 7 | Unlock with the password, then unplug the key | Session stays unlocked |
| 8 | Wrong PIN / no key at sign-in | Clear error message on the tile |
| 9 | Enroll a second key for the same account; sign in with it | Works; unplugging it locks |
| 10 | Enroll a key in *touch only* mode; sign in without PIN | Works with a touch only |
| 11 | Change the account password, sign in with the key | *Windows rejected the password…*; re-enrolling fixes it |
| 12 | `fidologon config password-fallback off` with the second account not enrolled | Password tile still shown |
| 13 | Enroll the second account too, sign out | Password tile hidden |
| 14 | Boot into safe mode | Password tile shown |
| 15 | Run `emergency-disable.ps1` | Password tile back, FidoLogon tile gone |
| 16 | Uninstall | Tile, filter and service removed |
| 17 | Remote Desktop into the VM | No FidoLogon tile, password works |
| 18 | `fidologon config lock-on-removal off`; sign in with the key, unplug it | Session stays unlocked (event log: *session left open*) |
| 19 | Still off: `fidologon set <id> --lock-on-removal on`, sign in with that key, unplug it | Session locks |
| 20 | `fidologon config lock-on-removal on`, `fidologon set <id> --lock-on-removal off`, sign in, unplug | Session stays unlocked; other keys still lock |
| 21 | `fidologon devices` with a CTAP 2.0 key (if available), then enroll it with `--mode pin` | *credProtect: no*; enrollment refused with *cannot enforce its PIN* |
| 22 | Plug a second FIDO2 key, sign in with a *PIN + touch* key | *Several security keys are plugged in*; the other key's PIN retries are unchanged |
| 23 | Set `Keys\{id}\RequirePin` to 0 on a *PIN + touch* key, sign in without PIN | Refused (*No enrolled security key is plugged in*) |
| 24 | Plug a FIDO key of another brand next to the enrolled one, sign in | Works; *Several security keys are plugged in* only appears with a second key of the same model |
| 25 | Restart the *FidoLogon* service while signed in with the key, then unplug the key | Session locks (binding reloaded) |
| 26 | `fidologon models import` the BLOB from https://mds3.fidoalliance.org/, `models search` your key, `models allow <aaguid>`, enroll the key | Enrollment works; `fidologon list` shows the AAGUID |
| 27 | With the list from 26, enroll a key of another model | Refused: *This security key model is not allowed…* |
| 28 | `fidologon models remove <aaguid>` | Every model can be enrolled again |
| 29 | Sign-in tile: type a PIN | No *reveal* (eye) button in the PIN field |
| 30 | Select the key tile with no key plugged, then plug the *PIN + touch* key | *Plug in your security key*, then the PIN field appears |
| 31 | Type the PIN, press Enter | Title *Touch your security key*; signed in after the touch, without pressing anything else |
| 32 | Select the tile with a *touch only* key plugged | *Touch your security key* right away; a touch signs in |
| 33 | Wait 30 s without touching (touch only) | *No touch detected…*; unplugging and plugging the key in again restarts the wait |
| 34 | Plug two enrolled keys, select the tile | *Leave only one plugged in*; no PIN field |
| 35 | Enroll a key with a PIN from the GUI | A *Security key PIN* window asks for the PIN (a wrong PIN asks again, with the error), then a *Touch your security key* window shows *Touch 1 of 2*, then *Touch 2 of 2* |
| 36 | `fidologon models sync`, then `fidologon models certified on`, enroll a genuine key | BLOB downloaded; enrollment works |
| 37 | Fresh installation with the default options | `fidologon config` shows certified models and metadata-auto-sync on; about 2 minutes after the service starts, *Application* log: *Downloaded FIDO Metadata Service BLOB*; nothing is written to `%ProgramData%\FidoLogon` |
| 38 | Install the MSI with the UI: options page, tick the desktop and emergency shortcuts and the certificate | Shortcuts created with the FidoLogon icon; certificate in *Trusted Root* and *Trusted Publishers*; uninstall removes them |
| 39 | Upgrade with the next MSI silently (`msiexec /i … /qn`) | Same shortcuts and certificate trust as before |
| 40 | Restart with the enrolled key already plugged, select the key tile | The PIN field or *Touch your security key* within a few seconds, never *not enrolled* |
| 41 | Select the key tile, then plug the key | The tile reacts about 1 second after Windows sees the key (in a VM, add the USB passthrough delay) |
| 42 | Look at *Sign-in options* | The FidoLogon option is a white outline glyph on a transparent background, the size of the password glyph |
| 43 | Touch-only key: select the key tile, touch the blinking key | Signed in to the key's account; never back to the password tile |
| 44 | GUI: select an enrolled key, *Test* | A *Touch your security key* window shows while the key blinks, then *The key unlocks the stored credential* |
| 45 | Install an older MSI over a newer one (bundled .NET runtime older than the installed one) | Setup succeeds and the *FidoLogon* service runs |
| 46 | Fresh installation with *Enroll only key models certified by the FIDO Alliance* unticked | `fidologon config` shows certified models and metadata-auto-sync off; any FIDO2 key can be enrolled |
| 47 | Policy on, before the first download (or offline), enroll a key | Refused before any touch, with a message pointing to `fidologon models sync` |
| 48 | `fidologon models certified off`, then upgrade with the next MSI | The policy stays off |
| 49 | Session opened with a key, unplug it and plug it back within half a second (same port) | The session is locked |
| 50 | Session opened with a key: stop the *FidoLogon* service, unplug and plug the key back, start the service | The session is locked at the service's first check |

Debug output of the credential provider (`OutputDebugString`) can be watched with Sysinternals
*DebugView* (capture *Global Win32*). The service logs to the *Application* event log, source *FidoLogon*.
