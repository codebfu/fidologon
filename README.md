# FidoLogon

> [!WARNING]
> FidoLogon replaces part of the Windows sign-in screen. Keep the password sign-in enabled until
> your keys work, and read the [recovery guide](docs/recovery.md) before installing it on a
> machine you care about.

Sign in to **local Windows accounts** with a **FIDO2 security key** (YubiKey, SoloKey, Feitian,
Token2, …) and **lock the session automatically when the key is removed** (optional, on by default).

- Sign-in with the key's **PIN + touch**, or **touch only** (chosen per key at enrollment).
- Several keys per account (keep a backup key) and several accounts per computer.
- The Windows password tile can be kept as a fallback or hidden (per-computer option).
- Unplugging the key that opened the session locks it. Sessions opened with the password are not affected.
  This can be turned off for the whole computer, and overridden per key (always lock / never lock).
- Configuration with a GUI (`FidoLogon configuration`) or the command line (`fidologon.exe`).
- Only key models certified by the FIDO Alliance by default, checked against the key's attestation
  and the FIDO Metadata Service (downloaded daily, or imported offline); can be narrowed to chosen
  models or turned off.

Not supported: Remote Desktop, NFC/Bluetooth keys, Microsoft/Entra ID/domain accounts (for
Entra ID, use the built-in Windows security-key sign-in instead).

## How it works

```
 Sign-in screen (LogonUI)                    FidoLogon service (LocalSystem)
 ┌─────────────────────────────┐              ┌──────────────────────────────┐
 │ FidoLogon credential provider│  key path    │ binds session ⇄ key device   │
 │  1. find an enrolled key     │ ───────────► │ polls device presence        │
 │  2. PIN + touch → hmac-secret│  (registry)  │ key gone → lock the session  │
 │  3. decrypt stored password  │              └──────────────────────────────┘
 │  4. hand it to Windows (LSA) │
 └─────────────────────────────┘
```

At enrollment, FidoLogon creates a FIDO2 credential on the key and uses the key's
`hmac-secret` extension to derive an AES-256-GCM key, which encrypts the account's Windows
password. The encrypted password is stored in `HKLM\SOFTWARE\FidoLogon` (readable by SYSTEM and
Administrators only) and can only be decrypted by the same key, with its PIN when required.
Windows still verifies the password, so **changing the account password requires enrolling the
key again**. Details: [docs/architecture.md](docs/architecture.md).

## Requirements

- Windows 10 or 11, 64-bit (x64).
- A FIDO2 key supporting the `hmac-secret` extension (all current YubiKey 5, Security Key series and most FIDO2 keys).
  *PIN + touch* mode also needs the CTAP 2.1 `credProtect` extension, so that the key itself refuses
  to work without its PIN; older CTAP 2.0 keys can only be enrolled in *touch only* mode.
- Keep only one enrolled key plugged in when signing in: the PIN is never sent to a key that might be
  someone else's.
- A local account with a password.
- Administrator rights to install and to enroll keys.

## Installation

1. Download `FidoLogon-<version>-x64.msi` from the [releases](https://github.com/codebfu/fidologon/releases).
2. Releases are signed with a self-signed certificate. To avoid SmartScreen/antivirus warnings,
   trust it first (as administrator, after checking `SHA256SUMS.txt`):
   `powershell -ExecutionPolicy Bypass -File trust-certificate.ps1 -CertificatePath FidoLogon-CodeSigning.cer`,
   or tick *Trust the FidoLogon code-signing certificate* in the installer.
   See [docs/signing.md](docs/signing.md).
3. Install the MSI. Its *Installation options* page chooses the shortcuts (Start menu, desktop,
   emergency disable script) and whether to trust the certificate.
4. Open **FidoLogon configuration** from the Start menu and click **Add key…**. The key blinks
   twice: a window tells you when to touch it.

For an unattended installation, set the options on the command line (1 = on, 0 = off):

```
msiexec /i FidoLogon-<version>-x64.msi /qn STARTMENU_SHORTCUT=1 DESKTOP_SHORTCUT=1 EMERGENCY_SHORTCUT=0 TRUST_CERTIFICATE=0
```

An upgrade keeps the choices of the installed version unless the command line sets them.

At the sign-in or lock screen, choose your account, then **Sign-in options → key icon**. The tile
follows the plugged key: it asks you to plug it in, to leave only one key plugged in, or for its
PIN, and says when to touch it. A *touch only* key signs in with a touch alone.

### Command line

```
fidologon devices
fidologon enroll --user alice --label "Blue YubiKey" --mode pin
fidologon list
fidologon test <id>
fidologon remove <id>
fidologon config password-fallback off
fidologon config lock-on-removal off          # machine-wide default
fidologon set <id> --lock-on-removal on       # per-key override (default|on|off)
fidologon models sync                         # download the FIDO Metadata Service BLOB
fidologon models import blob.jwt              # or import one downloaded from https://mds3.fidoalliance.org/
fidologon models search "YubiKey 5"
fidologon models allow <aaguid>               # only allowed models can then be enrolled
fidologon models certified on|off             # allow every model certified in the metadata (default on)
fidologon config metadata-auto-sync on|off    # the service keeps the metadata up to date (default on)
```

By default only key models certified by the FIDO Alliance can be enrolled: the service downloads
the FIDO Metadata Service data about 2 minutes after it starts, then daily. On an offline computer,
import the BLOB (`fidologon models import`) or untick *Enroll only key models certified by the FIDO
Alliance* in the installer (or run `fidologon models certified off`).

Run `fidologon help` for all options. An administrator command prompt is required.

## Recovery

If you cannot sign in, see [docs/recovery.md](docs/recovery.md). The password tile is never hidden
in safe mode, in Remote Desktop sessions, or while any enabled local account has no enrolled key.

## Building

Requirements: Visual Studio 2022/2026 with the *Desktop development with C++* workload (CMake,
vcpkg), the .NET 10 SDK.

```powershell
./scripts/build.ps1                  # native + .NET build, all tests, MSI and zip in artifacts/
./scripts/build.ps1 -Version 1.2.3   # stamp a version
```

Manual test procedure on a virtual machine: [docs/testing.md](docs/testing.md).

## Releases and versioning

Versions follow [Semantic Versioning](https://semver.org/). To publish a release, push a tag:

```
git tag v1.0.0
git push origin v1.0.0
```

The [build workflow](.github/workflows/build.yml) builds and tests every push and pull request.
For `v*.*.*` tags it also signs the binaries and the MSI and creates a GitHub release with the MSI,
the zip, the public certificate and `SHA256SUMS.txt`. Tags with a suffix (`v1.0.0-beta.1`) create
pre-releases.

## License

FidoLogon is free software: you can redistribute it and/or modify it under the terms of the
GNU General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version. See [LICENSE](LICENSE) and
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
