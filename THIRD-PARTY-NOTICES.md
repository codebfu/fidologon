# Third-party notices

FidoLogon is licensed under the GNU General Public License v3.0 or later
(see `LICENSE`). It includes the following third-party components, whose
licenses are compatible with GPL-3.0. The full license texts are shipped in
`THIRD-PARTY-LICENSES.txt` next to the installed binaries (generated at build
time from the vcpkg packages).

| Component | Used for | License |
|---|---|---|
| [libfido2](https://github.com/Yubico/libfido2) (Yubico) | Talking to FIDO2 security keys | BSD-2-Clause |
| [libcbor](https://github.com/PJK/libcbor) | CBOR encoding (libfido2 dependency) | MIT |
| [OpenSSL 3](https://www.openssl.org/) | Cryptography (libfido2 dependency) | Apache-2.0 |
| [zlib](https://zlib.net/) | Compression (libfido2 dependency) | Zlib |
| [.NET runtime](https://github.com/dotnet/runtime) | Configuration tools and service (self-contained) | MIT, see [THIRD-PARTY-NOTICES](https://github.com/dotnet/runtime/blob/main/THIRD-PARTY-NOTICES.TXT) |
| [System.Diagnostics.EventLog, System.ServiceProcess.ServiceController](https://github.com/dotnet/runtime) | Service hosting and logging | MIT |

Build-time only (not part of the shipped binaries):

| Component | License |
|---|---|
| [WiX Toolset 5](https://github.com/wixtoolset/wix) | MS-RL |
| [vcpkg](https://github.com/microsoft/vcpkg) | MIT |
| [xUnit.net](https://github.com/xunit/xunit) | Apache-2.0 |

OpenSSL is used (rather than LibreSSL) on purpose: OpenSSL 3 is distributed
under Apache-2.0, which is compatible with GPL-3.0.
