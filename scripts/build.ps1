<#
.SYNOPSIS
    Builds, tests and packages FidoLogon.

.DESCRIPTION
    1. Native components (CMake + vcpkg, static CRT): credential provider, native API, lock helper.
    2. Native tests (CTest).
    3. .NET components (CLI, configuration GUI, service) and their tests.
    4. Staging folder with every file the installer ships.
    5. Packaging by package.ps1 (unless -SkipPackage): optional Authenticode signing of the
       binaries (see docs/signing.md), MSI installer (WiX) and zip.

.EXAMPLE
    ./scripts/build.ps1
    ./scripts/build.ps1 -Version 1.2.0 -CertificateThumbprint 0123...ABCD
#>
[CmdletBinding()]
param(
    # Product version (major.minor.patch). Pre-release suffixes are kept in InformationalVersion.
    [string] $Version = "0.0.0",
    [switch] $SkipTests,
    [switch] $SkipInstaller,
    # Stop after the staging folder: no signing, MSI or zip.
    [switch] $SkipPackage,
    # Sign binaries and MSI with this certificate of Cert:\CurrentUser\My (see import-signing-certificate.ps1).
    [string] $CertificateThumbprint
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$buildDir = Join-Path $root "build"
$nativeBuildDir = Join-Path $buildDir "native"
$stagingDir = Join-Path $buildDir "staging"

if ($Version -notmatch '^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?$') {
    throw "Version must look like 1.2.3 or 1.2.3-beta.1, got '$Version'."
}
$numericVersion = "$($Matches[1]).$($Matches[2]).$($Matches[3])"

function Invoke-Checked {
    param([string] $Description, [scriptblock] $Command)
    Write-Host "==> $Description" -ForegroundColor Cyan
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

function Initialize-VsEnvironment {
    if (Get-Command cl.exe -ErrorAction SilentlyContinue) {
        return
    }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vsPath) {
        throw "Visual Studio with the C++ desktop workload is required."
    }
    Import-Module (Join-Path $vsPath "Common7\Tools\Microsoft.VisualStudio.DevShell.dll")
    Microsoft.VisualStudio.DevShell\Enter-VsDevShell -VsInstallPath $vsPath -SkipAutomaticLocation -DevCmdArguments "-arch=x64 -host_arch=x64" | Out-Null
    if (-not $env:VCPKG_ROOT -and (Test-Path (Join-Path $vsPath "VC\vcpkg\vcpkg.exe"))) {
        $env:VCPKG_ROOT = Join-Path $vsPath "VC\vcpkg"
    }
}

Initialize-VsEnvironment
if (-not $env:VCPKG_ROOT) {
    throw "VCPKG_ROOT is not set and no Visual Studio bundled vcpkg was found."
}

# --- Native ---------------------------------------------------------------
Push-Location (Join-Path $root "native")
try {
    Invoke-Checked "Configure native build" { cmake --preset x64-release "-DFIDOLOGON_VERSION=$numericVersion" }
    Invoke-Checked "Build native components" { cmake --build --preset x64-release }
    if (-not $SkipTests) {
        Invoke-Checked "Run native tests" { ctest --preset x64-release }
    }
} finally {
    Pop-Location
}

# --- .NET -----------------------------------------------------------------
$dotnetProps = @("-c", "Release", "-p:Version=$Version", "-p:FileVersion=$numericVersion.0",
    "-p:AssemblyVersion=$numericVersion.0", "-p:NativeBinDir=$nativeBuildDir")
$solution = Join-Path $root "FidoLogon.slnx"
Invoke-Checked "Build .NET components" { dotnet build $solution @dotnetProps }
if (-not $SkipTests) {
    Invoke-Checked "Run .NET tests" { dotnet test $solution @dotnetProps --no-build }
}

# --- Staging ----------------------------------------------------------------
if (Test-Path $stagingDir) {
    Remove-Item -Recurse -Force $stagingDir
}
New-Item -ItemType Directory -Force $stagingDir | Out-Null
foreach ($project in "FidoLogon.Cli", "FidoLogon.Config", "FidoLogon.Service") {
    $projectPath = Join-Path $root "src\$project\$project.csproj"
    Invoke-Checked "Publish $project" {
        dotnet publish $projectPath @dotnetProps -r win-x64 --self-contained true -o $stagingDir
    }
}
foreach ($file in "credential_provider\FidoLogonCredentialProvider.dll", "native_api\fidologon_native.dll",
    "lock\FidoLogon.Lock.exe") {
    Copy-Item (Join-Path $nativeBuildDir $file) $stagingDir -Force
}
Copy-Item (Join-Path $root "LICENSE") (Join-Path $stagingDir "LICENSE.txt") -Force
Copy-Item (Join-Path $root "THIRD-PARTY-NOTICES.md") $stagingDir -Force
# Full license texts of the statically linked native libraries, as installed by vcpkg.
$licenses = Get-ChildItem (Join-Path $buildDir "vcpkg_installed\x64-windows-static\share") -Filter copyright -Recurse |
    Sort-Object FullName | ForEach-Object {
        "=" * 78
        $_.Directory.Name
        "=" * 78
        Get-Content $_.FullName -Raw
    }
Set-Content -Path (Join-Path $stagingDir "THIRD-PARTY-LICENSES.txt") -Value $licenses -Encoding utf8
Copy-Item (Join-Path $root "scripts\emergency-disable.ps1") $stagingDir -Force

if (-not $SkipPackage) {
    & (Join-Path $PSScriptRoot "package.ps1") -Version $Version -StagingDir $stagingDir `
        -SkipInstaller:$SkipInstaller -CertificateThumbprint $CertificateThumbprint
}
