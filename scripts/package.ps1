<#
.SYNOPSIS
    Packages a staging folder produced by build.ps1: optional signing, MSI installer (WiX) and zip.

.DESCRIPTION
    Runs on its own so that the release workflow can sign in a separate job that builds nothing
    and restores no cache (see docs/signing.md).

.EXAMPLE
    ./scripts/package.ps1 -Version 1.2.0
    ./scripts/package.ps1 -Version 1.2.0 -StagingDir staging -CertificateThumbprint 0123...ABCD
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Version,
    [string] $StagingDir,
    [string] $OutputDir,
    [switch] $SkipInstaller,
    # Sign binaries and MSI with this certificate of Cert:\CurrentUser\My (see import-signing-certificate.ps1).
    [string] $CertificateThumbprint
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$buildDir = Join-Path $root "build"
if (-not $StagingDir) {
    $StagingDir = Join-Path $buildDir "staging"
}
if (-not $OutputDir) {
    $OutputDir = Join-Path $root "artifacts"
}
$StagingDir = (Resolve-Path $StagingDir).Path

if ($Version -notmatch '^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?$') {
    throw "Version must look like 1.2.3 or 1.2.3-beta.1, got '$Version'."
}
$numericVersion = "$($Matches[1]).$($Matches[2]).$($Matches[3])"

if ($CertificateThumbprint) {
    & (Join-Path $PSScriptRoot "sign-files.ps1") -CertificateThumbprint $CertificateThumbprint `
        -Files (Get-ChildItem $StagingDir -Recurse -Include "FidoLogon*.dll", "FidoLogon*.exe", "fidologon*.dll", "fidologon*.exe" | ForEach-Object FullName)
}

New-Item -ItemType Directory -Force $OutputDir | Out-Null
if (-not $SkipInstaller) {
    $msiName = "FidoLogon-$Version-x64.msi"
    # The installer can offer to trust the public signing certificate: it looks it up by thumbprint.
    $signingCertificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2 `
        (Join-Path $root "certs\FidoLogon-CodeSigning.cer")
    Write-Host "==> Build MSI" -ForegroundColor Cyan
    # --no-incremental: WiX does not track the properties, so a new version must force a full build.
    dotnet build (Join-Path $root "installer\FidoLogon.Installer.wixproj") -c Release --no-incremental `
        "-p:ProductVersion=$numericVersion" "-p:StagingDir=$StagingDir\" "-p:OutputName=FidoLogon" `
        "-p:SigningCertThumbprint=$($signingCertificate.Thumbprint)" -o (Join-Path $buildDir "installer")
    if ($LASTEXITCODE -ne 0) {
        throw "Build MSI failed with exit code $LASTEXITCODE."
    }
    Copy-Item (Join-Path $buildDir "installer\FidoLogon.msi") (Join-Path $OutputDir $msiName) -Force
    if ($CertificateThumbprint) {
        & (Join-Path $PSScriptRoot "sign-files.ps1") -CertificateThumbprint $CertificateThumbprint `
            -Files (Join-Path $OutputDir $msiName)
    }
}

$zipPath = Join-Path $OutputDir "FidoLogon-$Version-x64.zip"
if (Test-Path $zipPath) {
    Remove-Item $zipPath
}
Compress-Archive -Path (Join-Path $StagingDir "*") -DestinationPath $zipPath
Write-Host "Artifacts written to $OutputDir" -ForegroundColor Green
