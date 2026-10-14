<#
.SYNOPSIS
    Imports the code-signing PFX into the current user's certificate store, or removes it.

.DESCRIPTION
    Import: reads the PFX from -PfxPath or, if omitted, from the base64 environment variable
    FIDOLOGON_SIGNING_PFX_BASE64; reads its password from -PasswordPath or, if omitted, from the
    environment variable FIDOLOGON_SIGNING_PASSWORD. The PFX is imported from memory (no temporary
    file), with a non-exportable private key, into Cert:\CurrentUser\My. Writes the thumbprint to
    the pipeline, to pass to sign-files.ps1 or package.ps1.

    Neither the key nor the password is ever passed on a command line.

    Remove: -RemoveThumbprint deletes the certificate and its private key from the store.

.EXAMPLE
    $thumbprint = ./scripts/import-signing-certificate.ps1 -PfxPath .secrets/FidoLogon-CodeSigning.pfx `
        -PasswordPath .secrets/FidoLogon-CodeSigning.password.txt
    ./scripts/build.ps1 -Version 1.2.0 -CertificateThumbprint $thumbprint
    ./scripts/import-signing-certificate.ps1 -RemoveThumbprint $thumbprint
#>
[CmdletBinding(DefaultParameterSetName = "Import")]
param(
    [Parameter(ParameterSetName = "Import")] [string] $PfxPath,
    [Parameter(ParameterSetName = "Import")] [string] $PasswordPath,
    [Parameter(Mandatory, ParameterSetName = "Remove")] [string] $RemoveThumbprint
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($PSCmdlet.ParameterSetName -eq "Remove") {
    $RemoveThumbprint = $RemoveThumbprint -replace '\s', ''
    if ($RemoveThumbprint -notmatch '^[0-9A-Fa-f]{40}$') {
        throw "Invalid certificate thumbprint '$RemoveThumbprint'."
    }
    $path = "Cert:\CurrentUser\My\$RemoveThumbprint"
    if (Test-Path $path) {
        Remove-Item -Path $path -DeleteKey
        Write-Host "Removed signing certificate $RemoveThumbprint"
    }
    return
}

if ($PfxPath) {
    $pfxBytes = [IO.File]::ReadAllBytes((Resolve-Path $PfxPath))
} elseif ($env:FIDOLOGON_SIGNING_PFX_BASE64) {
    $pfxBytes = [Convert]::FromBase64String($env:FIDOLOGON_SIGNING_PFX_BASE64)
} else {
    throw "Give -PfxPath or set FIDOLOGON_SIGNING_PFX_BASE64."
}
if ($PasswordPath) {
    $password = (Get-Content -Path $PasswordPath -Raw).Trim()
} elseif ($env:FIDOLOGON_SIGNING_PASSWORD) {
    $password = $env:FIDOLOGON_SIGNING_PASSWORD
} else {
    throw "Give -PasswordPath or set FIDOLOGON_SIGNING_PASSWORD."
}

$flags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet -bor
    [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
$collection = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
try {
    $collection.Import($pfxBytes, $password, $flags)
} finally {
    [Array]::Clear($pfxBytes, 0, $pfxBytes.Length)
    $password = $null
}

$codeSigningOid = "1.3.6.1.5.5.7.3.3"
$certificate = $collection | Where-Object {
    $_.HasPrivateKey -and ($_.Extensions |
        Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } |
        ForEach-Object { $_.EnhancedKeyUsages } | Where-Object { $_.Value -eq $codeSigningOid })
} | Select-Object -First 1
if (-not $certificate) {
    throw "The PFX holds no code-signing certificate with a private key."
}

$store = New-Object Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
$store.Open("ReadWrite")
try {
    $store.Add($certificate)
} finally {
    $store.Close()
}
Write-Host "Imported signing certificate $($certificate.Thumbprint) ($($certificate.Subject))"
Write-Output $certificate.Thumbprint
