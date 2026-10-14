<#
.SYNOPSIS
    Authenticode-signs files with a certificate from the current user's store (SHA-256, RFC 3161 timestamp).

.DESCRIPTION
    The certificate is selected by thumbprint, so no key file or password ever appears on the
    signtool command line. Use scripts/import-signing-certificate.ps1 to put a PFX into the store.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string[]] $Files,
    [Parameter(Mandatory)] [string] $CertificateThumbprint,
    [string] $TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$CertificateThumbprint = $CertificateThumbprint -replace '\s', ''
if ($CertificateThumbprint -notmatch '^[0-9A-Fa-f]{40}$') {
    throw "Invalid certificate thumbprint '$CertificateThumbprint'."
}
$certificate = Get-Item "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
if (-not $certificate -or -not $certificate.HasPrivateKey) {
    throw "No certificate with a private key and thumbprint $CertificateThumbprint in Cert:\CurrentUser\My."
}

function Find-SignTool {
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    $kitsRoot = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots" -ErrorAction SilentlyContinue).KitsRoot10
    if (-not $kitsRoot) {
        $kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\"
    }
    $candidate = Get-ChildItem (Join-Path $kitsRoot "bin") -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -like "*\x64" } |
        Sort-Object { [version]($_.Directory.Parent.Name -replace '[^0-9.]', '') } -Descending |
        Select-Object -First 1
    if (-not $candidate) {
        throw "signtool.exe not found: install the Windows SDK."
    }
    return $candidate.FullName
}

$signTool = Find-SignTool
foreach ($file in $Files) {
    Write-Host "Signing $file"
    # Timestamp servers are occasionally unavailable: retry a few times.
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        & $signTool sign /fd SHA256 /s My /sha1 $CertificateThumbprint /tr $TimestampUrl /td SHA256 /q $file
        if ($LASTEXITCODE -eq 0) {
            break
        }
        if ($attempt -eq 3) {
            throw "signtool failed for $file"
        }
        Start-Sleep -Seconds (5 * $attempt)
    }
}
