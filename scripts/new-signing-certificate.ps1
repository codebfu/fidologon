<#
.SYNOPSIS
    Creates the self-signed code-signing certificate used by the release pipeline.

.DESCRIPTION
    Writes to the git-ignored .secrets/ folder:
      - FidoLogon-CodeSigning.pfx        private key + certificate (BACK IT UP, keep it secret)
      - FidoLogon-CodeSigning.password.txt  PFX password
    and the public certificate to certs/FidoLogon-CodeSigning.cer (committed: machines
    import it to trust signed builds, see docs/signing.md).

    With -GitHubRepository, also stores SIGNING_CERT_PFX_BASE64 and SIGNING_CERT_PASSWORD
    as secrets of the release-signing GitHub Actions environment (requires an authenticated gh
    CLI and the environment, see docs/signing.md).
#>
[CmdletBinding()]
param(
    [string] $Subject = "CN=FidoLogon Code Signing",
    [int] $ValidityYears = 5,
    [string] $GitHubRepository,
    [switch] $Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$secretsDir = Join-Path $root ".secrets"
$certsDir = Join-Path $root "certs"
$pfxPath = Join-Path $secretsDir "FidoLogon-CodeSigning.pfx"
$passwordPath = Join-Path $secretsDir "FidoLogon-CodeSigning.password.txt"
$cerPath = Join-Path $certsDir "FidoLogon-CodeSigning.cer"

if ((Test-Path $pfxPath) -and -not $Force) {
    throw "$pfxPath already exists. Use -Force to replace it (signed builds would then need the new certificate)."
}
New-Item -ItemType Directory -Force $secretsDir, $certsDir | Out-Null

$certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject `
    -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy Exportable `
    -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears($ValidityYears)
try {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $password = [Convert]::ToBase64String($bytes)
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force

    Export-PfxCertificate -Cert $certificate -FilePath $pfxPath -Password $securePassword | Out-Null
    Export-Certificate -Cert $certificate -FilePath $cerPath -Type CERT | Out-Null
    Set-Content -Path $passwordPath -Value $password -NoNewline -Encoding ascii
} finally {
    # The PFX in .secrets/ is the only copy needed: do not leave the key in the user store.
    Remove-Item -Path "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -DeleteKey
}

Write-Host "Certificate $($certificate.Thumbprint) valid until $($certificate.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host "  private: $pfxPath"
Write-Host "  public:  $cerPath"

if ($GitHubRepository) {
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($pfxPath)) | gh secret set SIGNING_CERT_PFX_BASE64 --repo $GitHubRepository --env release-signing
    if ($LASTEXITCODE -ne 0) { throw "gh secret set SIGNING_CERT_PFX_BASE64 failed" }
    $password | gh secret set SIGNING_CERT_PASSWORD --repo $GitHubRepository --env release-signing
    if ($LASTEXITCODE -ne 0) { throw "gh secret set SIGNING_CERT_PASSWORD failed" }
    Write-Host "GitHub secrets updated for $GitHubRepository"
}
