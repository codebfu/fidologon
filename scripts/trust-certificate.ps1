<#
.SYNOPSIS
    Makes this computer trust FidoLogon builds signed with the project's self-signed certificate.

.DESCRIPTION
    Imports the public certificate into the local machine "Trusted Root Certification
    Authorities" and "Trusted Publishers" stores. Run as administrator. Only do this if
    you trust whoever controls the matching private key.
#>
[CmdletBinding()]
param(
    [string] $CertificatePath = (Join-Path (Split-Path -Parent $PSScriptRoot) "certs\FidoLogon-CodeSigning.cer")
)

$ErrorActionPreference = "Stop"

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as administrator."
}

foreach ($store in "Cert:\LocalMachine\Root", "Cert:\LocalMachine\TrustedPublisher") {
    Import-Certificate -FilePath $CertificatePath -CertStoreLocation $store | Out-Null
    Write-Host "Imported into $store"
}
