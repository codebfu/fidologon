<#
.SYNOPSIS
    Emergency switch: restores password sign-in and disables the FidoLogon tile.

.DESCRIPTION
    Run as administrator (for example from another administrator account, or from
    safe mode). It:
      - re-enables the password fallback,
      - unregisters the FidoLogon password filter,
      - marks the FidoLogon credential provider as disabled.
    Enrolled keys are kept. Reinstall (repair) FidoLogon from "Apps" to enable it again.
    See docs/recovery.md for the offline procedure when you cannot sign in at all.

    -Elevate (used by the Start menu shortcut): when not run as administrator, relaunches the
    script elevated in a window that stays open and asks for confirmation first.
#>
[CmdletBinding()]
param(
    [switch] $Elevate,
    [switch] $AskConfirmation
)

$ErrorActionPreference = "Stop"

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($Elevate) {
        Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList @(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-NoExit", "-File", "`"$PSCommandPath`"", "-AskConfirmation")
        return
    }
    throw "Run this script as administrator."
}
if ($Elevate -or $AskConfirmation) {
    $answer = Read-Host "Disable FidoLogon and restore password sign-in? (y/N)"
    if ($answer -notmatch '^(y|yes)$') {
        Write-Host "Cancelled."
        return
    }
}

$auth = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication"
$filterKey = "$auth\Credential Provider Filters\{0D55732F-293A-41B1-90F3-D260B9C8EF94}"
$providerKey = "$auth\Credential Providers\{FAAD8F12-6991-448B-BF78-892ED3E6A76B}"

if (Test-Path "HKLM:\SOFTWARE\FidoLogon") {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\FidoLogon" -Name AllowPasswordFallback -Value 1 -Type DWord
    Write-Host "Password fallback enabled."
}
if (Test-Path $filterKey) {
    Remove-Item -Path $filterKey -Recurse
    Write-Host "Password filter unregistered."
}
if (Test-Path $providerKey) {
    Set-ItemProperty -Path $providerKey -Name Disabled -Value 1 -Type DWord
    Write-Host "FidoLogon credential provider disabled."
}
Write-Host "Done. Password sign-in is available again."
