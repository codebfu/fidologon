# Recovery

Use these procedures if you cannot sign in with your security key.

## 1. Sign in with the password

Unless the password fallback was turned off, the password tile is still available: on the sign-in
screen, choose **Sign-in options** and the key-with-asterisks (password) icon.

Common causes when the key no longer works:

| Message | Cause | Fix |
|---|---|---|
| *Windows rejected the password stored for this security key* | The account password changed | Sign in with the password, remove the key and enroll it again |
| *No enrolled security key is plugged in* | Wrong or unplugged key, or a key on an unsupported transport (NFC) | Plug the enrolled key over USB |
| *Incorrect security key PIN* / *PIN is blocked* | Wrong PIN; too many attempts | Unplug and replug after 3 failures; after 8 the key must be reset (its credentials are lost) |
| *Timed out waiting for the security key* | The key was not touched within 30 seconds | Try again and touch the key when it blinks |
| *Several security keys are plugged in* | *PIN + touch* sign-in with more than one FIDO2 key of the enrolled model plugged | Unplug every key except the enrolled one |

## 2. Another administrator account

From any administrator account, run as administrator:

```powershell
& "C:\Program Files\FidoLogon\emergency-disable.ps1"
```

This turns the password fallback on, unregisters the password filter and disables the FidoLogon
tile. Enrolled keys are kept. To enable FidoLogon again: delete the value
`Disabled` under
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{FAAD8F12-6991-448B-BF78-892ED3E6A76B}`,
then repair FidoLogon from *Settings → Apps*.

## 3. Safe mode

FidoLogon never hides the password tile in safe mode. Hold **Shift** while clicking **Restart**
(on the sign-in screen power menu), then *Troubleshoot → Advanced options → Startup Settings →
Restart → 4 (Enable Safe Mode)*. Sign in with the password, then run `emergency-disable.ps1` or
uninstall FidoLogon.

## 4. Offline (Windows Recovery Environment)

If nothing else works:

1. Boot into the recovery environment (Shift + Restart, or boot from Windows installation media
   and choose *Repair your computer*), then *Troubleshoot → Advanced options → Command Prompt*.
   If BitLocker is enabled, you need the recovery key.
2. Find the Windows drive letter (often `D:` in WinRE): `dir D:\Windows`.
3. Load the offline registry and remove the filter:

```
reg load HKLM\OfflineSoftware D:\Windows\System32\config\SOFTWARE
reg delete "HKLM\OfflineSoftware\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{0D55732F-293A-41B1-90F3-D260B9C8EF94}" /f
reg add "HKLM\OfflineSoftware\FidoLogon" /v AllowPasswordFallback /t REG_DWORD /d 1 /f
reg unload HKLM\OfflineSoftware
```

4. Restart: the password tile is back.

## Uninstalling

Versions before 0.1.0-rc.5 kept the FIDO Metadata Service BLOB in `%ProgramData%\FidoLogon`; that
folder is no longer used and can be deleted.

Uninstalling FidoLogon (*Settings → Apps*) removes the credential provider, the filter and the
service. The enrolled-key records (encrypted, useless without the keys) stay in
`HKLM\SOFTWARE\FidoLogon`; delete that key to remove them.
