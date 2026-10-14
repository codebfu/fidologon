namespace FidoLogon.Core;

/// <summary>Validates enrollment input and performs it; shared by the CLI and the GUI.</summary>
public static class EnrollmentService
{
    public static string Enroll(SecurityKeyDevice device, LocalAccount account, string label, UnlockMode mode,
        SecretText pin, SecretText password, TouchPrompt? onTouch = null)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(account);
        if (account.Disabled)
        {
            throw new FidoLogonException(FidoLogonErrorCode.InvalidArgument, "This account is disabled.", null);
        }
        if (password.IsEmpty)
        {
            throw new FidoLogonException(FidoLogonErrorCode.InvalidArgument,
                "Accounts without a password cannot be enrolled.", null);
        }

        // Refuse to store a wrong password: the key would then open nothing.
        FidoLogonApi.VerifyPassword(account.Name, password);
        return FidoLogonApi.Enroll(device.Path, account, string.IsNullOrWhiteSpace(label) ? device.DisplayName : label.Trim(),
            mode, pin, password, onTouch);
    }
}
