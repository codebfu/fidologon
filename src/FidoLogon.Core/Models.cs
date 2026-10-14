namespace FidoLogon.Core;

/// <summary>Error codes of the native API (native/core/include/fidologon/errors.h).</summary>
public enum FidoLogonErrorCode
{
    Ok = 0,
    InvalidArgument = 1,
    NotFound = 2,
    NoDevice = 3,
    DeviceError = 4,
    PinRequired = 5,
    PinInvalid = 6,
    PinBlocked = 7,
    PinNotSet = 8,
    HmacSecretUnsupported = 9,
    CredentialNotOnDevice = 10,
    DecryptFailed = 11,
    StorageError = 12,
    AccessDenied = 13,
    Timeout = 14,
    PasswordInvalid = 15,
    BufferTooSmall = 16,
    Internal = 17,
    OperationDenied = 18,
    MultipleDevices = 19,
    CredProtectUnsupported = 20,
    AttestationRejected = 21,
}

public sealed class FidoLogonException(FidoLogonErrorCode code, string message, string? detail)
    : Exception(string.IsNullOrEmpty(detail) ? message : $"{message} ({detail})")
{
    public FidoLogonErrorCode Code { get; } = code;

    /// <summary>User-facing description of the error, without technical details.</summary>
    public string Description { get; } = message;
}

public sealed record SecurityKeyDevice(string Path, string Product, string Manufacturer, int VendorId = 0,
    int ProductId = 0)
{
    public string UsbId => $"{VendorId:x4}:{ProductId:x4}";

    public string DisplayName =>
        string.IsNullOrWhiteSpace(Product) ? Path : $"{Manufacturer} {Product}".Trim();
}

/// <param name="CredProtect">
/// The key supports CTAP 2.1 credProtect, so it can itself refuse to work without its PIN.
/// Required for <see cref="UnlockMode.PinAndTouch"/>.
/// </param>
public sealed record SecurityKeyCapabilities(bool Fido2, bool HasPin, bool HmacSecret, bool CredProtect)
{
    public bool SupportsPinMode => HmacSecret && HasPin && CredProtect;
}

public sealed record EnrolledKey(
    string Id,
    string UserSid,
    string UserName,
    string Label,
    bool RequirePin,
    DateTimeOffset Created,
    bool? LockOnRemoval = null,
    string Aaguid = "")
{
    /// <summary>Per-key behavior shown to users: "default", "on" or "off".</summary>
    public string LockOnRemovalSetting => LockOnRemoval switch
    {
        null => "default",
        true => "on",
        false => "off",
    };
}

/// <summary>Key model allowed at enrollment (see <see cref="KeyModelPolicy"/>).</summary>
public sealed record AllowedKeyModel(string Aaguid, string Description, string Status, int RootCount)
{
    public bool IsBlocked => MetadataEntry.BlockedStatuses.Contains(Status);
}

public sealed record LocalAccount(string Name, string FullName, string Sid, bool Disabled)
{
    public string DisplayName => string.IsNullOrWhiteSpace(FullName) ? Name : $"{Name} ({FullName})";
}

/// <param name="SessionId">Session of the LogonUI instance that signed in.</param>
/// <param name="DeviceArrival">When the key that signed in arrived, read at sign-in (FILETIME, 0 if unknown).</param>
public sealed record LastAuthentication(string UserSid, string DevicePath, string RecordId, DateTime TimestampUtc,
    int SessionId = 0, long DeviceArrival = 0);

/// <summary>
/// Result of taking the last key sign-in for a session: <see cref="Taken"/> when it belonged to that
/// session (and was consumed), <see cref="OtherSession"/> when it belongs to another session (left in place).
/// </summary>
public sealed record LastAuthenticationLookup(LastAuthentication? Taken, LastAuthentication? OtherSession)
{
    public static LastAuthenticationLookup None { get; } = new(null, null);
}

/// <summary>A session bound to the key that opened it, persisted by the service in volatile storage.</summary>
/// <param name="DeviceArrival">When the bound key arrived, from its sign-in (0 if unknown).</param>
public sealed record SessionKeyBinding(int SessionId, string UserSid, string DevicePath, string RecordId,
    long DeviceArrival = 0);

public enum UnlockMode
{
    /// <summary>The key's PIN is required at sign-in (recommended).</summary>
    PinAndTouch,

    /// <summary>Touching the key is enough: anyone holding the key can sign in.</summary>
    TouchOnly,
}
