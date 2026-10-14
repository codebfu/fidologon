using System.Globalization;
using System.Runtime.InteropServices;

namespace FidoLogon.Core;

/// <summary>
/// Managed facade over the native API. Device access and configuration changes
/// require administrator rights (or SYSTEM).
/// </summary>
/// <summary>Called just before the key waits for touch number <paramref name="touch"/> of <paramref name="total"/>.</summary>
public delegate void TouchPrompt(int touch, int total);

public static class FidoLogonApi
{
    private const int MaxItems = 256;

    public static IReadOnlyList<SecurityKeyDevice> ListDevices()
    {
        var buffer = new NativeMethods.Device[MaxItems];
        Check(NativeMethods.fl_list_devices(buffer, buffer.Length, out int count));
        return buffer.Take(count)
            .Select(d => new SecurityKeyDevice(d.Path, d.Product, d.Manufacturer, d.VendorId, d.ProductId))
            .ToList();
    }

    public static SecurityKeyCapabilities GetCapabilities(string devicePath)
    {
        Check(NativeMethods.fl_get_device_caps(devicePath, out var caps));
        return new SecurityKeyCapabilities(caps.Fido2 != 0, caps.HasPin != 0, caps.HmacSecret != 0,
            caps.CredProtect != 0);
    }

    public static bool IsDevicePresent(string devicePath)
    {
        Check(NativeMethods.fl_is_device_present(devicePath, out int present));
        return present != 0;
    }

    /// <summary>
    /// When Windows last saw the device behind this path arrive (FILETIME), 0 when absent or unknown.
    /// It changes when a key is unplugged and plugged back, even on the same path.
    /// </summary>
    public static long GetDeviceArrival(string devicePath)
    {
        Check(NativeMethods.fl_get_device_arrival(devicePath, out ulong arrival));
        return unchecked((long)arrival);
    }

    public static IReadOnlyList<LocalAccount> ListLocalAccounts()
    {
        var buffer = new NativeMethods.LocalUser[MaxItems];
        Check(NativeMethods.fl_list_local_users(buffer, buffer.Length, out int count));
        return buffer.Take(count).Select(u => new LocalAccount(u.Name, u.FullName, u.Sid, u.Disabled != 0)).ToList();
    }

    /// <summary>Throws <see cref="FidoLogonException"/> with <see cref="FidoLogonErrorCode.PasswordInvalid"/> on failure.</summary>
    public static unsafe void VerifyPassword(string userName, SecretText password)
    {
        fixed (char* passwordChars = password.Buffer)
        {
            Check(NativeMethods.fl_verify_password(userName, passwordChars, out _));
        }
    }

    /// <summary>
    /// Enrolls a key for an account. The caller must have verified the password;
    /// the user touches the key twice (credential creation, then hmac-secret).
    /// </summary>
    /// <param name="onTouch">Called with (touch, total) just before each wait for a touch on the key
    /// (two for an enrollment), on the calling thread.</param>
    public static unsafe string Enroll(string devicePath, LocalAccount account, string label, UnlockMode mode,
        SecretText pin, SecretText password, TouchPrompt? onTouch = null)
    {
        var id = new char[NativeMethods.IdMax];
        NativeMethods.TouchCallback? callback = Callback(onTouch);
        fixed (char* pinChars = pin.Buffer)
        fixed (char* passwordChars = password.Buffer)
        {
            Check(NativeMethods.fl_enroll_ex(devicePath, account.Sid, account.Name, label,
                mode == UnlockMode.PinAndTouch ? 1 : 0, pinChars, passwordChars, id, id.Length, callback, IntPtr.Zero));
        }
        GC.KeepAlive(callback);
        return new string(id).TrimEnd('\0');
    }

    private static NativeMethods.TouchCallback? Callback(TouchPrompt? onTouch) =>
        onTouch is null ? null : (touch, total, _) => onTouch(touch, total);

    public static IReadOnlyList<EnrolledKey> ListEnrolledKeys()
    {
        var buffer = new NativeMethods.Record[MaxItems];
        Check(NativeMethods.fl_list_records(buffer, buffer.Length, out int count));
        return buffer.Take(count)
            .Select(r => new EnrolledKey(r.Id, r.UserSid, r.UserName, r.Label, r.RequirePin != 0,
                DateTimeOffset.FromUnixTimeSeconds(r.CreatedUnix),
                r.LockOnRemoval == NativeMethods.LockDefault ? null : r.LockOnRemoval == NativeMethods.LockAlways,
                r.Aaguid))
            .OrderBy(k => k.UserName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(k => k.Created)
            .ToList();
    }

    public static void RemoveEnrolledKey(string recordId) => Check(NativeMethods.fl_remove_record(recordId));

    /// <summary>Checks that a plugged key still decrypts the stored password (touch, plus PIN if required).</summary>
    public static unsafe void TestEnrolledKey(string recordId, SecretText pin, TouchPrompt? onTouch = null)
    {
        NativeMethods.TouchCallback? callback = Callback(onTouch);
        fixed (char* pinChars = pin.Buffer)
        {
            Check(NativeMethods.fl_test_record_ex(recordId, pinChars, callback, IntPtr.Zero));
        }
        GC.KeepAlive(callback);
    }

    public static bool AllowPasswordFallback
    {
        get
        {
            Check(NativeMethods.fl_get_allow_password_fallback(out int allow));
            return allow != 0;
        }
        set => Check(NativeMethods.fl_set_allow_password_fallback(value ? 1 : 0));
    }

    public static IReadOnlyList<AllowedKeyModel> ListAllowedModels()
    {
        var buffer = new NativeMethods.AllowedModel[MaxItems];
        Check(NativeMethods.fl_list_allowed_models(buffer, buffer.Length, out int count));
        return buffer.Take(count)
            .Select(m => new AllowedKeyModel(m.Aaguid, m.Description, m.Status, m.RootCount))
            .OrderBy(m => m.Description, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>Adds or replaces an allowed key model with its attestation root certificates (DER).</summary>
    public static void SetAllowedModel(string aaguid, string description, string status,
        IReadOnlyList<byte[]> rootCertificates)
    {
        var handles = rootCertificates.Select(r => GCHandle.Alloc(r, GCHandleType.Pinned)).ToList();
        try
        {
            IntPtr[] pointers = handles.Select(h => h.AddrOfPinnedObject()).ToArray();
            int[] lengths = rootCertificates.Select(r => r.Length).ToArray();
            Check(NativeMethods.fl_set_allowed_model(aaguid, description, status, pointers, lengths, pointers.Length));
        }
        finally
        {
            handles.ForEach(h => h.Free());
        }
    }

    public static void RemoveAllowedModel(string aaguid) => Check(NativeMethods.fl_remove_allowed_model(aaguid));

    /// <summary>Replaces the certified models (every FIDO2 model of the imported metadata) as a whole.</summary>
    public static void ReplaceCertifiedModels(IReadOnlyList<MetadataEntry> entries)
    {
        var strings = new List<IntPtr>();
        var handles = new List<GCHandle>();
        IntPtr Text(string value)
        {
            IntPtr pointer = Marshal.StringToHGlobalUni(value);
            strings.Add(pointer);
            return pointer;
        }
        IntPtr Pin(object value)
        {
            GCHandle handle = GCHandle.Alloc(value, GCHandleType.Pinned);
            handles.Add(handle);
            return handle.AddrOfPinnedObject();
        }
        try
        {
            var inputs = new NativeMethods.ModelInput[entries.Count];
            for (int i = 0; i < entries.Count; i++)
            {
                MetadataEntry entry = entries[i];
                IntPtr[] roots = entry.AttestationRootCertificates.Select(Pin).ToArray();
                int[] lengths = entry.AttestationRootCertificates.Select(r => r.Length).ToArray();
                inputs[i] = new NativeMethods.ModelInput
                {
                    Aaguid = Text(entry.Aaguid),
                    Description = Text(entry.Description),
                    Status = Text(entry.Status),
                    Roots = Pin(roots),
                    RootLengths = Pin(lengths),
                    RootCount = roots.Length,
                };
            }
            Check(NativeMethods.fl_replace_certified_models(inputs, inputs.Length));
        }
        finally
        {
            handles.ForEach(h => h.Free());
            strings.ForEach(Marshal.FreeHGlobal);
        }
    }

    public static int CountCertifiedModels()
    {
        Check(NativeMethods.fl_count_certified_models(out int count));
        return count;
    }

    /// <summary>Certified models (every FIDO2 model with attestation roots in the imported metadata).</summary>
    public static IReadOnlyList<AllowedKeyModel> ListCertifiedModels()
    {
        // The list is longer than the other ones (several hundred models): sized from the count.
        for (int attempt = 0; ; attempt++)
        {
            var buffer = new NativeMethods.AllowedModel[CountCertifiedModels() + 16];
            int result = NativeMethods.fl_list_certified_models(buffer, buffer.Length, out int count);
            if (result == (int)FidoLogonErrorCode.BufferTooSmall && attempt < 3)
            {
                continue;  // replaced by a longer list meanwhile
            }
            Check(result);
            return buffer.Take(count)
                .Select(m => new AllowedKeyModel(m.Aaguid, m.Description, m.Status, m.RootCount))
                .ToList();
        }
    }

    /// <summary>Copies a certified model, with its attestation roots, to the allowed list.</summary>
    public static void AllowCertifiedModel(string aaguid) => Check(NativeMethods.fl_allow_certified_model(aaguid));

    /// <summary>Number and next update date of the BLOB the certified models come from, null if none.</summary>
    public static (int Number, DateOnly NextUpdate)? GetMetadataInfo()
    {
        var nextUpdate = new char[NativeMethods.IdMax];
        Check(NativeMethods.fl_get_metadata_info(out int present, out int number, nextUpdate, nextUpdate.Length));
        if (present == 0 || !DateOnly.TryParseExact(new string(nextUpdate).TrimEnd('\0'), "yyyy-MM-dd",
                CultureInfo.InvariantCulture, DateTimeStyles.None, out DateOnly date))
        {
            return null;
        }
        return (number, date);
    }

    public static void SetMetadataInfo(int number, DateOnly nextUpdate) =>
        Check(NativeMethods.fl_set_metadata_info(number, nextUpdate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)));

    /// <summary>
    /// Sets <see cref="AllowCertifiedModels"/> and <see cref="AutoSyncMetadata"/> to <paramref name="enable"/>,
    /// each only if it was never set (the installation choice, applied once).
    /// </summary>
    public static void ApplyDefaultModelPolicy(bool enable) =>
        Check(NativeMethods.fl_apply_default_model_policy(enable ? 1 : 0));

    /// <summary>
    /// When true, enrollment also accepts every certified model (attestation still verified).
    /// Use <see cref="KeyModelPolicy.SetAllowCertifiedModels"/> to turn it on.
    /// </summary>
    public static bool AllowCertifiedModels
    {
        get
        {
            Check(NativeMethods.fl_get_allow_certified_models(out int allow));
            return allow != 0;
        }
        set => Check(NativeMethods.fl_set_allow_certified_models(value ? 1 : 0));
    }

    /// <summary>When true, the service downloads a new FIDO Metadata Service BLOB once the imported one is outdated.</summary>
    public static bool AutoSyncMetadata
    {
        get
        {
            Check(NativeMethods.fl_get_auto_sync_metadata(out int enabled));
            return enabled != 0;
        }
        set => Check(NativeMethods.fl_set_auto_sync_metadata(value ? 1 : 0));
    }

    /// <summary>
    /// Machine-wide default (true when never set): lock the session when the key that opened it is removed.
    /// </summary>
    public static bool LockOnKeyRemoval
    {
        get
        {
            Check(NativeMethods.fl_get_lock_on_key_removal(out int lockSession));
            return lockSession != 0;
        }
        set => Check(NativeMethods.fl_set_lock_on_key_removal(value ? 1 : 0));
    }

    /// <summary>Overrides <see cref="LockOnKeyRemoval"/> for one key; null follows the machine-wide option.</summary>
    public static void SetKeyLockOnRemoval(string recordId, bool? lockSession) =>
        Check(NativeMethods.fl_set_record_lock_on_removal(recordId, lockSession switch
        {
            null => NativeMethods.LockDefault,
            true => NativeMethods.LockAlways,
            false => NativeMethods.LockNever,
        }));

    /// <summary>Effective behavior when the key of a record is removed (machine-wide option for unknown records).</summary>
    public static bool ShouldLockOnRemoval(string? recordId)
    {
        Check(NativeMethods.fl_should_lock_on_removal(recordId, out int lockSession));
        return lockSession != 0;
    }

    /// <summary>
    /// True when the computer is joined to Active Directory or Entra ID (or this cannot be determined):
    /// the password tile is then never hidden.
    /// </summary>
    public static bool IsMachineJoined()
    {
        Check(NativeMethods.fl_is_machine_joined(out int joined));
        return joined != 0;
    }

    /// <summary>True when every enabled local account has a key, which is required before the password tile is hidden.</summary>
    public static bool EveryEnabledAccountHasKey()
    {
        Check(NativeMethods.fl_every_user_enrolled(out int result));
        return result != 0;
    }

    /// <summary>Takes the credential provider's last key sign-in record if it belongs to the session.</summary>
    public static LastAuthenticationLookup TakeLastAuthentication(int sessionId)
    {
        Check(NativeMethods.fl_take_last_auth((uint)sessionId, out var value, out int status));
        if (status == NativeMethods.LastAuthNone)
        {
            return LastAuthenticationLookup.None;
        }
        var auth = new LastAuthentication(value.UserSid, value.DevicePath, value.RecordId,
            DateTime.FromFileTimeUtc((long)value.TimestampFileTime), (int)value.SessionId,
            unchecked((long)value.DeviceArrival));
        return status == NativeMethods.LastAuthTaken ? new(auth, null) : new(null, auth);
    }

    public static void SaveSessionBinding(SessionKeyBinding binding)
    {
        var value = new NativeMethods.SessionBinding
        {
            SessionId = (uint)binding.SessionId,
            UserSid = binding.UserSid,
            DevicePath = binding.DevicePath,
            RecordId = binding.RecordId,
            DeviceArrival = unchecked((ulong)binding.DeviceArrival),
        };
        Check(NativeMethods.fl_save_session_binding(in value));
    }

    public static void RemoveSessionBinding(int sessionId) =>
        Check(NativeMethods.fl_remove_session_binding((uint)sessionId));

    public static IReadOnlyList<SessionKeyBinding> ListSessionBindings()
    {
        var buffer = new NativeMethods.SessionBinding[MaxItems];
        Check(NativeMethods.fl_list_session_bindings(buffer, buffer.Length, out int count));
        return buffer.Take(count)
            .Select(b => new SessionKeyBinding((int)b.SessionId, b.UserSid, b.DevicePath, b.RecordId,
                unchecked((long)b.DeviceArrival)))
            .ToList();
    }

    public static string DescribeError(FidoLogonErrorCode code)
    {
        var buffer = new char[512];
        NativeMethods.fl_describe_error((int)code, buffer, buffer.Length);
        return new string(buffer).TrimEnd('\0');
    }

    internal static void Check(int result)
    {
        if (result == 0)
        {
            return;
        }
        var detail = new char[1024];
        NativeMethods.fl_last_error_message(detail, detail.Length);
        var code = (FidoLogonErrorCode)result;
        throw new FidoLogonException(code, DescribeError(code), new string(detail).TrimEnd('\0'));
    }
}

/// <summary>Process-local hooks used by automated tests (registry root under HKCU, simulated keys).</summary>
public static class FidoLogonTestHooks
{
    public static void UseCurrentUserStorage(string? relativePath) =>
        FidoLogonApi.Check(NativeMethods.fl_test_set_storage_root(relativePath));

    public static void UseFakeAuthenticator(bool enable) =>
        FidoLogonApi.Check(NativeMethods.fl_test_use_fake_authenticator(enable ? 1 : 0));

    public static void PlugFakeKey(string devicePath, string pin) =>
        FidoLogonApi.Check(NativeMethods.fl_test_fake_plug(devicePath, pin));

    public static void UnplugFakeKey(string devicePath) =>
        FidoLogonApi.Check(NativeMethods.fl_test_fake_unplug(devicePath));
}
