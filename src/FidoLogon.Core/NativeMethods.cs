using System.Runtime.InteropServices;

namespace FidoLogon.Core;

/// <summary>P/Invoke declarations for fidologon_native.dll (see native/native_api/include/fidologon_native.h).</summary>
internal static class NativeMethods
{
    private const string Dll = "fidologon_native.dll";

    public const int PathMax = 512;
    public const int TextMax = 256;
    public const int IdMax = 64;
    public const int SidMax = 192;

    public const int LockDefault = -1;
    public const int LockNever = 0;
    public const int LockAlways = 1;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct Device
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = PathMax)] public string Path;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = TextMax)] public string Product;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = TextMax)] public string Manufacturer;
        public int VendorId;
        public int ProductId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DeviceCaps
    {
        public int Fido2;
        public int HasPin;
        public int HmacSecret;
        public int CredProtect;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct Record
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = IdMax)] public string Id;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = SidMax)] public string UserSid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = TextMax)] public string UserName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = TextMax)] public string Label;
        public int RequirePin;
        public long CreatedUnix;
        public int LockOnRemoval;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = IdMax)] public string Aaguid;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct AllowedModel
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = IdMax)] public string Aaguid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = TextMax)] public string Description;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = TextMax)] public string Status;
        public int RootCount;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct LocalUser
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = TextMax)] public string Name;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = TextMax)] public string FullName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = SidMax)] public string Sid;
        public int Disabled;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct LastAuth
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = SidMax)] public string UserSid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = PathMax)] public string DevicePath;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = IdMax)] public string RecordId;
        public ulong TimestampFileTime;
        public uint SessionId;
        public ulong DeviceArrival;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SessionBinding
    {
        public uint SessionId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = SidMax)] public string UserSid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = PathMax)] public string DevicePath;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = IdMax)] public string RecordId;
        public ulong DeviceArrival;
    }

    public const int LastAuthNone = 0;
    public const int LastAuthTaken = 1;
    public const int LastAuthOtherSession = 2;

#pragma warning disable SYSLIB1054 // ByValTStr structs require runtime marshalling.
    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_last_error_message(char[] buffer, int capacity);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_describe_error(int code, char[] buffer, int capacity);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_list_devices([Out] Device[]? devices, int capacity, out int count);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_get_device_caps(string devicePath, out DeviceCaps caps);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_is_device_present(string devicePath, out int present);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_get_device_arrival(string devicePath, out ulong arrival);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_list_local_users([Out] LocalUser[]? users, int capacity, out int count);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern unsafe int fl_verify_password(string userName, char* password, out uint win32Error);

    /// <summary>fl_touch_callback: called on the calling thread before each wait for a touch.</summary>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void TouchCallback(int touch, int total, IntPtr context);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern unsafe int fl_enroll_ex(string devicePath, string userSid, string userName, string label,
        int requirePin, char* pin, char* password, char[] recordId, int recordIdCapacity, TouchCallback? callback,
        IntPtr context);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_list_records([Out] Record[]? records, int capacity, out int count);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_remove_record(string recordId);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern unsafe int fl_test_record_ex(string recordId, char* pin, TouchCallback? callback,
        IntPtr context);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_get_allow_password_fallback(out int allow);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_set_allow_password_fallback(int allow);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_list_allowed_models([Out] AllowedModel[]? models, int capacity, out int count);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_set_allowed_model(string aaguid, string description, string status, IntPtr[] roots,
        int[] rootLengths, int rootCount);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_remove_allowed_model(string aaguid);

    /// <summary>fl_model_input: every pointer must stay valid (pinned or unmanaged) during the call.</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ModelInput
    {
        public IntPtr Aaguid;
        public IntPtr Description;
        public IntPtr Status;
        public IntPtr Roots;
        public IntPtr RootLengths;
        public int RootCount;
    }

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_replace_certified_models(ModelInput[] models, int count);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_count_certified_models(out int count);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_list_certified_models([Out] AllowedModel[]? models, int capacity, out int count);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_allow_certified_model(string aaguid);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_get_metadata_info(out int present, out int number, char[] nextUpdate, int capacity);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_set_metadata_info(int number, string nextUpdate);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_apply_default_model_policy(int enable);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_get_allow_certified_models(out int allow);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_set_allow_certified_models(int allow);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_get_auto_sync_metadata(out int enabled);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_set_auto_sync_metadata(int enabled);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_get_lock_on_key_removal(out int lockSession);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_set_lock_on_key_removal(int lockSession);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_set_record_lock_on_removal(string recordId, int mode);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_should_lock_on_removal(string? recordId, out int lockSession);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_every_user_enrolled(out int result);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_is_machine_joined(out int joined);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_take_last_auth(uint sessionId, out LastAuth lastAuth, out int status);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_save_session_binding(in SessionBinding binding);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_remove_session_binding(uint sessionId);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_list_session_bindings([Out] SessionBinding[]? bindings, int capacity, out int count);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_test_set_storage_root(string? currentUserPath);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_test_use_fake_authenticator(int enable);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_test_fake_plug(string devicePath, string pin);

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern int fl_test_fake_unplug(string devicePath);
#pragma warning restore SYSLIB1054
}
