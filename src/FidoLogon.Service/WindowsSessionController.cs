using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using FidoLogon.Core;

namespace FidoLogon.Service;

internal sealed class NativeKeyBindingSource : IKeyBindingSource
{
    public LastAuthenticationLookup TakeLastAuthentication(int sessionId) =>
        FidoLogonApi.TakeLastAuthentication(sessionId);

    public bool IsDevicePresent(string devicePath) => FidoLogonApi.IsDevicePresent(devicePath);

    public long GetDeviceArrival(string devicePath) => FidoLogonApi.GetDeviceArrival(devicePath);

    public bool ShouldLockOnRemoval(string recordId) => FidoLogonApi.ShouldLockOnRemoval(recordId);

    public void SaveBinding(SessionKeyBinding binding) => FidoLogonApi.SaveSessionBinding(binding);

    public void RemoveBinding(int sessionId) => FidoLogonApi.RemoveSessionBinding(sessionId);

    public IReadOnlyList<SessionKeyBinding> LoadBindings() => FidoLogonApi.ListSessionBindings();
}

/// <summary>Session operations for a service running as LocalSystem.</summary>
internal sealed class WindowsSessionController(string lockHelperPath, IServiceLog log) : ISessionController
{
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint CreateNoWindow = 0x08000000;

    public DateTime UtcNow => DateTime.UtcNow;

    public string? GetSessionUserSid(int sessionId)
    {
        if (!WTSQueryUserToken((uint)sessionId, out IntPtr token))
        {
            return null;
        }
        try
        {
            using var identity = new WindowsIdentity(token);
            return identity.User?.Value;
        }
        finally
        {
            CloseHandle(token);
        }
    }

    public void LockSession(int sessionId)
    {
        try
        {
            StartLockHelper(sessionId);
        }
        catch (Win32Exception e)
        {
            // Disconnecting also returns the console to the sign-in screen.
            log.Warning($"Lock helper failed ({e.Message}); disconnecting session {sessionId} instead.");
            if (!WTSDisconnectSession(IntPtr.Zero, sessionId, false))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }

    // LockWorkStation only works from inside the session, so run the helper there as the user.
    private void StartLockHelper(int sessionId)
    {
        if (!WTSQueryUserToken((uint)sessionId, out IntPtr token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        IntPtr environment = IntPtr.Zero;
        try
        {
            if (!CreateEnvironmentBlock(out environment, token, false))
            {
                environment = IntPtr.Zero;
            }
            var startup = new StartupInfo
            {
                cb = Marshal.SizeOf<StartupInfo>(),
                lpDesktop = @"winsta0\default",
            };
            var commandLine = new StringBuilder($"\"{lockHelperPath}\"");
            if (!CreateProcessAsUser(token, lockHelperPath, commandLine, IntPtr.Zero, IntPtr.Zero, false,
                    CreateUnicodeEnvironment | CreateNoWindow, environment, null, ref startup,
                    out ProcessInformation process))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
        finally
        {
            if (environment != IntPtr.Zero)
            {
                DestroyEnvironmentBlock(environment);
            }
            CloseHandle(token);
        }
    }

#pragma warning disable SYSLIB1054, CA1838 // StartupInfo contains strings: keep runtime marshalling.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSDisconnectSession(IntPtr server, int sessionId, bool wait);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(IntPtr environment);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateProcessAsUserW")]
    private static extern bool CreateProcessAsUser(IntPtr token, string applicationName, StringBuilder commandLine,
        IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags,
        IntPtr environment, string? currentDirectory, ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
#pragma warning restore SYSLIB1054, CA1838
}
