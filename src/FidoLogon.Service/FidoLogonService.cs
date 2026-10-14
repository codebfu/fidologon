using System.Diagnostics;
using System.ServiceProcess;
using FidoLogon.Core;
using Microsoft.Win32;

namespace FidoLogon.Service;

internal sealed class FidoLogonService : ServiceBase, IServiceLog
{
    public const string Name = "FidoLogon";
    private const string EventSource = "FidoLogon";
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(500);

    private readonly SessionKeyMonitor _monitor;
    private readonly MetadataAutoSync _metadataSync;
    private Timer? _timer;
    private int _polling;

    public FidoLogonService()
    {
        ServiceName = Name;
        CanHandleSessionChangeEvent = true;
        CanStop = true;
        CanShutdown = true;
        string lockHelper = Path.Combine(AppContext.BaseDirectory, "FidoLogon.Lock.exe");
        _monitor = new SessionKeyMonitor(new NativeKeyBindingSource(), new WindowsSessionController(lockHelper, this),
            this);
        _metadataSync = new MetadataAutoSync(KeyModelPolicy.CreateDefault(), KeyModelPolicy.CreateHttpClient, this);
    }

    protected override void OnStart(string[] args)
    {
        _monitor.Restore();
        _timer = new Timer(_ => PollOnce(), null, PollInterval, PollInterval);
        ApplyInstallationModelPolicy();
        _metadataSync.Start();
        Info("FidoLogon service started.");
    }

    protected override void OnStop()
    {
        _timer?.Dispose();
        _timer = null;
        _metadataSync.Dispose();
    }

    protected override void OnShutdown() => OnStop();

    protected override void OnSessionChange(SessionChangeDescription change)
    {
        switch (change.Reason)
        {
            case SessionChangeReason.SessionLogon:
            case SessionChangeReason.SessionUnlock:
            case SessionChangeReason.ConsoleConnect:
                _monitor.OnSessionActivated(change.SessionId);
                break;
            case SessionChangeReason.SessionLock:
            case SessionChangeReason.SessionLogoff:
            case SessionChangeReason.ConsoleDisconnect:
            case SessionChangeReason.RemoteDisconnect:
                _monitor.OnSessionDeactivated(change.SessionId);
                break;
        }
    }

    // The installer records whether only certified key models may be enrolled (with the daily
    // metadata download). The choice is applied once: later changes made with the CLI or the GUI stay.
    private void ApplyInstallationModelPolicy()
    {
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\FidoLogon Installer");
            FidoLogonApi.ApplyDefaultModelPolicy(enable: key?.GetValue("ModelPolicyOff") is null);
        }
        catch (Exception e) when (e is FidoLogonException or DllNotFoundException or IOException
                                      or UnauthorizedAccessException or System.Security.SecurityException)
        {
            Warning($"Cannot apply the key model policy chosen at installation: {e.Message}");
        }
    }

    private void PollOnce()
    {
        // Skip a tick rather than overlap when a check is slow.
        if (Interlocked.Exchange(ref _polling, 1) == 1)
        {
            return;
        }
        try
        {
            _monitor.Poll();
        }
        finally
        {
            Volatile.Write(ref _polling, 0);
        }
    }

    public void Info(string message) => Write(message, EventLogEntryType.Information);

    public void Warning(string message) => Write(message, EventLogEntryType.Warning);

    private static void Write(string message, EventLogEntryType type)
    {
        try
        {
            if (EventLog.SourceExists(EventSource))
            {
                EventLog.WriteEntry(EventSource, message, type);
                return;
            }
        }
        catch (Exception e) when (e is InvalidOperationException or System.Security.SecurityException)
        {
        }
        Trace.WriteLine($"FidoLogon ({type}): {message}");
    }
}
