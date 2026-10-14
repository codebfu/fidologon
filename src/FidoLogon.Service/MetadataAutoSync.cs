using FidoLogon.Core;

namespace FidoLogon.Service;

/// <summary>
/// Once a day, when the administrator turned <see cref="FidoLogonApi.AutoSyncMetadata"/> on, downloads a
/// new FIDO Metadata Service BLOB if the imported one is outdated (or none was imported).
/// </summary>
internal sealed class MetadataAutoSync(KeyModelPolicy policy, Func<HttpClient> createClient, IServiceLog log)
    : IDisposable
{
    private static readonly TimeSpan FirstCheck = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan Interval = TimeSpan.FromDays(1);

    private Timer? _timer;
    private int _running;

    public void Start() => _timer = new Timer(_ => CheckNow(), null, FirstCheck, Interval);

    public void Dispose()
    {
        _timer?.Dispose();
        _timer = null;
    }

    /// <summary>Runs one check; never throws (failures are logged and retried at the next check).</summary>
    public void CheckNow()
    {
        if (Interlocked.Exchange(ref _running, 1) == 1)
        {
            return;
        }
        try
        {
            if (!FidoLogonApi.AutoSyncMetadata || !policy.NeedsSync(DateOnly.FromDateTime(DateTime.UtcNow)))
            {
                return;
            }
            using HttpClient client = createClient();
            MetadataSyncResult result = policy.SyncAsync(client).GetAwaiter().GetResult();
            if (result.Import is not { } import)
            {
                log.Info($"FIDO Metadata Service BLOB #{result.Number} is still the latest " +
                         $"(next update {result.NextUpdate:yyyy-MM-dd}).");
                return;
            }
            log.Info($"Downloaded FIDO Metadata Service BLOB #{import.Number} ({import.EntryCount} FIDO2 models, " +
                     $"next update {import.NextUpdate:yyyy-MM-dd}).");
            if (import.Blocked.Count > 0)
            {
                log.Warning("Allowed key models now revoked or compromised (enrollment refuses them): " +
                            string.Join(", ", import.Blocked));
            }
        }
        catch (Exception ex) when (ex is MetadataException or FidoLogonException or IOException
                                       or UnauthorizedAccessException)
        {
            log.Warning($"FIDO Metadata Service synchronization failed: {ex.Message}");
        }
        catch (Exception ex)
        {
            // Runs on a timer thread: an unexpected exception would end the service process.
            log.Warning($"FIDO Metadata Service synchronization failed unexpectedly: {ex}");
        }
        finally
        {
            Volatile.Write(ref _running, 0);
        }
    }
}
