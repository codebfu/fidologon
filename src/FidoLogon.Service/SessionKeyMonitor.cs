using FidoLogon.Core;

namespace FidoLogon.Service;

/// <summary>Event log of the service.</summary>
internal interface IServiceLog
{
    void Info(string message);

    void Warning(string message);
}

/// <summary>
/// Source of key bindings: what the credential provider recorded, which devices are plugged,
/// the lock-on-removal options and the persisted bindings.
/// </summary>
internal interface IKeyBindingSource
{
    /// <summary>Takes the credential provider's last key sign-in record if it belongs to this session.</summary>
    LastAuthenticationLookup TakeLastAuthentication(int sessionId);

    bool IsDevicePresent(string devicePath);

    /// <summary>When the device behind this path last arrived, 0 when unknown (see <see cref="FidoLogonApi.GetDeviceArrival"/>).</summary>
    long GetDeviceArrival(string devicePath);

    /// <summary>Whether removing the key of this record locks the session (per-key or machine-wide option).</summary>
    bool ShouldLockOnRemoval(string recordId);

    /// <summary>Bindings survive a service restart in volatile storage (cleared at reboot).</summary>
    void SaveBinding(SessionKeyBinding binding);

    void RemoveBinding(int sessionId);

    IReadOnlyList<SessionKeyBinding> LoadBindings();
}

/// <summary>Operations on Windows sessions.</summary>
internal interface ISessionController
{
    string? GetSessionUserSid(int sessionId);

    /// <summary>Starts locking the session; completion is reported by the session lock event.</summary>
    void LockSession(int sessionId);

    DateTime UtcNow { get; }
}

/// <summary>
/// Binds each session opened (or unlocked) with a security key to that key's device
/// path, and locks the session as soon as the device disappears (unless the key's
/// lock-on-removal option, or the machine-wide default, is off). A device that arrived
/// again on the same path (a key without a USB serial number unplugged, or swapped for
/// another, between two checks) counts as a removal.
/// </summary>
/// <remarks>
/// <para>
/// A binding exists only while the session is unlocked: locking, disconnecting or
/// logging off drops it, and only a key-based unlock creates it again. A session
/// unlocked with the password is therefore never locked by key removal.
/// The lock-on-removal option is read when the key disappears, so changes apply to
/// sessions that are already open.
/// </para>
/// <para>
/// The monitor fails closed: repeated presence-check errors count as a removal, a lock is
/// retried until the session lock event confirms it, and bindings are persisted so that a
/// service restart keeps protecting open sessions.
/// </para>
/// </remarks>
internal sealed class SessionKeyMonitor(IKeyBindingSource source, ISessionController sessions, IServiceLog log)
{
    /// <summary>Maximum delay between the credential provider's record and the session event.</summary>
    public static readonly TimeSpan MaxAuthenticationAge = TimeSpan.FromMinutes(2);

    /// <summary>Consecutive failed presence checks after which the key is considered removed.</summary>
    public const int MaxPresenceErrors = 3;

    /// <summary>Delay before locking again when no session lock event followed an attempt.</summary>
    public static readonly TimeSpan LockRetryInterval = TimeSpan.FromSeconds(5);

    private readonly object _lock = new();
    private readonly Dictionary<int, Binding> _bindings = [];

    /// <summary>Device path of the key bound to each session.</summary>
    public IReadOnlyDictionary<int, string> Bindings
    {
        get
        {
            lock (_lock)
            {
                return _bindings.ToDictionary(b => b.Key, b => b.Value.DevicePath);
            }
        }
    }

    /// <summary>Sessions whose key was removed and that are not locked yet.</summary>
    public IReadOnlyCollection<int> PendingLocks
    {
        get
        {
            lock (_lock)
            {
                return _bindings.Where(b => b.Value.LockPending).Select(b => b.Key).ToList();
            }
        }
    }

    /// <summary>Reloads the bindings persisted before a service restart.</summary>
    public void Restore()
    {
        IReadOnlyList<SessionKeyBinding> saved;
        try
        {
            saved = source.LoadBindings();
        }
        catch (Exception e) when (e is FidoLogonException or DllNotFoundException)
        {
            log.Warning($"Cannot reload the session bindings: {e.Message}");
            return;
        }
        foreach (SessionKeyBinding binding in saved)
        {
            string? sid = sessions.GetSessionUserSid(binding.SessionId);
            if (sid is null || !string.Equals(sid, binding.UserSid, StringComparison.OrdinalIgnoreCase))
            {
                RemovePersisted(binding.SessionId);  // session gone or reused by someone else
                continue;
            }
            lock (_lock)
            {
                // The arrival time of the sign-in, not of the restart: a key swapped while the service
                // was stopped then counts as a removal.
                _bindings[binding.SessionId] = new Binding(binding.DevicePath, binding.RecordId,
                    binding.DeviceArrival != 0 ? binding.DeviceArrival : Arrival(binding.DevicePath));
            }
            log.Info($"Session {binding.SessionId} is bound again to security key {binding.DevicePath}.");
        }
    }

    /// <summary>Session logon, unlock or console reconnection.</summary>
    public void OnSessionActivated(int sessionId)
    {
        LastAuthenticationLookup lookup;
        try
        {
            lookup = source.TakeLastAuthentication(sessionId);
        }
        catch (Exception e) when (e is FidoLogonException or DllNotFoundException)
        {
            log.Warning($"Cannot read the key sign-in record for session {sessionId}: {e.Message}");
            return;
        }

        LastAuthentication? auth = lookup.Taken;
        if (auth is null)
        {
            // Password or another provider: the session must not stay bound to a key.
            Unbind(sessionId);
            if (lookup.OtherSession is { } other && IsFresh(other))
            {
                log.Warning($"Session {sessionId} was activated while the last key sign-in belongs to session " +
                            $"{other.SessionId}; it is not bound to a key.");
            }
            return;
        }

        string? sid = sessions.GetSessionUserSid(sessionId);
        if (sid is null || !string.Equals(sid, auth.UserSid, StringComparison.OrdinalIgnoreCase))
        {
            log.Warning($"Ignoring key sign-in record for {auth.UserSid}: session {sessionId} belongs to {sid ?? "nobody"}.");
            Unbind(sessionId);
            return;
        }
        if (!IsFresh(auth))
        {
            log.Warning($"Ignoring stale key sign-in record for session {sessionId} " +
                        $"(age {sessions.UtcNow - auth.TimestampUtc}).");
            Unbind(sessionId);
            return;
        }

        // Read at sign-in by the credential provider, so that a key swapped before this event is noticed
        // at the next check. Records of older versions have none: read now instead.
        long arrival = auth.DeviceArrival != 0 ? auth.DeviceArrival : Arrival(auth.DevicePath);
        lock (_lock)
        {
            _bindings[sessionId] = new Binding(auth.DevicePath, auth.RecordId, arrival);
        }
        try
        {
            source.SaveBinding(new SessionKeyBinding(sessionId, auth.UserSid, auth.DevicePath, auth.RecordId, arrival));
        }
        catch (Exception e) when (e is FidoLogonException or DllNotFoundException)
        {
            log.Warning($"Cannot persist the binding of session {sessionId} (lost if the service restarts): {e.Message}");
        }
        log.Info($"Session {sessionId} is bound to security key {auth.DevicePath}.");
    }

    /// <summary>Session lock, disconnection or logoff.</summary>
    public void OnSessionDeactivated(int sessionId) => Unbind(sessionId);

    /// <summary>Locks every bound session whose key is no longer plugged.</summary>
    public void Poll()
    {
        List<KeyValuePair<int, Binding>> bindings;
        lock (_lock)
        {
            bindings = [.. _bindings];
        }
        foreach ((int sessionId, Binding binding) in bindings)
        {
            if (binding.LockPending)
            {
                if (sessions.UtcNow - binding.LastLockAttempt >= LockRetryInterval)
                {
                    TryLock(sessionId, binding);
                }
                continue;
            }

            if (!IsKeyGone(sessionId, binding))
            {
                continue;
            }

            bool shouldLock;
            try
            {
                shouldLock = source.ShouldLockOnRemoval(binding.RecordId);
            }
            catch (Exception e) when (e is FidoLogonException or DllNotFoundException)
            {
                log.Warning($"Cannot read the lock-on-removal option, using the default (lock): {e.Message}");
                shouldLock = true;
            }

            if (!shouldLock)
            {
                if (Unbind(sessionId, binding))
                {
                    log.Info($"Security key removed from session {sessionId}: lock on removal is off for this key, " +
                             "session left open.");
                }
                continue;
            }

            lock (_lock)
            {
                if (!_bindings.TryGetValue(sessionId, out Binding? current) || current != binding)
                {
                    continue;  // changed meanwhile
                }
                binding.LockPending = true;
            }
            log.Info($"Security key removed: locking session {sessionId}.");
            TryLock(sessionId, binding);
        }
    }

    // 0 (unknown) disables the arrival check for the binding; it never blocks a binding.
    private long Arrival(string devicePath)
    {
        try
        {
            return source.GetDeviceArrival(devicePath);
        }
        catch (Exception e) when (e is FidoLogonException or DllNotFoundException)
        {
            log.Warning($"Cannot read when security key {devicePath} arrived: {e.Message}");
            return 0;
        }
    }

    private bool IsFresh(LastAuthentication auth)
    {
        TimeSpan age = sessions.UtcNow - auth.TimestampUtc;
        return age <= MaxAuthenticationAge && age >= -MaxAuthenticationAge;
    }

    // Presence check; repeated errors count as a removal so that a flapping device cannot keep the
    // session open after the key is pulled.
    private bool IsKeyGone(int sessionId, Binding binding)
    {
        try
        {
            bool present = source.IsDevicePresent(binding.DevicePath);
            binding.PresenceErrors = 0;
            if (!present)
            {
                return true;
            }
            if (binding.Arrival == 0)
            {
                return false;
            }
            long arrival = source.GetDeviceArrival(binding.DevicePath);
            if (arrival == 0 || arrival == binding.Arrival)
            {
                return false;
            }
            log.Info($"Security key {binding.DevicePath} of session {sessionId} was unplugged and a device " +
                     "arrived on the same path: treated as a removal.");
            return true;
        }
        catch (Exception e) when (e is FidoLogonException or DllNotFoundException)
        {
            binding.PresenceErrors++;
            if (binding.PresenceErrors < MaxPresenceErrors)
            {
                return false;
            }
            log.Warning($"Cannot check security key presence for session {sessionId} ({binding.PresenceErrors} " +
                        $"times in a row), treating the key as removed: {e.Message}");
            return true;
        }
    }

    private void TryLock(int sessionId, Binding binding)
    {
        binding.LastLockAttempt = sessions.UtcNow;
        try
        {
            sessions.LockSession(sessionId);
            if (binding.LockFailures > 0)
            {
                log.Info($"Locking session {sessionId} succeeded after {binding.LockFailures} failed attempt(s).");
                binding.LockFailures = 0;
            }
        }
        catch (Exception e)
        {
            binding.LockFailures++;
            if (binding.LockFailures == 1 || binding.LockFailures % 10 == 0)
            {
                log.Warning($"Failed to lock session {sessionId} (attempt {binding.LockFailures}, retrying): {e.Message}");
            }
        }
    }

    private void Unbind(int sessionId)
    {
        bool removed;
        lock (_lock)
        {
            removed = _bindings.Remove(sessionId);
        }
        if (removed)
        {
            RemovePersisted(sessionId);
        }
    }

    // Removes the binding only if it is still the given one.
    private bool Unbind(int sessionId, Binding binding)
    {
        lock (_lock)
        {
            if (!_bindings.TryGetValue(sessionId, out Binding? current) || current != binding)
            {
                return false;
            }
            _bindings.Remove(sessionId);
        }
        RemovePersisted(sessionId);
        return true;
    }

    private void RemovePersisted(int sessionId)
    {
        try
        {
            source.RemoveBinding(sessionId);
        }
        catch (Exception e) when (e is FidoLogonException or DllNotFoundException)
        {
            log.Warning($"Cannot remove the persisted binding of session {sessionId}: {e.Message}");
        }
    }

    // Mutable state is only changed by the polling thread, or under _lock for LockPending.
    private sealed class Binding(string devicePath, string recordId, long arrival)
    {
        public string DevicePath { get; } = devicePath;

        public string RecordId { get; } = recordId;

        /// <summary>Arrival time of the bound device, 0 when unknown.</summary>
        public long Arrival { get; } = arrival;

        public int PresenceErrors { get; set; }

        public bool LockPending { get; set; }

        public DateTime LastLockAttempt { get; set; }

        public int LockFailures { get; set; }
    }
}
