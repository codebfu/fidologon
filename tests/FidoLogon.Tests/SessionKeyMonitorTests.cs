using FidoLogon.Core;
using FidoLogon.Service;

namespace FidoLogon.Tests;

public sealed class SessionKeyMonitorTests
{
    private const string Sid = "S-1-5-21-1-1001";
    private const string KeyPath = @"\\?\hid#key1";
    private static readonly DateTime Now = new(2026, 10, 12, 20, 0, 0, DateTimeKind.Utc);

    private sealed class FakeSource : IKeyBindingSource
    {
        public LastAuthentication? Pending { get; set; }

        public HashSet<string> Present { get; } = [];

        public bool Fail { get; set; }

        public Dictionary<string, bool> LockPolicy { get; } = [];

        public bool PolicyFails { get; set; }

        public Dictionary<int, SessionKeyBinding> Persisted { get; } = [];

        public LastAuthenticationLookup TakeLastAuthentication(int sessionId)
        {
            if (Pending is not { } value)
            {
                return LastAuthenticationLookup.None;
            }
            if (value.SessionId != sessionId)
            {
                return new LastAuthenticationLookup(null, value);
            }
            Pending = null;
            return new LastAuthenticationLookup(value, null);
        }

        public bool IsDevicePresent(string devicePath) =>
            Fail ? throw new FidoLogonException(FidoLogonErrorCode.Internal, "boom", null) : Present.Contains(devicePath);

        public Dictionary<string, long> Arrivals { get; } = [];

        public long GetDeviceArrival(string devicePath) => Arrivals.GetValueOrDefault(devicePath);

        public bool ShouldLockOnRemoval(string recordId) =>
            PolicyFails
                ? throw new FidoLogonException(FidoLogonErrorCode.StorageError, "boom", null)
                : LockPolicy.GetValueOrDefault(recordId, true);

        public void SaveBinding(SessionKeyBinding binding) => Persisted[binding.SessionId] = binding;

        public void RemoveBinding(int sessionId) => Persisted.Remove(sessionId);

        public IReadOnlyList<SessionKeyBinding> LoadBindings() => [.. Persisted.Values];
    }

    private sealed class FakeSessions : ISessionController
    {
        public Dictionary<int, string> Users { get; } = new() { [1] = Sid, [2] = "S-1-5-21-1-1002" };

        public List<int> Locked { get; } = [];

        public bool LockFails { get; set; }

        public DateTime UtcNow { get; set; } = Now;

        public string? GetSessionUserSid(int sessionId) => Users.GetValueOrDefault(sessionId);

        public void LockSession(int sessionId)
        {
            Locked.Add(sessionId);
            if (LockFails)
            {
                throw new InvalidOperationException("cannot lock");
            }
        }
    }

    private sealed class FakeLog : IServiceLog
    {
        public List<string> Infos { get; } = [];

        public List<string> Warnings { get; } = [];

        public void Info(string message) => Infos.Add(message);

        public void Warning(string message) => Warnings.Add(message);
    }

    private readonly FakeSource _source = new();
    private readonly FakeSessions _sessions = new();
    private readonly FakeLog _log = new();
    private readonly SessionKeyMonitor _monitor;

    public SessionKeyMonitorTests()
    {
        _monitor = new SessionKeyMonitor(_source, _sessions, _log);
        _source.Present.Add(KeyPath);
    }

    private void SignInWithKey(int sessionId, string sid = Sid, DateTime? at = null, int? recordedSession = null,
        long arrival = 0)
    {
        _source.Pending = new LastAuthentication(sid, KeyPath, "{record}", at ?? Now.AddSeconds(-3),
            recordedSession ?? sessionId, arrival);
        _monitor.OnSessionActivated(sessionId);
    }

    [Fact]
    public void LocksSessionWhenItsKeyIsRemoved()
    {
        SignInWithKey(1);
        Assert.Equal(KeyPath, _monitor.Bindings[1]);
        Assert.True(_source.Persisted.ContainsKey(1));

        _monitor.Poll();
        Assert.Empty(_sessions.Locked);

        _source.Present.Clear();
        _monitor.Poll();
        _monitor.Poll();
        Assert.Equal([1], _sessions.Locked);  // locked once, then waits for the lock event
        Assert.Equal([1], _monitor.PendingLocks);

        _monitor.OnSessionDeactivated(1);  // session lock event
        Assert.Empty(_monitor.Bindings);
        Assert.Empty(_source.Persisted);
    }

    [Fact]
    public void KeyPluggedAgainOnTheSamePathCountsAsARemoval()
    {
        // A key without a USB serial number gets a path derived from the port: another key plugged
        // into the same port between two polls keeps the path, but not the arrival time.
        _source.Arrivals[KeyPath] = 1000;
        SignInWithKey(1);
        _monitor.Poll();
        Assert.Empty(_sessions.Locked);

        _source.Arrivals[KeyPath] = 2000;
        _monitor.Poll();
        Assert.Equal([1], _sessions.Locked);
    }

    [Fact]
    public void KeySwappedBetweenSignInAndBindingCountsAsARemoval()
    {
        // The credential provider read the arrival time at sign-in; another key is already there when
        // the service binds the session.
        _source.Arrivals[KeyPath] = 2000;
        SignInWithKey(1, arrival: 1000);
        Assert.Equal(1000, _source.Persisted[1].DeviceArrival);
        _monitor.Poll();
        Assert.Equal([1], _sessions.Locked);
    }

    [Fact]
    public void KeySwappedWhileTheServiceWasStoppedCountsAsARemoval()
    {
        _source.Arrivals[KeyPath] = 1000;
        SignInWithKey(1, arrival: 1000);

        _source.Arrivals[KeyPath] = 2000;  // swapped before the restart
        var restarted = new SessionKeyMonitor(_source, _sessions, _log);
        restarted.Restore();
        restarted.Poll();
        Assert.Equal([1], _sessions.Locked);
    }

    [Fact]
    public void UnknownArrivalTimeKeepsThePathCheckOnly()
    {
        SignInWithKey(1);  // arrival time unknown (0)
        _source.Arrivals[KeyPath] = 2000;
        _monitor.Poll();
        Assert.Empty(_sessions.Locked);
    }

    [Fact]
    public void LockIsRetriedUntilTheSessionLockEventArrives()
    {
        SignInWithKey(1);
        _sessions.LockFails = true;
        _source.Present.Clear();
        _monitor.Poll();
        Assert.Equal([1], _sessions.Locked);
        Assert.Single(_log.Warnings, w => w.Contains("Failed to lock session 1", StringComparison.Ordinal));

        _source.Present.Add(KeyPath);  // plugging the key back does not cancel the lock
        _monitor.Poll();
        Assert.Single(_sessions.Locked);  // not before the retry interval

        _sessions.UtcNow += SessionKeyMonitor.LockRetryInterval;
        _sessions.LockFails = false;
        _monitor.Poll();
        Assert.Equal([1, 1], _sessions.Locked);
        Assert.Contains(_log.Infos, i => i.Contains("succeeded after 1 failed attempt", StringComparison.Ordinal));

        _sessions.UtcNow += SessionKeyMonitor.LockRetryInterval;  // still no lock event: lock again
        _monitor.Poll();
        Assert.Equal([1, 1, 1], _sessions.Locked);
    }

    [Fact]
    public void PasswordSignInIsNeverBound()
    {
        _monitor.OnSessionActivated(1);
        _source.Present.Clear();
        _monitor.Poll();
        Assert.Empty(_sessions.Locked);
    }

    [Fact]
    public void RecordForAnotherUserIsIgnored()
    {
        SignInWithKey(2, sid: Sid);
        Assert.Empty(_monitor.Bindings);
        Assert.Contains(_log.Warnings, w => w.Contains("belongs to", StringComparison.Ordinal));
    }

    [Fact]
    public void StaleRecordIsIgnored()
    {
        SignInWithKey(1, at: Now - SessionKeyMonitor.MaxAuthenticationAge - TimeSpan.FromSeconds(1));
        Assert.Empty(_monitor.Bindings);
    }

    [Fact]
    public void RecordOfAnotherSessionIsLeftForThatSession()
    {
        SignInWithKey(2, sid: "S-1-5-21-1-1002", recordedSession: 1);  // event of session 2, record of session 1
        Assert.Empty(_monitor.Bindings);
        Assert.NotNull(_source.Pending);
        Assert.Contains(_log.Warnings, w => w.Contains("belongs to session 1", StringComparison.Ordinal));

        _source.Pending = _source.Pending! with { UserSid = Sid };
        _monitor.OnSessionActivated(1);
        Assert.Equal(KeyPath, _monitor.Bindings[1]);
    }

    [Fact]
    public void ManualLockDropsBindingAndPasswordUnlockKeepsItDropped()
    {
        SignInWithKey(1);
        _monitor.OnSessionDeactivated(1);  // Win+L
        _monitor.OnSessionActivated(1);    // unlocked with the password: no pending record
        _source.Present.Clear();
        _monitor.Poll();
        Assert.Empty(_sessions.Locked);
    }

    [Fact]
    public void KeyUnlockRebindsSession()
    {
        SignInWithKey(1);
        _monitor.OnSessionDeactivated(1);
        SignInWithKey(1);
        _source.Present.Clear();
        _monitor.Poll();
        Assert.Equal([1], _sessions.Locked);
    }

    [Fact]
    public void SessionsAreTrackedIndependently()
    {
        SignInWithKey(1);
        _source.Pending = new LastAuthentication("S-1-5-21-1-1002", @"\\?\hid#key2", "{other}", Now, 2);
        _source.Present.Add(@"\\?\hid#key2");
        _monitor.OnSessionActivated(2);

        _source.Present.Remove(@"\\?\hid#key2");
        _monitor.Poll();
        Assert.Equal([2], _sessions.Locked);
        Assert.Equal([2], _monitor.PendingLocks);
    }

    [Fact]
    public void KeyWithLockOnRemovalOffLeavesSessionOpen()
    {
        _source.LockPolicy["{record}"] = false;
        SignInWithKey(1);
        _source.Present.Clear();
        _monitor.Poll();
        _monitor.Poll();
        Assert.Empty(_sessions.Locked);
        Assert.Empty(_monitor.Bindings);  // checked once, not on every poll
        Assert.Empty(_source.Persisted);
        Assert.Contains(_log.Infos, l => l.Contains("session left open", StringComparison.Ordinal));
    }

    [Fact]
    public void LockOnRemovalOptionIsReadWhenTheKeyDisappears()
    {
        _source.LockPolicy["{record}"] = false;
        SignInWithKey(1);
        _source.LockPolicy["{record}"] = true;  // changed while the session is open
        _source.Present.Clear();
        _monitor.Poll();
        Assert.Equal([1], _sessions.Locked);
    }

    [Fact]
    public void UnreadableLockOptionFallsBackToLocking()
    {
        SignInWithKey(1);
        _source.PolicyFails = true;
        _source.Present.Clear();
        _monitor.Poll();
        Assert.Equal([1], _sessions.Locked);
        Assert.Contains(_log.Warnings, l => l.Contains("Cannot read the lock-on-removal option", StringComparison.Ordinal));
    }

    [Fact]
    public void RepeatedPresenceErrorsLockTheSession()
    {
        SignInWithKey(1);
        _source.Fail = true;
        for (int i = 1; i < SessionKeyMonitor.MaxPresenceErrors; i++)
        {
            _monitor.Poll();
        }
        Assert.Empty(_sessions.Locked);  // a transient error does not lock
        Assert.Empty(_log.Warnings);

        _monitor.Poll();
        Assert.Equal([1], _sessions.Locked);
        Assert.Contains(_log.Warnings, w => w.Contains("treating the key as removed", StringComparison.Ordinal));
    }

    [Fact]
    public void SuccessfulCheckResetsThePresenceErrorCount()
    {
        SignInWithKey(1);
        _source.Fail = true;
        for (int i = 1; i < SessionKeyMonitor.MaxPresenceErrors; i++)
        {
            _monitor.Poll();
        }
        _source.Fail = false;
        _monitor.Poll();
        _source.Fail = true;
        _monitor.Poll();
        Assert.Empty(_sessions.Locked);
    }

    [Fact]
    public void BindingsAreRestoredAfterAServiceRestart()
    {
        SignInWithKey(1);
        _source.Persisted[2] = new SessionKeyBinding(2, "S-1-5-21-1-9999", KeyPath, "{x}");  // session reused
        _source.Persisted[5] = new SessionKeyBinding(5, Sid, KeyPath, "{y}");               // session gone

        var restarted = new SessionKeyMonitor(_source, _sessions, _log);
        restarted.Restore();
        Assert.Equal(KeyPath, restarted.Bindings[1]);
        Assert.Single(restarted.Bindings);
        Assert.Equal([1], _source.Persisted.Keys);

        _source.Present.Clear();
        restarted.Poll();
        Assert.Equal([1], _sessions.Locked);
    }

    [Fact]
    public void PasswordUnlockAfterRestartDropsARestoredBinding()
    {
        _source.Persisted[1] = new SessionKeyBinding(1, Sid, KeyPath, "{record}");
        _monitor.Restore();
        _monitor.OnSessionActivated(1);  // unlocked with the password
        Assert.Empty(_monitor.Bindings);
        Assert.Empty(_source.Persisted);
    }
}
