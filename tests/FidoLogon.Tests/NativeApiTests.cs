using FidoLogon.Core;
using static FidoLogon.Tests.NativeTestEnvironment;

namespace FidoLogon.Tests;

[Collection(NativeCollection.Name)]
public sealed class NativeApiTests : IDisposable
{
    private readonly NativeTestEnvironment _environment = new();

    public void Dispose() => _environment.Dispose();

    [Fact]
    public void ListsSimulatedDevice()
    {
        SecurityKeyDevice device = Assert.Single(FidoLogonApi.ListDevices());
        Assert.Equal(NativeTestEnvironment.DevicePath, device.Path);
        SecurityKeyCapabilities caps = FidoLogonApi.GetCapabilities(device.Path);
        Assert.True(caps.Fido2);
        Assert.True(caps.HasPin);
        Assert.True(caps.HmacSecret);
        Assert.True(caps.CredProtect);
        Assert.True(caps.SupportsPinMode);
    }

    [Fact]
    public void ListsLocalAccountsWithSids()
    {
        IReadOnlyList<LocalAccount> accounts = FidoLogonApi.ListLocalAccounts();
        Assert.NotEmpty(accounts);
        Assert.All(accounts, a => Assert.StartsWith("S-1-5-", a.Sid));
    }

    [Fact]
    public void EnrollTestAndRemoveKey()
    {
        LocalAccount account = NativeTestEnvironment.AnyEnabledAccount();
        string id = FidoLogonApi.Enroll(NativeTestEnvironment.DevicePath, account, "My key", UnlockMode.PinAndTouch,
            Secret(NativeTestEnvironment.Pin), Secret("Windows-Password"));

        EnrolledKey key = Assert.Single(FidoLogonApi.ListEnrolledKeys());
        Assert.Equal(id, key.Id);
        Assert.Equal(account.Sid, key.UserSid);
        Assert.Equal(account.Name, key.UserName);
        Assert.Equal("My key", key.Label);
        Assert.True(key.RequirePin);
        Assert.InRange(key.Created, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddMinutes(1));

        FidoLogonApi.TestEnrolledKey(id, Secret(NativeTestEnvironment.Pin));
        var wrongPin = Assert.Throws<FidoLogonException>(() => FidoLogonApi.TestEnrolledKey(id, Secret("000000")));
        Assert.Equal(FidoLogonErrorCode.PinInvalid, wrongPin.Code);
        var noPin = Assert.Throws<FidoLogonException>(() => FidoLogonApi.TestEnrolledKey(id, Secret("")));
        Assert.Equal(FidoLogonErrorCode.PinRequired, noPin.Code);

        FidoLogonTestHooks.UnplugFakeKey(NativeTestEnvironment.DevicePath);
        var unplugged = Assert.Throws<FidoLogonException>(() =>
            FidoLogonApi.TestEnrolledKey(id, Secret(NativeTestEnvironment.Pin)));
        Assert.Equal(FidoLogonErrorCode.NoDevice, unplugged.Code);

        FidoLogonApi.RemoveEnrolledKey(id);
        Assert.Empty(FidoLogonApi.ListEnrolledKeys());
        var missing = Assert.Throws<FidoLogonException>(() => FidoLogonApi.RemoveEnrolledKey(id));
        Assert.Equal(FidoLogonErrorCode.NotFound, missing.Code);
    }

    [Fact]
    public unsafe void EnrollWithATooSmallIdBufferLeavesNoRecord()
    {
        // The id does not fit: the enrollment must fail without leaving a working record behind.
        LocalAccount account = NativeTestEnvironment.AnyEnabledAccount();
        var id = new char[10];
        fixed (char* pin = "")
        fixed (char* password = "Windows-Password")
        {
            int result = NativeMethods.fl_enroll_ex(NativeTestEnvironment.DevicePath, account.Sid, account.Name, "Key",
                0, pin, password, id, id.Length, null, IntPtr.Zero);
            Assert.Equal((int)FidoLogonErrorCode.BufferTooSmall, result);
        }
        Assert.Empty(FidoLogonApi.ListEnrolledKeys());
    }

    [Fact]
    public void PinModeOnKeyWithoutPinIsRejected()
    {
        FidoLogonTestHooks.PlugFakeKey(@"\\?\hid#no_pin", "");
        var error = Assert.Throws<FidoLogonException>(() => FidoLogonApi.Enroll(@"\\?\hid#no_pin",
            NativeTestEnvironment.AnyEnabledAccount(), "k", UnlockMode.PinAndTouch, Secret(""), Secret("pw")));
        Assert.Equal(FidoLogonErrorCode.PinNotSet, error.Code);
        Assert.False(string.IsNullOrWhiteSpace(error.Description));
    }

    [Fact]
    public void PasswordFallbackOptionRoundTrips()
    {
        Assert.True(FidoLogonApi.AllowPasswordFallback);
        FidoLogonApi.AllowPasswordFallback = false;
        Assert.False(FidoLogonApi.AllowPasswordFallback);
        FidoLogonApi.AllowPasswordFallback = true;
        Assert.True(FidoLogonApi.AllowPasswordFallback);
    }

    [Fact]
    public void LockOnRemovalDefaultsToOnAndCanBeOverriddenPerKey()
    {
        Assert.True(FidoLogonApi.LockOnKeyRemoval);
        string id = FidoLogonApi.Enroll(NativeTestEnvironment.DevicePath, NativeTestEnvironment.AnyEnabledAccount(),
            "k", UnlockMode.PinAndTouch, Secret(NativeTestEnvironment.Pin), Secret("Windows-Password"));
        Assert.Null(Assert.Single(FidoLogonApi.ListEnrolledKeys()).LockOnRemoval);
        Assert.True(FidoLogonApi.ShouldLockOnRemoval(id));

        FidoLogonApi.LockOnKeyRemoval = false;
        Assert.False(FidoLogonApi.LockOnKeyRemoval);
        Assert.False(FidoLogonApi.ShouldLockOnRemoval(id));
        Assert.False(FidoLogonApi.ShouldLockOnRemoval(null));

        FidoLogonApi.SetKeyLockOnRemoval(id, true);
        Assert.True(Assert.Single(FidoLogonApi.ListEnrolledKeys()).LockOnRemoval);
        Assert.True(FidoLogonApi.ShouldLockOnRemoval(id));

        FidoLogonApi.LockOnKeyRemoval = true;
        FidoLogonApi.SetKeyLockOnRemoval(id, false);
        Assert.Equal("off", Assert.Single(FidoLogonApi.ListEnrolledKeys()).LockOnRemovalSetting);
        Assert.False(FidoLogonApi.ShouldLockOnRemoval(id));

        FidoLogonApi.SetKeyLockOnRemoval(id, null);
        Assert.Null(Assert.Single(FidoLogonApi.ListEnrolledKeys()).LockOnRemoval);
        var missing = Assert.Throws<FidoLogonException>(() => FidoLogonApi.SetKeyLockOnRemoval("{nope}", true));
        Assert.Equal(FidoLogonErrorCode.NotFound, missing.Code);
    }

    [Fact]
    public void NoLastAuthenticationByDefault()
    {
        Assert.Equal(LastAuthenticationLookup.None, FidoLogonApi.TakeLastAuthentication(1));
    }

    [Fact]
    public void SessionBindingsRoundTrip()
    {
        Assert.Empty(FidoLogonApi.ListSessionBindings());
        FidoLogonApi.SaveSessionBinding(new SessionKeyBinding(3, "S-1-5-21-1-1001", @"\\?\hid#a", "{r}", 1234567890123));
        Assert.Equal(new SessionKeyBinding(3, "S-1-5-21-1-1001", @"\\?\hid#a", "{r}", 1234567890123),
            Assert.Single(FidoLogonApi.ListSessionBindings()));
        FidoLogonApi.RemoveSessionBinding(3);
        Assert.Empty(FidoLogonApi.ListSessionBindings());
    }

    [Fact]
    public void UnknownDeviceIsNotPresent()
    {
        Assert.False(FidoLogonApi.IsDevicePresent(@"\\?\hid#vid_0000&pid_0000#does-not-exist"));
    }

    [Fact]
    public void PasswordOfUnknownAccountIsRejected()
    {
        // A non-existent account is used on purpose: wrong passwords on a real account count toward lockout.
        var error = Assert.Throws<FidoLogonException>(() =>
            FidoLogonApi.VerifyPassword($"fidologon-test-{Guid.NewGuid():N}"[..20], Secret("irrelevant")));
        Assert.Equal(FidoLogonErrorCode.PasswordInvalid, error.Code);
    }
}
