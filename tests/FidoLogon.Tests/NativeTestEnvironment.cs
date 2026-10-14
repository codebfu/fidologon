using FidoLogon.Core;
using Microsoft.Win32;

namespace FidoLogon.Tests;

/// <summary>The native hooks are process-wide: tests using them must not run in parallel.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class NativeCollection
{
    public const string Name = "native";
}

/// <summary>Redirects storage to a throw-away HKCU key and replaces real keys with simulated ones.</summary>
public sealed class NativeTestEnvironment : IDisposable
{
    public const string DevicePath = @"\\?\hid#fake_key";
    public const string Pin = "123456";

    /// <summary>Wraps test input; tests do not need to wipe it.</summary>
    public static SecretText Secret(string value) => SecretText.FromChars(value);

    private readonly string _root = $@"Software\FidoLogonTests\dotnet-{Guid.NewGuid():N}";

    public NativeTestEnvironment()
    {
        FidoLogonTestHooks.UseCurrentUserStorage(_root);
        FidoLogonTestHooks.UseFakeAuthenticator(true);
        FidoLogonTestHooks.PlugFakeKey(DevicePath, Pin);
    }

    public static LocalAccount AnyEnabledAccount() =>
        FidoLogonApi.ListLocalAccounts().First(a => !a.Disabled);

    public void Dispose()
    {
        FidoLogonTestHooks.UseFakeAuthenticator(false);
        FidoLogonTestHooks.UseCurrentUserStorage(null);
        Registry.CurrentUser.DeleteSubKeyTree(_root, throwOnMissingSubKey: false);
        using RegistryKey? parent = Registry.CurrentUser.OpenSubKey(@"Software\FidoLogonTests", writable: true);
        if (parent is not null && parent.SubKeyCount == 0 && parent.ValueCount == 0)
        {
            Registry.CurrentUser.DeleteSubKey(@"Software\FidoLogonTests", throwOnMissingSubKey: false);
        }
    }
}
