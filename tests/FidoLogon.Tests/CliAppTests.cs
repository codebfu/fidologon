using FidoLogon.Cli;
using FidoLogon.Core;

namespace FidoLogon.Tests;

internal sealed class FakeTerminal : ITerminal
{
    private readonly Queue<string> _inputs = new();

    public List<string> Output { get; } = [];

    public List<string> Errors { get; } = [];

    public FakeTerminal Answer(params string[] inputs)
    {
        foreach (string input in inputs)
        {
            _inputs.Enqueue(input);
        }
        return this;
    }

    public string AllOutput => string.Join("\n", Output);

    public void WriteLine(string text = "") => Output.Add(text);

    public void WriteError(string text) => Errors.Add(text);

    public string ReadLine(string prompt) => _inputs.Dequeue();

    public SecretText ReadSecret(string prompt) => SecretText.FromChars(_inputs.Dequeue());
}

public sealed class CommandLineTests
{
    [Fact]
    public void ParsesCommandOptionsFlagsAndPositionals()
    {
        var line = CommandLine.Parse(["Enroll", "--user", "alice", "--yes", "extra", "--mode", "touch"]);
        Assert.Equal("enroll", line.Command);
        Assert.Equal("alice", line.Option("USER"));
        Assert.Equal("touch", line.Option("mode"));
        Assert.True(line.Flag("yes"));
        Assert.Equal(["extra"], line.Positionals);
    }

    [Fact]
    public void DefaultsToHelp() => Assert.Equal("help", CommandLine.Parse([]).Command);

    [Fact]
    public void RejectsOptionWithoutValue() =>
        Assert.Throws<UsageException>(() => CommandLine.Parse(["enroll", "--user"]));

    [Fact]
    public void RejectsUnknownOptions() =>
        Assert.Throws<UsageException>(() => CommandLine.Parse(["remove", "--force", "x"]).EnsureOnly());
}

[Collection(NativeCollection.Name)]
public sealed class CliAppTests : IDisposable
{
    private readonly NativeTestEnvironment _environment = new();

    public void Dispose() => _environment.Dispose();

    // Enrollment without Windows password verification (the tests have no real password).
    private static CliApp CreateApp(FakeTerminal terminal) =>
        new(terminal, (device, account, label, mode, pin, password, onTouch) =>
            FidoLogonApi.Enroll(device.Path, account, label, mode, pin, password, onTouch));

    [Fact]
    public void UnknownCommandIsAUsageError()
    {
        var terminal = new FakeTerminal();
        Assert.Equal(2, CreateApp(terminal).Run(["frobnicate"]));
        Assert.Contains(terminal.Errors, e => e.Contains("Unknown command", StringComparison.Ordinal));
    }

    [Fact]
    public void EnrollRequiresUser()
    {
        var terminal = new FakeTerminal();
        Assert.Equal(2, CreateApp(terminal).Run(["enroll"]));
    }

    [Fact]
    public void FullKeyLifecycle()
    {
        string user = NativeTestEnvironment.AnyEnabledAccount().Name;

        var terminal = new FakeTerminal();
        Assert.Equal(0, CreateApp(terminal).Run(["list"]));
        Assert.Contains("No key enrolled.", terminal.Output);

        terminal = new FakeTerminal();
        Assert.Equal(0, CreateApp(terminal).Run(["devices"]));
        Assert.Contains(terminal.Output, l => l.Contains("PIN set: yes", StringComparison.Ordinal) &&
                                              l.Contains("credProtect: yes", StringComparison.Ordinal));

        terminal = new FakeTerminal().Answer("Windows-Password", NativeTestEnvironment.Pin);
        Assert.Equal(0, CreateApp(terminal).Run(["enroll", "--user", user, "--label", "Desk key"]));
        Assert.Contains(terminal.Output, l => l.StartsWith($"Key enrolled for {user}", StringComparison.Ordinal));
        Assert.Contains("Touch your security key now (1/2): it blinks while it waits.", terminal.Output);
        Assert.Contains("Touch your security key now (2/2): it blinks while it waits.", terminal.Output);

        string id = Assert.Single(FidoLogonApi.ListEnrolledKeys()).Id;

        terminal = new FakeTerminal();
        Assert.Equal(0, CreateApp(terminal).Run(["list"]));
        Assert.Contains(terminal.Output, l => l.Contains("Desk key", StringComparison.Ordinal) &&
                                              l.Contains("PIN + touch", StringComparison.Ordinal));

        terminal = new FakeTerminal().Answer(NativeTestEnvironment.Pin);
        Assert.Equal(0, CreateApp(terminal).Run(["test", id.Trim('{', '}')]));
        Assert.Contains(terminal.Output, l => l.StartsWith("OK", StringComparison.Ordinal));
        Assert.Contains("Touch your security key now: it blinks while it waits.", terminal.Output);

        terminal = new FakeTerminal().Answer("000000");
        Assert.Equal(1, CreateApp(terminal).Run(["test", id]));
        Assert.Contains(terminal.Errors, e => e.Contains("Incorrect security key PIN", StringComparison.Ordinal));

        terminal = new FakeTerminal().Answer("n");
        Assert.Equal(1, CreateApp(terminal).Run(["remove", id]));
        Assert.Single(FidoLogonApi.ListEnrolledKeys());

        terminal = new FakeTerminal();
        Assert.Equal(0, CreateApp(terminal).Run(["remove", id, "--yes"]));
        Assert.Empty(FidoLogonApi.ListEnrolledKeys());
    }

    [Fact]
    public void TouchOnlyEnrollmentWarnsAndStillAsksPinOfProtectedKey()
    {
        string user = NativeTestEnvironment.AnyEnabledAccount().Name;
        var terminal = new FakeTerminal().Answer("Windows-Password", NativeTestEnvironment.Pin);
        Assert.Equal(0, CreateApp(terminal).Run(["enroll", "--user", user, "--mode", "touch", "--device", "0"]));
        Assert.Contains(terminal.Output, l => l.Contains("anyone holding this key", StringComparison.Ordinal));
        Assert.False(Assert.Single(FidoLogonApi.ListEnrolledKeys()).RequirePin);
    }

    [Fact]
    public void LockOnRemovalCanBeSetMachineWideAndPerKey()
    {
        string user = NativeTestEnvironment.AnyEnabledAccount().Name;
        var terminal = new FakeTerminal().Answer("Windows-Password", NativeTestEnvironment.Pin);
        Assert.Equal(0, CreateApp(terminal).Run(["enroll", "--user", user, "--lock-on-removal", "off"]));
        Assert.Contains("Lock on removal: off for this key.", terminal.Output);
        EnrolledKey key = Assert.Single(FidoLogonApi.ListEnrolledKeys());
        Assert.False(key.LockOnRemoval);

        terminal = new FakeTerminal();
        Assert.Equal(0, CreateApp(terminal).Run(["list"]));
        Assert.Contains(terminal.Output, l => l.Contains("lock on removal: off,", StringComparison.Ordinal));

        Assert.Equal(0, CreateApp(new FakeTerminal()).Run(["set", key.Id, "--lock-on-removal", "default"]));
        Assert.Null(Assert.Single(FidoLogonApi.ListEnrolledKeys()).LockOnRemoval);

        terminal = new FakeTerminal();
        Assert.Equal(0, CreateApp(terminal).Run(["config", "lock-on-removal", "off"]));
        Assert.False(FidoLogonApi.LockOnKeyRemoval);
        Assert.False(FidoLogonApi.ShouldLockOnRemoval(key.Id));

        terminal = new FakeTerminal();
        Assert.Equal(0, CreateApp(terminal).Run(["list"]));
        Assert.Contains(terminal.Output, l => l.Contains("lock on removal: default (off),", StringComparison.Ordinal));

        Assert.Equal(0, CreateApp(new FakeTerminal()).Run(["set", key.Id.Trim('{', '}'), "--lock-on-removal", "on"]));
        Assert.True(FidoLogonApi.ShouldLockOnRemoval(key.Id));

        terminal = new FakeTerminal();
        Assert.Equal(0, CreateApp(terminal).Run(["config"]));
        Assert.Contains("lock-on-removal: off", terminal.Output);
        Assert.Contains("  (1 key(s) override it, see 'fidologon list')", terminal.Output);

        Assert.Equal(2, CreateApp(new FakeTerminal()).Run(["set", key.Id, "--lock-on-removal", "maybe"]));
        Assert.Equal(2, CreateApp(new FakeTerminal()).Run(["set", key.Id]));
        Assert.Equal(1, CreateApp(new FakeTerminal()).Run(["set", "{nope}", "--lock-on-removal", "on"]));
        Assert.Equal(0, CreateApp(new FakeTerminal()).Run(["config", "lock-on-removal", "on"]));
        Assert.True(FidoLogonApi.LockOnKeyRemoval);
    }

    [Fact]
    public void ConfigTogglesPasswordFallback()
    {
        var terminal = new FakeTerminal();
        Assert.Equal(0, CreateApp(terminal).Run(["config", "password-fallback", "off"]));
        Assert.False(FidoLogonApi.AllowPasswordFallback);
        Assert.Contains(terminal.Output, l => l.Contains("Not effective yet", StringComparison.Ordinal));

        terminal = new FakeTerminal();
        Assert.Equal(0, CreateApp(terminal).Run(["config"]));
        Assert.Contains("password-fallback: off", terminal.Output);

        Assert.Equal(2, CreateApp(new FakeTerminal()).Run(["config", "password-fallback", "maybe"]));
        Assert.Equal(0, CreateApp(new FakeTerminal()).Run(["config", "password-fallback", "on"]));
        Assert.True(FidoLogonApi.AllowPasswordFallback);
    }
}
