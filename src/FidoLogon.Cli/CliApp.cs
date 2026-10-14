using System.Reflection;
using FidoLogon.Core;

namespace FidoLogon.Cli;

internal delegate string EnrollAction(SecurityKeyDevice device, LocalAccount account, string label, UnlockMode mode,
    SecretText pin, SecretText password, TouchPrompt? onTouch);

internal sealed class CliApp(ITerminal terminal, EnrollAction? enroll = null, KeyModelPolicy? models = null,
    Func<HttpClient>? http = null)
{
    private const string Usage = """
        FidoLogon - Windows sign-in with FIDO2 security keys

        Usage: fidologon <command> [options]

        Commands:
          devices                         List plugged FIDO2 security keys.
          users                           List local accounts and their number of enrolled keys.
          list                            List enrolled keys.
          enroll --user <name>            Enroll a key for a local account.
                 [--device <n|path>]      Key to use (index from 'devices'); optional if only one is plugged.
                 [--label <text>]         Display name of the key.
                 [--mode pin|touch]       Require the key PIN at sign-in (default) or only a touch.
                 [--lock-on-removal default|on|off]
                                          Lock the session when this key is removed
                                          (default: follow the machine-wide option).
          set <id> --lock-on-removal default|on|off
                                          Change the lock-on-removal behavior of an enrolled key.
          remove <id> [--yes]             Remove an enrolled key.
          test <id>                       Check that the plugged key still unlocks this enrollment.
          config                          Show options.
          config password-fallback on|off Keep or hide the Windows password tile.
          config lock-on-removal on|off   Lock the session when the key that opened it is removed
                                          (machine-wide default, on unless changed).
          config metadata-auto-sync on|off
                                          Let the service download a new FIDO Metadata Service
                                          BLOB once the imported one is outdated (on unless
                                          turned off at installation).
          models                          List the key models allowed at enrollment
                                          (empty list and certified models off: every
                                          model is accepted).
          models sync                     Download the latest FIDO Metadata Service BLOB from
                                          https://mds3.fidoalliance.org/ and import it.
          models import <file>            Import a FIDO Metadata Service BLOB downloaded from
                                          https://mds3.fidoalliance.org/ (verified offline).
          models certified on|off         Also allow every model certified in the imported
                                          metadata (its attestation is still checked; on
                                          unless turned off at installation).
          models search <text>            Search the imported metadata by name or AAGUID.
          models allow <aaguid>           Allow a key model (its attestation is then checked).
          models remove <aaguid>          Remove a key model from the allowed list.
          version                         Show the version.

        Administrator rights are required.
        """;

    private readonly EnrollAction _enroll = enroll ?? EnrollmentService.Enroll;
    private readonly Lazy<KeyModelPolicy> _models = new(() => models ?? KeyModelPolicy.CreateDefault());

    public int Run(IReadOnlyList<string> args)
    {
        try
        {
            CommandLine command = CommandLine.Parse(args);
            if (command.Flag("help"))
            {
                terminal.WriteLine(Usage);
                return 0;
            }
            return command.Command switch
            {
                "help" or "-h" or "/?" => Help(),
                "version" or "--version" => Version(),
                "devices" => Devices(),
                "users" => Users(),
                "list" => List(),
                "enroll" => Enroll(command),
                "set" => Set(command),
                "remove" => Remove(command),
                "test" => Test(command),
                "config" => Config(command),
                "models" => Models(command),
                _ => throw new UsageException($"Unknown command '{command.Command}'."),
            };
        }
        catch (UsageException e)
        {
            terminal.WriteError($"Error: {e.Message}");
            terminal.WriteError("Run 'fidologon help' for usage.");
            return 2;
        }
        catch (FidoLogonException e)
        {
            terminal.WriteError($"Error: {e.Message}");
            return 1;
        }
        catch (MetadataException e)
        {
            terminal.WriteError($"Error: {e.Message}");
            return 1;
        }
        catch (IOException e)
        {
            terminal.WriteError($"Error: {e.Message}");
            return 1;
        }
        catch (DllNotFoundException)
        {
            terminal.WriteError("Error: fidologon_native.dll is missing. Reinstall FidoLogon.");
            return 1;
        }
    }

    private int Help()
    {
        terminal.WriteLine(Usage);
        return 0;
    }

    private int Version()
    {
        string version = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";
        terminal.WriteLine($"FidoLogon {version}");
        return 0;
    }

    private int Devices()
    {
        IReadOnlyList<SecurityKeyDevice> devices = FidoLogonApi.ListDevices();
        if (devices.Count == 0)
        {
            terminal.WriteLine("No FIDO2 security key detected.");
            return 0;
        }
        for (int i = 0; i < devices.Count; i++)
        {
            string caps;
            try
            {
                SecurityKeyCapabilities c = FidoLogonApi.GetCapabilities(devices[i].Path);
                caps = $"PIN set: {(c.HasPin ? "yes" : "no")}, hmac-secret: {(c.HmacSecret ? "yes" : "NO (unsupported)")}, " +
                       $"credProtect: {(c.CredProtect ? "yes" : "no (touch-only mode only)")}";
            }
            catch (FidoLogonException e)
            {
                caps = $"unavailable: {e.Description}";
            }
            terminal.WriteLine($"[{i}] {devices[i].DisplayName} (USB {devices[i].UsbId})");
            terminal.WriteLine($"    {caps}");
            terminal.WriteLine($"    {devices[i].Path}");
        }
        return 0;
    }

    private int Users()
    {
        IReadOnlyList<EnrolledKey> keys = FidoLogonApi.ListEnrolledKeys();
        foreach (LocalAccount account in FidoLogonApi.ListLocalAccounts())
        {
            int count = keys.Count(k => string.Equals(k.UserSid, account.Sid, StringComparison.OrdinalIgnoreCase));
            string state = account.Disabled ? " [disabled]" : string.Empty;
            terminal.WriteLine($"{account.DisplayName}{state}: {count} key(s)");
        }
        return 0;
    }

    private int List()
    {
        IReadOnlyList<EnrolledKey> keys = FidoLogonApi.ListEnrolledKeys();
        if (keys.Count == 0)
        {
            terminal.WriteLine("No key enrolled.");
            return 0;
        }
        bool lockByDefault = FidoLogonApi.LockOnKeyRemoval;
        foreach (EnrolledKey key in keys)
        {
            string mode = key.RequirePin ? "PIN + touch" : "touch only";
            string lockOnRemoval = key.LockOnRemoval is null
                ? $"default ({OnOff(lockByDefault)})"
                : OnOff(key.LockOnRemoval.Value);
            string model = string.IsNullOrEmpty(key.Aaguid) ? "unknown" : key.Aaguid;
            terminal.WriteLine($"{key.Id}  {key.UserName,-20} {key.Label,-30} {mode,-12} {key.Created:yyyy-MM-dd}  " +
                               $"lock on removal: {lockOnRemoval}, model: {model}");
        }
        return 0;
    }

    private int Enroll(CommandLine command)
    {
        command.EnsureOnly("user", "device", "label", "mode", "lock-on-removal");
        string userName = command.Option("user") ?? throw new UsageException("--user is required.");
        bool? lockOnRemoval = ParseLockOnRemoval(command.Option("lock-on-removal") ?? "default");
        UnlockMode mode = (command.Option("mode") ?? "pin").ToLowerInvariant() switch
        {
            "pin" => UnlockMode.PinAndTouch,
            "touch" => UnlockMode.TouchOnly,
            _ => throw new UsageException("--mode must be 'pin' or 'touch'."),
        };

        LocalAccount account = FidoLogonApi.ListLocalAccounts()
            .FirstOrDefault(a => string.Equals(a.Name, userName, StringComparison.OrdinalIgnoreCase))
            ?? throw new UsageException($"No local account named '{userName}'.");
        SecurityKeyDevice device = SelectDevice(command.Option("device"));
        SecurityKeyCapabilities caps = FidoLogonApi.GetCapabilities(device.Path);
        if (!caps.HmacSecret)
        {
            throw new FidoLogonException(FidoLogonErrorCode.HmacSecretUnsupported,
                FidoLogonApi.DescribeError(FidoLogonErrorCode.HmacSecretUnsupported), null);
        }
        if (mode == UnlockMode.PinAndTouch && !caps.HasPin)
        {
            throw new FidoLogonException(FidoLogonErrorCode.PinNotSet,
                FidoLogonApi.DescribeError(FidoLogonErrorCode.PinNotSet), null);
        }
        if (mode == UnlockMode.PinAndTouch && !caps.CredProtect)
        {
            throw new FidoLogonException(FidoLogonErrorCode.CredProtectUnsupported,
                FidoLogonApi.DescribeError(FidoLogonErrorCode.CredProtectUnsupported), null);
        }
        if (mode == UnlockMode.TouchOnly)
        {
            terminal.WriteLine("Warning: in touch-only mode, anyone holding this key can sign in to the account.");
        }

        using SecretText password = terminal.ReadSecret($"Windows password for {account.Name}: ");
        using SecretText pin = caps.HasPin ? terminal.ReadSecret("Security key PIN: ") : SecretText.Empty();
        string id = _enroll(device, account, command.Option("label") ?? string.Empty, mode, pin, password, PromptTouch);
        terminal.WriteLine($"Key enrolled for {account.Name} (id {id}).");
        if (lockOnRemoval is not null)
        {
            FidoLogonApi.SetKeyLockOnRemoval(id, lockOnRemoval);
            terminal.WriteLine($"Lock on removal: {OnOff(lockOnRemoval.Value)} for this key.");
        }
        if (mode == UnlockMode.PinAndTouch)
        {
            terminal.WriteLine("Sign in by choosing the key icon under \"Sign-in options\", typing the PIN and touching the key.");
        }
        return 0;
    }

    private int Set(CommandLine command)
    {
        command.EnsureOnly("lock-on-removal");
        string id = command.Positionals.SingleOrDefault() ?? throw new UsageException("set needs exactly one id.");
        string value = command.Option("lock-on-removal") ?? throw new UsageException("--lock-on-removal is required.");
        bool? lockOnRemoval = ParseLockOnRemoval(value);
        EnrolledKey key = FindKey(id);
        FidoLogonApi.SetKeyLockOnRemoval(key.Id, lockOnRemoval);
        terminal.WriteLine(lockOnRemoval is null
            ? $"Lock on removal of key '{key.Label}' now follows the machine-wide option ({OnOff(FidoLogonApi.LockOnKeyRemoval)})."
            : $"Lock on removal of key '{key.Label}' set to {OnOff(lockOnRemoval.Value)}.");
        return 0;
    }

    private int Remove(CommandLine command)
    {
        command.EnsureOnly();
        string id = command.Positionals.SingleOrDefault() ?? throw new UsageException("remove needs exactly one id.");
        EnrolledKey key = FindKey(id);
        if (!command.Flag("yes"))
        {
            string answer = terminal.ReadLine($"Remove key '{key.Label}' of {key.UserName}? [y/N] ");
            if (!answer.Trim().Equals("y", StringComparison.OrdinalIgnoreCase) &&
                !answer.Trim().Equals("yes", StringComparison.OrdinalIgnoreCase))
            {
                terminal.WriteLine("Cancelled.");
                return 1;
            }
        }
        FidoLogonApi.RemoveEnrolledKey(key.Id);
        terminal.WriteLine("Key removed.");
        return 0;
    }

    private int Test(CommandLine command)
    {
        command.EnsureOnly();
        string id = command.Positionals.SingleOrDefault() ?? throw new UsageException("test needs exactly one id.");
        EnrolledKey key = FindKey(id);
        using SecretText pin = key.RequirePin ? terminal.ReadSecret("Security key PIN: ") : SecretText.Empty();
        FidoLogonApi.TestEnrolledKey(key.Id, pin, PromptTouch);
        terminal.WriteLine("OK: the key unlocks the stored credential.");
        return 0;
    }

    private int Config(CommandLine command)
    {
        command.EnsureOnly();
        if (command.Positionals.Count == 0)
        {
            bool fallback = FidoLogonApi.AllowPasswordFallback;
            terminal.WriteLine($"password-fallback: {OnOff(fallback)}");
            if (!fallback && FidoLogonApi.IsMachineJoined())
            {
                terminal.WriteLine("  (not effective: this computer is joined to a domain or Entra ID, so the password tile stays visible)");
            }
            else if (!fallback && !FidoLogonApi.EveryEnabledAccountHasKey())
            {
                terminal.WriteLine("  (not effective: some enabled accounts have no key, so the password tile stays visible)");
            }
            terminal.WriteLine($"lock-on-removal: {OnOff(FidoLogonApi.LockOnKeyRemoval)}");
            terminal.WriteLine($"metadata-auto-sync: {OnOff(FidoLogonApi.AutoSyncMetadata)}");
            int overrides = FidoLogonApi.ListEnrolledKeys().Count(k => k.LockOnRemoval is not null);
            if (overrides > 0)
            {
                terminal.WriteLine($"  ({overrides} key(s) override it, see 'fidologon list')");
            }
            return 0;
        }
        if (command.Positionals.Count != 2)
        {
            throw new UsageException("Usage: fidologon config password-fallback|lock-on-removal|metadata-auto-sync on|off");
        }
        string option = command.Positionals[0].ToLowerInvariant();
        bool enabled = command.Positionals[1].ToLowerInvariant() switch
        {
            "on" => true,
            "off" => false,
            _ => throw new UsageException("Value must be 'on' or 'off'."),
        };
        switch (option)
        {
            case "password-fallback":
                return SetPasswordFallback(enabled);
            case "lock-on-removal":
                FidoLogonApi.LockOnKeyRemoval = enabled;
                terminal.WriteLine($"lock-on-removal set to {OnOff(enabled)}.");
                if (!enabled)
                {
                    terminal.WriteLine("Removing a key no longer locks the session, except for keys set to 'on'. " +
                                       "Lock the session yourself (Win+L) when you leave.");
                }
                return 0;
            case "metadata-auto-sync":
                FidoLogonApi.AutoSyncMetadata = enabled;
                terminal.WriteLine($"metadata-auto-sync set to {OnOff(enabled)}.");
                if (enabled)
                {
                    terminal.WriteLine("The FidoLogon service checks once a day and downloads a new BLOB from " +
                                       $"{KeyModelPolicy.MetadataServiceUrl} once the imported one is outdated.");
                }
                return 0;
            default:
                throw new UsageException("Usage: fidologon config password-fallback|lock-on-removal|metadata-auto-sync on|off");
        }
    }

    private int SetPasswordFallback(bool allow)
    {
        FidoLogonApi.AllowPasswordFallback = allow;
        terminal.WriteLine($"password-fallback set to {(allow ? "on" : "off")}.");
        if (!allow && FidoLogonApi.IsMachineJoined())
        {
            terminal.WriteLine("Not effective: this computer is joined to a domain or Entra ID, so the password tile stays visible.");
        }
        else if (!allow)
        {
            terminal.WriteLine(FidoLogonApi.EveryEnabledAccountHasKey()
                ? "The password tile is now hidden at sign-in. Keep a backup key enrolled: see the recovery guide."
                : "Not effective yet: the password tile stays visible until every enabled account has a key.");
        }
        return 0;
    }

    private int Models(CommandLine command)
    {
        command.EnsureOnly();
        IReadOnlyList<string> arguments = command.Positionals;
        string action = arguments.Count == 0 ? "list" : arguments[0].ToLowerInvariant();
        string Argument() => arguments.Count == 2
            ? arguments[1]
            : throw new UsageException($"Usage: fidologon models {action} <{(action == "import" ? "file" : "aaguid")}>");
        switch (action)
        {
            case "list":
                return ListModels();
            case "import":
                return ReportImport(_models.Value.Import(Argument()));
            case "sync":
            {
                if (arguments.Count != 1)
                {
                    throw new UsageException("Usage: fidologon models sync");
                }
                using HttpClient client = (http ?? KeyModelPolicy.CreateHttpClient)();
                MetadataSyncResult sync = _models.Value.SyncAsync(client).GetAwaiter().GetResult();
                if (sync.Import is null)
                {
                    terminal.WriteLine($"Already up to date: BLOB #{sync.Number}, next update {sync.NextUpdate:yyyy-MM-dd}.");
                    return 0;
                }
                return ReportImport(sync.Import);
            }
            case "certified":
            {
                bool allow = (arguments.Count == 2 ? arguments[1].ToLowerInvariant() : "") switch
                {
                    "on" => true,
                    "off" => false,
                    _ => throw new UsageException("Usage: fidologon models certified on|off"),
                };
                _models.Value.SetAllowCertifiedModels(allow);
                terminal.WriteLine(allow
                    ? $"Every certified model of the imported metadata can now be enrolled " +
                      $"({FidoLogonApi.CountCertifiedModels()} models); its attestation is checked. " +
                      "Keep the metadata up to date ('fidologon models sync')."
                    : "Certified models are no longer allowed: only the allowed list counts.");
                return 0;
            }
            case "search":
            {
                if (arguments.Count < 2)
                {
                    throw new UsageException("Usage: fidologon models search <text>");
                }
                string text = string.Join(' ', arguments.Skip(1));
                MetadataBlob blob = _models.Value.LoadMetadata()
                    ?? throw new MetadataException("Import a FIDO Metadata Service BLOB first (fidologon models import <file>).");
                List<MetadataEntry> matches = blob.Entries
                    .Where(e => e.Description.Contains(text, StringComparison.OrdinalIgnoreCase) ||
                                e.Aaguid.StartsWith(text, StringComparison.OrdinalIgnoreCase))
                    .OrderBy(e => e.Description, StringComparer.OrdinalIgnoreCase)
                    .ToList();
                foreach (MetadataEntry entry in matches)
                {
                    terminal.WriteLine($"{entry.Aaguid}  {entry.Status,-22} {entry.Description}");
                }
                terminal.WriteLine($"{matches.Count} model(s) found.");
                return 0;
            }
            case "allow":
            {
                MetadataEntry entry = _models.Value.Allow(Argument());
                terminal.WriteLine($"Allowed {entry.Description} ({entry.Aaguid}, {entry.Status}).");
                terminal.WriteLine("Only allowed models can now be enrolled; keys already enrolled keep working.");
                return 0;
            }
            case "remove":
                KeyModelPolicy.Remove(Argument());
                terminal.WriteLine(FidoLogonApi.ListAllowedModels().Count == 0 && !FidoLogonApi.AllowCertifiedModels
                    ? "Model removed. The list is empty: every key model can be enrolled again."
                    : "Model removed.");
                return 0;
            default:
                throw new UsageException("Usage: fidologon models " +
                                         "[sync|import <file>|search <text>|allow <aaguid>|remove <aaguid>|certified on|off]");
        }
    }

    private int ReportImport(MetadataImportResult result)
    {
        terminal.WriteLine($"Imported FIDO Metadata Service BLOB #{result.Number} ({result.EntryCount} FIDO2 models, " +
                           $"next update {result.NextUpdate:yyyy-MM-dd}).");
        if (result.IsOutdated(DateOnly.FromDateTime(DateTime.Today)))
        {
            terminal.WriteLine("Warning: a newer BLOB should already be available; download it again.");
        }
        if (result.Updated.Count > 0)
        {
            terminal.WriteLine($"Updated allowed models: {string.Join(", ", result.Updated)}");
        }
        if (result.Missing.Count > 0)
        {
            terminal.WriteLine($"Not described any more (kept unchanged): {string.Join(", ", result.Missing)}");
        }
        if (result.Blocked.Count > 0)
        {
            terminal.WriteLine($"Warning: now revoked or compromised, enrollment refuses them: {string.Join(", ", result.Blocked)}");
        }
        return 0;
    }

    private int ListModels()
    {
        IReadOnlyList<AllowedKeyModel> allowed = FidoLogonApi.ListAllowedModels();
        bool certified = FidoLogonApi.AllowCertifiedModels;
        if (certified)
        {
            terminal.WriteLine($"Every certified model of the imported metadata is allowed " +
                               $"({FidoLogonApi.CountCertifiedModels()} models), plus this list:");
        }
        else if (allowed.Count == 0)
        {
            terminal.WriteLine("No key model restriction: every FIDO2 key model can be enrolled.");
        }
        foreach (AllowedKeyModel model in allowed)
        {
            string blocked = model.IsBlocked ? "  (blocked: enrollment refused)" : "";
            terminal.WriteLine($"{model.Aaguid}  {model.Status,-22} {model.Description}{blocked}");
        }
        try
        {
            terminal.WriteLine(_models.Value.LoadMetadata() is { } blob
                ? $"Imported metadata: BLOB #{blob.Number}, next update {blob.NextUpdate:yyyy-MM-dd}."
                : "No FIDO Metadata Service BLOB imported.");
        }
        catch (MetadataException e)
        {
            terminal.WriteLine($"The imported metadata is invalid: {e.Message}");
        }
        return 0;
    }

    private static string OnOff(bool value) => value ? "on" : "off";

    private void PromptTouch(int touch, int total) =>
        terminal.WriteLine(total > 1
            ? $"Touch your security key now ({touch}/{total}): it blinks while it waits."
            : "Touch your security key now: it blinks while it waits.");

    private static bool? ParseLockOnRemoval(string value) => value.ToLowerInvariant() switch
    {
        "default" => null,
        "on" => true,
        "off" => false,
        _ => throw new UsageException("--lock-on-removal must be 'default', 'on' or 'off'."),
    };

    private SecurityKeyDevice SelectDevice(string? selector)
    {
        IReadOnlyList<SecurityKeyDevice> devices = FidoLogonApi.ListDevices();
        if (devices.Count == 0)
        {
            throw new FidoLogonException(FidoLogonErrorCode.NoDevice, "No FIDO2 security key detected.", null);
        }
        if (selector is null)
        {
            return devices.Count == 1
                ? devices[0]
                : throw new UsageException("Several keys are plugged: choose one with --device (see 'fidologon devices').");
        }
        if (int.TryParse(selector, out int index))
        {
            return index >= 0 && index < devices.Count
                ? devices[index]
                : throw new UsageException($"No device with index {index}.");
        }
        return devices.FirstOrDefault(d => string.Equals(d.Path, selector, StringComparison.OrdinalIgnoreCase))
            ?? throw new UsageException($"No device with path '{selector}'.");
    }

    private static EnrolledKey FindKey(string id)
    {
        string normalized = id.Trim().Trim('{', '}');
        return FidoLogonApi.ListEnrolledKeys().FirstOrDefault(k =>
                   string.Equals(k.Id.Trim('{', '}'), normalized, StringComparison.OrdinalIgnoreCase))
               ?? throw new FidoLogonException(FidoLogonErrorCode.NotFound, $"No enrolled key with id '{id}'.", null);
    }
}
