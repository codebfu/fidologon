namespace FidoLogon.Cli;

/// <summary>Parsed command line: a command, positional arguments, "--name value" options and "--flag" switches.</summary>
internal sealed class CommandLine
{
    private static readonly HashSet<string> KnownFlags = new(StringComparer.OrdinalIgnoreCase) { "yes", "help" };

    private readonly Dictionary<string, string> _options = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _flags = new(StringComparer.OrdinalIgnoreCase);

    public string Command { get; private init; } = "help";

    public List<string> Positionals { get; } = [];

    public static CommandLine Parse(IReadOnlyList<string> args)
    {
        var result = new CommandLine { Command = args.Count > 0 ? args[0].ToLowerInvariant() : "help" };
        for (int i = 1; i < args.Count; i++)
        {
            string arg = args[i];
            if (!arg.StartsWith("--", StringComparison.Ordinal))
            {
                result.Positionals.Add(arg);
                continue;
            }
            string name = arg[2..];
            if (name.Length == 0)
            {
                throw new UsageException("Empty option name.");
            }
            if (KnownFlags.Contains(name))
            {
                result._flags.Add(name);
                continue;
            }
            if (i + 1 >= args.Count)
            {
                throw new UsageException($"Option --{name} needs a value.");
            }
            result._options[name] = args[++i];
        }
        return result;
    }

    public string? Option(string name) => _options.GetValueOrDefault(name);

    public bool Flag(string name) => _flags.Contains(name);

    public void EnsureOnly(params string[] allowedOptions)
    {
        foreach (string name in _options.Keys)
        {
            if (!allowedOptions.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                throw new UsageException($"Unknown option --{name} for '{Command}'.");
            }
        }
    }
}

internal sealed class UsageException(string message) : Exception(message);
