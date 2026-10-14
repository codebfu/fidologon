using System.Security.Cryptography;
using FidoLogon.Core;

namespace FidoLogon.Cli;

internal interface ITerminal
{
    void WriteLine(string text = "");

    void WriteError(string text);

    string ReadLine(string prompt);

    /// <summary>Reads a secret without echoing it. The caller disposes it.</summary>
    SecretText ReadSecret(string prompt);
}

internal sealed class ConsoleTerminal : ITerminal
{
    public void WriteLine(string text = "") => Console.WriteLine(text);

    public void WriteError(string text) => Console.Error.WriteLine(text);

    public string ReadLine(string prompt)
    {
        Console.Write(prompt);
        return Console.ReadLine() ?? string.Empty;
    }

    // Windows passwords are at most 256 characters; FIDO2 PINs at most 63.
    private const int MaxSecretLength = 256;

    public SecretText ReadSecret(string prompt)
    {
        Console.Write(prompt);
        if (Console.IsInputRedirected)
        {
            // Piped input only exists as a string: kept for scripting, not for interactive use.
            return SecretText.FromChars(Console.ReadLine() ?? string.Empty);
        }
        char[] buffer = GC.AllocateArray<char>(MaxSecretLength, pinned: true);
        int length = 0;
        try
        {
            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    return SecretText.FromChars(buffer.AsSpan(0, length));
                }
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (length > 0)
                    {
                        buffer[--length] = '\0';
                    }
                }
                else if (!char.IsControl(key.KeyChar) && length < buffer.Length)
                {
                    buffer[length++] = key.KeyChar;
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(buffer.AsSpan()));
        }
    }
}
