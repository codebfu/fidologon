using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace FidoLogon.Core;

/// <summary>
/// A password or PIN kept out of immutable .NET strings: the characters live in a pinned,
/// null-terminated buffer that is handed to the native API without copies, excluded from
/// Windows Error Reporting dumps, and zeroed on <see cref="Dispose"/>.
/// </summary>
public sealed partial class SecretText : IDisposable
{
    private readonly char[] _buffer;
    private readonly bool _excludedFromDumps;
    private bool _disposed;

    private SecretText(int length)
    {
        // The pinned object heap never moves the array: its address stays valid for the native API
        // and for the dump exclusion.
        _buffer = GC.AllocateArray<char>(length + 1, pinned: true);
        Length = length;
        _excludedFromDumps = ExcludeFromDumps(_buffer, register: true);
    }

    public int Length { get; }

    public bool IsEmpty => Length == 0;

    public static SecretText Empty() => new(0);

    public static SecretText FromChars(ReadOnlySpan<char> value)
    {
        var secret = new SecretText(value.Length);
        value.CopyTo(secret._buffer);
        return secret;
    }

    /// <summary>Copies a <see cref="SecureString"/> (for example a WPF PasswordBox's SecurePassword).</summary>
    public static SecretText FromSecureString(SecureString value)
    {
        ArgumentNullException.ThrowIfNull(value);
        IntPtr unmanaged = Marshal.SecureStringToGlobalAllocUnicode(value);
        try
        {
            var secret = new SecretText(value.Length);
            unsafe
            {
                new ReadOnlySpan<char>((void*)unmanaged, value.Length).CopyTo(secret._buffer);
            }
            return secret;
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(unmanaged);
        }
    }

    /// <summary>Null-terminated characters, valid until <see cref="Dispose"/>.</summary>
    internal char[] Buffer
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_buffer.AsSpan()));
        if (_excludedFromDumps)
        {
            ExcludeFromDumps(_buffer, register: false);
        }
    }

    private static unsafe bool ExcludeFromDumps(char[] buffer, bool register)
    {
        try
        {
            fixed (char* address = buffer)
            {
                uint size = (uint)(buffer.Length * sizeof(char));
                return register
                    ? WerRegisterExcludedMemoryBlock(address, size) >= 0
                    : WerUnregisterExcludedMemoryBlock(address) >= 0;
            }
        }
        catch (EntryPointNotFoundException)
        {
            return false;  // Windows without the API: the buffer is still wiped on Dispose
        }
    }

    [LibraryImport("kernel32.dll")]
    private static unsafe partial int WerRegisterExcludedMemoryBlock(void* address, uint size);

    [LibraryImport("kernel32.dll")]
    private static unsafe partial int WerUnregisterExcludedMemoryBlock(void* address);
}
