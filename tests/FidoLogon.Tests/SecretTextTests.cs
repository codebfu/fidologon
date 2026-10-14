using System.Security;
using FidoLogon.Core;

namespace FidoLogon.Tests;

public sealed class SecretTextTests
{
    [Fact]
    public void BufferIsNullTerminatedAndWipedOnDispose()
    {
        var secret = SecretText.FromChars("p4ss");
        char[] buffer = secret.Buffer;
        Assert.Equal("p4ss\0", new string(buffer));
        Assert.Equal(4, secret.Length);

        secret.Dispose();
        Assert.All(buffer, c => Assert.Equal('\0', c));
        Assert.Throws<ObjectDisposedException>(() => secret.Buffer);
        secret.Dispose();  // idempotent
    }

    [Fact]
    public void CopiesSecureString()
    {
        using var secure = new SecureString();
        foreach (char c in "1234")
        {
            secure.AppendChar(c);
        }
        using SecretText secret = SecretText.FromSecureString(secure);
        Assert.Equal("1234\0", new string(secret.Buffer));
    }

    [Fact]
    public void EmptySecretIsEmpty()
    {
        using SecretText secret = SecretText.Empty();
        Assert.True(secret.IsEmpty);
        Assert.Equal("\0", new string(secret.Buffer));
    }
}
