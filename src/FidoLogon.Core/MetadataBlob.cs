using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace FidoLogon.Core;

public sealed class MetadataException(string message) : Exception(message);

/// <summary>One FIDO2 authenticator model described by the FIDO Metadata Service.</summary>
/// <param name="Status">Latest status report, e.g. FIDO_CERTIFIED_L1 or REVOKED.</param>
public sealed record MetadataEntry(string Aaguid, string Description, string Status,
    IReadOnlyList<byte[]> AttestationRootCertificates)
{
    /// <summary>Statuses that make a model unacceptable (same list as the native enrollment check).</summary>
    public static readonly IReadOnlySet<string> BlockedStatuses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "REVOKED",
        "USER_VERIFICATION_BYPASS",
        "ATTESTATION_KEY_COMPROMISE",
        "USER_KEY_REMOTE_COMPROMISE",
        "USER_KEY_PHYSICAL_COMPROMISE",
    };

    public bool IsBlocked => BlockedStatuses.Contains(Status);
}

/// <summary>
/// FIDO Metadata Service (MDS3) BLOB: a JWT signed by the FIDO Alliance, downloaded by the
/// administrator from https://mds3.fidoalliance.org/ and imported offline.
/// </summary>
public sealed class MetadataBlob
{
    /// <summary>Host name the signing certificate must be issued to.</summary>
    public const string SignerHostName = "mds.fidoalliance.org";

    private MetadataBlob(int number, DateOnly nextUpdate, IReadOnlyList<MetadataEntry> entries)
    {
        Number = number;
        NextUpdate = nextUpdate;
        Entries = entries;
    }

    /// <summary>Serial number of the BLOB, increased by every new release.</summary>
    public int Number { get; }

    /// <summary>Date by which a newer BLOB is published.</summary>
    public DateOnly NextUpdate { get; }

    /// <summary>FIDO2 entries (those identified by an AAGUID).</summary>
    public IReadOnlyList<MetadataEntry> Entries { get; }

    /// <summary>
    /// What is kept of the imported BLOB: its number and date, and its certified models (their
    /// attestation roots stay in the store and are not loaded).
    /// </summary>
    internal static MetadataBlob FromStored(int number, DateOnly nextUpdate, IReadOnlyList<MetadataEntry> entries) =>
        new(number, nextUpdate, entries);

    public MetadataEntry? Find(string aaguid) =>
        Entries.FirstOrDefault(e => string.Equals(e.Aaguid, aaguid, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Verifies the signature and the signing certificate chain up to <paramref name="trustAnchor"/>,
    /// then parses the entries. Revocation is not checked (the computer may be offline).
    /// </summary>
    public static MetadataBlob Parse(string jwt, X509Certificate2 trustAnchor, DateTime verificationTime)
    {
        ArgumentNullException.ThrowIfNull(jwt);
        ArgumentNullException.ThrowIfNull(trustAnchor);
        // The BLOB is untrusted input: any parse failure (a value of the wrong JSON kind, for one) is reported
        // as a MetadataException, which every caller handles.
        try
        {
            return ParseUnchecked(jwt, trustAnchor, verificationTime);
        }
        catch (Exception e) when (e is not MetadataException and not OutOfMemoryException)
        {
            throw new MetadataException($"Invalid BLOB: {e.Message}");
        }
    }

    private static MetadataBlob ParseUnchecked(string jwt, X509Certificate2 trustAnchor, DateTime verificationTime)
    {
        string[] parts = jwt.Trim().Split('.');
        if (parts.Length != 3)
        {
            throw new MetadataException("The file is not a FIDO Metadata Service BLOB (JWT expected).");
        }

        using JsonDocument header = ParseJson(parts[0], "header");
        string algorithm = GetString(header.RootElement, "alg");
        List<X509Certificate2> certificates = [];
        try
        {
            if (!header.RootElement.TryGetProperty("x5c", out JsonElement x5c) || x5c.ValueKind != JsonValueKind.Array ||
                x5c.GetArrayLength() == 0)
            {
                throw new MetadataException("The BLOB header has no signing certificate (x5c).");
            }
            foreach (JsonElement item in x5c.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String)
                {
                    throw new MetadataException("The BLOB header has an invalid signing certificate (x5c).");
                }
                certificates.Add(X509CertificateLoader.LoadCertificate(Convert.FromBase64String(item.GetString()!)));
            }
            VerifySigner(certificates, trustAnchor, verificationTime);
            VerifySignature(certificates[0], algorithm, parts);
        }
        catch (Exception e) when (e is FormatException or CryptographicException)
        {
            throw new MetadataException($"Invalid BLOB signature data: {e.Message}");
        }
        finally
        {
            certificates.ForEach(c => c.Dispose());
        }

        using JsonDocument payload = ParseJson(parts[1], "payload");
        return ParsePayload(payload.RootElement);
    }

    private static void VerifySigner(List<X509Certificate2> certificates, X509Certificate2 trustAnchor,
        DateTime verificationTime)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(trustAnchor);
        chain.ChainPolicy.ExtraStore.AddRange(certificates.Skip(1).ToArray());
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = verificationTime;
        if (!chain.Build(certificates[0]))
        {
            string reasons = string.Join(", ", chain.ChainStatus.Select(s => s.Status));
            throw new MetadataException($"The BLOB is not signed by the FIDO Alliance ({reasons}).");
        }
        if (!certificates[0].MatchesHostname(SignerHostName))
        {
            throw new MetadataException($"The BLOB signing certificate is not issued to {SignerHostName}.");
        }
    }

    private static void VerifySignature(X509Certificate2 signer, string algorithm, string[] parts)
    {
        byte[] signedData = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        byte[] signature = Base64Url.DecodeFromChars(parts[2]);
        bool valid = algorithm switch
        {
            "RS256" => signer.GetRSAPublicKey()?.VerifyData(signedData, signature, HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1) ?? false,
            "PS256" => signer.GetRSAPublicKey()?.VerifyData(signedData, signature, HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss) ?? false,
            "ES256" => signer.GetECDsaPublicKey()?.VerifyData(signedData, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation) ?? false,
            _ => throw new MetadataException($"Unsupported BLOB signature algorithm '{algorithm}'."),
        };
        if (!valid)
        {
            throw new MetadataException("The BLOB signature is invalid: the file was modified or damaged.");
        }
    }

    private static MetadataBlob ParsePayload(JsonElement root)
    {
        try
        {
            int number = root.GetProperty("no").GetInt32();
            DateOnly nextUpdate = DateOnly.ParseExact(GetString(root, "nextUpdate"), "yyyy-MM-dd",
                CultureInfo.InvariantCulture);
            List<MetadataEntry> entries = [];
            foreach (JsonElement entry in root.GetProperty("entries").EnumerateArray())
            {
                if (!entry.TryGetProperty("aaguid", out JsonElement aaguid) || aaguid.GetString() is not { } id)
                {
                    continue;  // U2F or UAF authenticator: not usable by FidoLogon
                }
                JsonElement statement = entry.GetProperty("metadataStatement");
                List<byte[]> roots = [];
                if (statement.TryGetProperty("attestationRootCertificates", out JsonElement rootList))
                {
                    roots.AddRange(rootList.EnumerateArray().Select(r => Convert.FromBase64String(r.GetString() ?? "")));
                }
                entries.Add(new MetadataEntry(id.ToLowerInvariant(),
                    statement.TryGetProperty("description", out JsonElement d) ? d.GetString() ?? "" : "",
                    LatestStatus(entry), roots));
            }
            return new MetadataBlob(number, nextUpdate, entries);
        }
        catch (Exception e) when (e is KeyNotFoundException or InvalidOperationException or FormatException)
        {
            throw new MetadataException($"Unexpected BLOB content: {e.Message}");
        }
    }

    private static string LatestStatus(JsonElement entry)
    {
        if (!entry.TryGetProperty("statusReports", out JsonElement reports) || reports.ValueKind != JsonValueKind.Array)
        {
            return "";
        }
        // The latest effective report wins; reports without a date count as oldest.
        string status = "";
        string latestDate = "";
        foreach (JsonElement report in reports.EnumerateArray())
        {
            string date = report.TryGetProperty("effectiveDate", out JsonElement d) ? d.GetString() ?? "" : "";
            if (string.CompareOrdinal(date, latestDate) >= 0)
            {
                latestDate = date;
                status = report.TryGetProperty("status", out JsonElement s) ? s.GetString() ?? "" : "";
            }
        }
        return status;
    }

    private static JsonDocument ParseJson(string base64Url, string part)
    {
        try
        {
            return JsonDocument.Parse(Base64Url.DecodeFromChars(base64Url));
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            throw new MetadataException($"The BLOB {part} is not valid JSON: {e.Message}");
        }
    }

    private static string GetString(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out JsonElement value) &&
        value.ValueKind == JsonValueKind.String
            ? value.GetString()!
            : throw new MetadataException($"The BLOB has no '{name}' text field.");
}
