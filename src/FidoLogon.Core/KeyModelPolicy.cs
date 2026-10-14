using System.Security.Cryptography.X509Certificates;

namespace FidoLogon.Core;

/// <summary>Outcome of a FIDO Metadata Service BLOB import.</summary>
/// <param name="Updated">Allowed models refreshed from the new BLOB (roots and status).</param>
/// <param name="Missing">Allowed models the new BLOB no longer describes (kept unchanged).</param>
/// <param name="Blocked">Allowed models whose new status is blocked: enrollment now refuses them.</param>
public sealed record MetadataImportResult(int Number, DateOnly NextUpdate, int EntryCount,
    IReadOnlyList<string> Updated, IReadOnlyList<string> Missing, IReadOnlyList<string> Blocked)
{
    public bool IsOutdated(DateOnly today) => NextUpdate < today;
}

/// <summary>Outcome of a download from the FIDO Metadata Service.</summary>
/// <param name="Import">The import of the downloaded BLOB, or null when the imported one was already the latest.</param>
public sealed record MetadataSyncResult(int Number, DateOnly NextUpdate, MetadataImportResult? Import)
{
    public bool UpToDate => Import is null;
}

/// <summary>
/// Key model allow-list, fed by the FIDO Metadata Service: the administrator imports (or the service
/// downloads) the MDS3 BLOB, then allows models by AAGUID. Enrollment (native code) accepts a key only
/// if its attestation chains to the roots stored for its model. Every FIDO2 model of the imported BLOB
/// is also kept as a "certified model": when <see cref="FidoLogonApi.AllowCertifiedModels"/> is on, all
/// of them are accepted too. With an empty list and certified models not allowed, every model is accepted.
/// </summary>
/// <remarks>
/// The BLOB is verified in memory and never written to disk: only its number, its next update date and
/// its certified models are kept, in the registry store that only SYSTEM and Administrators can write.
/// </remarks>
public sealed class KeyModelPolicy(X509Certificate2 trustAnchor)
{
    /// <summary>Where the FIDO Alliance publishes the MDS3 BLOB.</summary>
    public const string MetadataServiceUrl = "https://mds3.fidoalliance.org/";

    /// <summary>Upper bound for a downloaded BLOB (the real one is a few megabytes).</summary>
    public const int MaxBlobSize = 64 * 1024 * 1024;

    public static KeyModelPolicy CreateDefault() => new(MetadataTrustAnchor.Load());

    /// <summary>
    /// What is kept of the imported BLOB (number, next update and certified models), or null if none
    /// was imported.
    /// </summary>
    public MetadataBlob? LoadMetadata()
    {
        if (FidoLogonApi.GetMetadataInfo() is not { } info)
        {
            return null;
        }
        List<MetadataEntry> entries = FidoLogonApi.ListCertifiedModels()
            .Select(m => new MetadataEntry(m.Aaguid, m.Description, m.Status, []))
            .ToList();
        return MetadataBlob.FromStored(info.Number, info.NextUpdate, entries);
    }

    public MetadataImportResult Import(string blobFile) => ImportJwt(File.ReadAllText(blobFile));

    /// <summary>Verifies a BLOB, then refreshes the allowed and certified models from it.</summary>
    public MetadataImportResult ImportJwt(string jwt)
    {
        MetadataBlob blob = MetadataBlob.Parse(jwt, trustAnchor, DateTime.UtcNow);
        if (FidoLogonApi.GetMetadataInfo() is { } current && blob.Number < current.Number)
        {
            throw new MetadataException(
                $"This BLOB (#{blob.Number}) is older than the imported one (#{current.Number}).");
        }

        List<string> updated = [];
        List<string> missing = [];
        List<string> blocked = [];
        foreach (AllowedKeyModel model in FidoLogonApi.ListAllowedModels())
        {
            if (blob.Find(model.Aaguid) is not { } entry || entry.AttestationRootCertificates.Count == 0)
            {
                missing.Add(model.Aaguid);
                continue;
            }
            FidoLogonApi.SetAllowedModel(entry.Aaguid, entry.Description, entry.Status, entry.AttestationRootCertificates);
            updated.Add(entry.Aaguid);
            if (entry.IsBlocked)
            {
                blocked.Add(entry.Aaguid);
            }
        }
        FidoLogonApi.ReplaceCertifiedModels(CertifiedEntries(blob));
        FidoLogonApi.SetMetadataInfo(blob.Number, blob.NextUpdate);
        return new MetadataImportResult(blob.Number, blob.NextUpdate, blob.Entries.Count, updated, missing, blocked);
    }

    /// <summary>
    /// Downloads the BLOB from <see cref="MetadataServiceUrl"/> and imports it when it is newer than the
    /// imported one. It is verified exactly like a BLOB imported from a file.
    /// </summary>
    public async Task<MetadataSyncResult> SyncAsync(HttpClient http, CancellationToken cancellationToken = default)
    {
        string jwt;
        try
        {
            using HttpResponseMessage response = await http.GetAsync(MetadataServiceUrl,
                HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength > MaxBlobSize)
            {
                throw new MetadataException("The FIDO Metadata Service returned a file that is too large.");
            }
            await using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var buffer = new MemoryStream();
            byte[] chunk = new byte[81920];
            int read;
            while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
            {
                if (buffer.Length + read > MaxBlobSize)
                {
                    throw new MetadataException("The FIDO Metadata Service returned a file that is too large.");
                }
                buffer.Write(chunk, 0, read);
            }
            jwt = System.Text.Encoding.ASCII.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new MetadataException($"Could not download the FIDO Metadata Service BLOB: {ex.Message}");
        }

        MetadataBlob blob = MetadataBlob.Parse(jwt, trustAnchor, DateTime.UtcNow);
        if (FidoLogonApi.GetMetadataInfo() is { } current && blob.Number <= current.Number &&
            FidoLogonApi.CountCertifiedModels() > 0)
        {
            return new MetadataSyncResult(current.Number, current.NextUpdate, null);
        }
        MetadataImportResult import = ImportJwt(jwt);
        return new MetadataSyncResult(import.Number, import.NextUpdate, import);
    }

    /// <summary>HTTP client for <see cref="SyncAsync"/> (system proxy, two-minute timeout).</summary>
    public static HttpClient CreateHttpClient()
    {
        var http = new HttpClient { Timeout = TimeSpan.FromMinutes(2) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("FidoLogon");
        return http;
    }

    /// <summary>True when no BLOB was imported or its next update date has passed.</summary>
    public bool NeedsSync(DateOnly today) =>
        FidoLogonApi.GetMetadataInfo() is not { } current || current.NextUpdate <= today;

    /// <summary>
    /// Allows (or stops allowing) every FIDO2 model certified in the imported metadata. Turning it on
    /// requires imported metadata.
    /// </summary>
    public void SetAllowCertifiedModels(bool allow)
    {
        if (allow && FidoLogonApi.CountCertifiedModels() == 0)
        {
            throw new MetadataException("Import or synchronize the FIDO Metadata Service BLOB first.");
        }
        FidoLogonApi.AllowCertifiedModels = allow;
    }

    // Blocked models are kept: enrollment then names their status instead of "not allowed".
    private static List<MetadataEntry> CertifiedEntries(MetadataBlob blob) =>
        blob.Entries.Where(e => e.AttestationRootCertificates.Count > 0).ToList();

    /// <summary>Adds a certified model of the imported metadata to the allow-list.</summary>
    public MetadataEntry Allow(string aaguid)
    {
        if (FidoLogonApi.GetMetadataInfo() is null)
        {
            throw new MetadataException("Import a FIDO Metadata Service BLOB first.");
        }
        string id = aaguid.Trim();
        AllowedKeyModel model = FidoLogonApi.ListCertifiedModels()
            .FirstOrDefault(m => string.Equals(m.Aaguid, id, StringComparison.OrdinalIgnoreCase))
            ?? throw new MetadataException(
                $"No FIDO2 model with AAGUID {aaguid} and attestation root certificates in the imported metadata.");
        if (model.IsBlocked)
        {
            throw new MetadataException($"{model.Description} has status {model.Status} and cannot be allowed.");
        }
        FidoLogonApi.AllowCertifiedModel(model.Aaguid);
        return new MetadataEntry(model.Aaguid, model.Description, model.Status, []);
    }

    public static void Remove(string aaguid) => FidoLogonApi.RemoveAllowedModel(aaguid.Trim().ToLowerInvariant());
}
