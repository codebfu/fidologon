using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using FidoLogon.Core;
using static FidoLogon.Tests.NativeTestEnvironment;

namespace FidoLogon.Tests;

/// <summary>Test PKI standing in for GlobalSign and the FIDO Alliance signing certificate.</summary>
internal sealed class TestMetadataPki : IDisposable
{
    private static readonly DateTimeOffset NotBefore = DateTimeOffset.UtcNow.AddDays(-1);
    private static readonly DateTimeOffset NotAfter = DateTimeOffset.UtcNow.AddYears(5);

    public TestMetadataPki(string hostName = MetadataBlob.SignerHostName, bool ecdsaSigner = false)
    {
        using RSA rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest("CN=Test MDS Root", rootKey, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        Root = rootRequest.CreateSelfSigned(NotBefore, NotAfter);

        using RSA caKey = RSA.Create(2048);
        var caRequest = new CertificateRequest("CN=Test MDS CA", caKey, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using X509Certificate2 caPublic = caRequest.Create(Root, NotBefore, NotAfter, [1, 2, 3, 4]);
        Intermediate = caPublic.CopyWithPrivateKey(caKey);

        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(hostName);
        if (ecdsaSigner)
        {
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest($"CN={hostName}", key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(san.Build());
            // An ECDSA certificate issued by an RSA CA needs an explicit signature generator.
            var generator = X509SignatureGenerator.CreateForRSA(caKey, RSASignaturePadding.Pkcs1);
            using X509Certificate2 signer = request.Create(Intermediate.SubjectName, generator, NotBefore, NotAfter,
                [5, 6, 7, 8]);
            Signer = signer.CopyWithPrivateKey(key);
        }
        else
        {
            using RSA key = RSA.Create(2048);
            var request = new CertificateRequest($"CN={hostName}", key, HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(san.Build());
            using X509Certificate2 signer = request.Create(Intermediate, NotBefore, NotAfter, [5, 6, 7, 8]);
            Signer = signer.CopyWithPrivateKey(key);
        }
    }

    public X509Certificate2 Root { get; }

    public X509Certificate2 Intermediate { get; }

    public X509Certificate2 Signer { get; }

    public string Sign(object payload)
    {
        bool ecdsa = Signer.GetECDsaPrivateKey() is not null;
        var header = new
        {
            alg = ecdsa ? "ES256" : "RS256",
            typ = "JWT",
            x5c = new[] { Convert.ToBase64String(Signer.RawData), Convert.ToBase64String(Intermediate.RawData) },
        };
        string signedPart = Encode(header) + "." + Encode(payload);
        byte[] data = Encoding.ASCII.GetBytes(signedPart);
        byte[] signature = ecdsa
            ? Signer.GetECDsaPrivateKey()!.SignData(data, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation)
            : Signer.GetRSAPrivateKey()!.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return signedPart + "." + Base64Url.EncodeToString(signature);
    }

    public static string Encode(object value) => Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(value));

    public static object Payload(int number, params object[] entries) =>
        new { legalHeader = "test", no = number, nextUpdate = "2030-01-01", entries };

    public static object Entry(string aaguid, string description, byte[] root, params (string Status, string Date)[] reports) =>
        new
        {
            aaguid,
            metadataStatement = new
            {
                description,
                attestationRootCertificates = new[] { Convert.ToBase64String(root) },
            },
            statusReports = reports.Select(r => new { status = r.Status, effectiveDate = r.Date }).ToArray(),
        };

    public static object U2fEntry() =>
        new
        {
            attestationCertificateKeyIdentifiers = new[] { "abcd" },
            metadataStatement = new { description = "U2F only" },
            statusReports = new[] { new { status = "FIDO_CERTIFIED", effectiveDate = "2020-01-01" } },
        };

    public void Dispose()
    {
        Root.Dispose();
        Intermediate.Dispose();
        Signer.Dispose();
    }
}

public sealed class MetadataBlobTests : IDisposable
{
    private const string Aaguid = "FA2B99DC-9E39-4257-8F92-4A30D23C4118";
    private readonly TestMetadataPki _pki = new();
    private readonly byte[] _vendorRoot = [0x30, 0x03, 0x02, 0x01, 0x01];

    public void Dispose() => _pki.Dispose();

    private object SamplePayload() => TestMetadataPki.Payload(42,
        TestMetadataPki.Entry(Aaguid, "Test Key 5", _vendorRoot,
            ("FIDO_CERTIFIED", "2020-01-01"), ("REVOKED", "2024-05-01"), ("FIDO_CERTIFIED_L1", "2021-01-01")),
        TestMetadataPki.U2fEntry());

    [Fact]
    public void ParsesAVerifiedBlob()
    {
        MetadataBlob blob = MetadataBlob.Parse(_pki.Sign(SamplePayload()), _pki.Root, DateTime.UtcNow);
        Assert.Equal(42, blob.Number);
        Assert.Equal(new DateOnly(2030, 1, 1), blob.NextUpdate);
        MetadataEntry entry = Assert.Single(blob.Entries);  // the U2F entry is skipped
        Assert.Equal(Aaguid.ToLowerInvariant(), entry.Aaguid);
        Assert.Equal("Test Key 5", entry.Description);
        Assert.Equal("REVOKED", entry.Status);  // latest effective report
        Assert.True(entry.IsBlocked);
        Assert.Equal(_vendorRoot, Assert.Single(entry.AttestationRootCertificates));
        Assert.Same(entry, blob.Find(Aaguid));
    }

    [Fact]
    public void AcceptsAnEcdsaSigner()
    {
        using var pki = new TestMetadataPki(ecdsaSigner: true);
        Assert.Equal(42, MetadataBlob.Parse(pki.Sign(SamplePayload()), pki.Root, DateTime.UtcNow).Number);
    }

    [Fact]
    public void RejectsAModifiedPayload()
    {
        string[] parts = _pki.Sign(SamplePayload()).Split('.');
        parts[1] = TestMetadataPki.Encode(TestMetadataPki.Payload(43));
        Assert.Throws<MetadataException>(() => MetadataBlob.Parse(string.Join('.', parts), _pki.Root, DateTime.UtcNow));
    }

    [Fact]
    public void RejectsAnUntrustedSigner()
    {
        using var other = new TestMetadataPki();
        var error = Assert.Throws<MetadataException>(() =>
            MetadataBlob.Parse(other.Sign(SamplePayload()), _pki.Root, DateTime.UtcNow));
        Assert.Contains("not signed by the FIDO Alliance", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsASignerForAnotherHost()
    {
        using var pki = new TestMetadataPki(hostName: "evil.example.com");
        var error = Assert.Throws<MetadataException>(() =>
            MetadataBlob.Parse(pki.Sign(SamplePayload()), pki.Root, DateTime.UtcNow));
        Assert.Contains(MetadataBlob.SignerHostName, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsGarbage()
    {
        Assert.Throws<MetadataException>(() => MetadataBlob.Parse("not a jwt", _pki.Root, DateTime.UtcNow));
        Assert.Throws<MetadataException>(() => MetadataBlob.Parse("a.b.c", _pki.Root, DateTime.UtcNow));
    }

    [Theory]
    [InlineData("{\"alg\":1}")]
    [InlineData("{\"alg\":\"RS256\",\"x5c\":[1]}")]
    [InlineData("[1]")]
    [InlineData("{\"alg\":\"RS256\",\"x5c\":\"text\"}")]
    public void ReportsHeaderFieldsOfTheWrongTypeAsMetadataErrors(string header)
    {
        // Any other exception type would escape the callers' handlers (and end the service).
        string jwt = TestMetadataPki.Encode(JsonDocument.Parse(header).RootElement) + "." +
                     TestMetadataPki.Encode(new { no = 1 }) + ".c2ln";
        Assert.Throws<MetadataException>(() => MetadataBlob.Parse(jwt, _pki.Root, DateTime.UtcNow));
    }

    /// <summary>
    /// Opt-in check against the real FIDO Metadata Service: set FIDOLOGON_TEST_MDS_BLOB to a BLOB
    /// downloaded from https://mds3.fidoalliance.org/ (the test passes trivially otherwise).
    /// </summary>
    [Fact]
    public void ParsesTheRealBlobWithTheEmbeddedAnchorWhenProvided()
    {
        string? path = Environment.GetEnvironmentVariable("FIDOLOGON_TEST_MDS_BLOB");
        if (string.IsNullOrEmpty(path))
        {
            return;
        }
        using X509Certificate2 anchor = MetadataTrustAnchor.Load();
        MetadataBlob blob = MetadataBlob.Parse(File.ReadAllText(path), anchor, DateTime.UtcNow);
        Assert.True(blob.Number > 0);
        Assert.Contains(blob.Entries, e => e.Description.Contains("YubiKey 5", StringComparison.Ordinal) &&
                                           e.AttestationRootCertificates.Count > 0);
    }

    [Fact]
    public void EmbeddedTrustAnchorIsGlobalSignRootR3()
    {
        using X509Certificate2 anchor = MetadataTrustAnchor.Load();
        Assert.Contains("GlobalSign Root CA - R3", anchor.Subject, StringComparison.Ordinal);
    }
}

[Collection(NativeCollection.Name)]
public sealed class KeyModelPolicyTests : IDisposable
{
    private const string Aaguid = "fa2b99dc-9e39-4257-8f92-4a30d23c4118";
    private const string OtherAaguid = "00000000-0000-0000-0000-000000000042";
    private readonly NativeTestEnvironment _environment = new();
    private readonly TestMetadataPki _pki = new();
    private readonly KeyModelPolicy _policy;
    private readonly byte[] _vendorRoot = [0x30, 0x03, 0x02, 0x01, 0x01];

    public KeyModelPolicyTests()
    {
        _policy = new KeyModelPolicy(_pki.Root);
    }

    public void Dispose()
    {
        _environment.Dispose();
        _pki.Dispose();
    }

    private string WriteBlob(int number, string status = "FIDO_CERTIFIED_L1", bool includeOther = true)
    {
        var entries = new List<object> { TestMetadataPki.Entry(Aaguid, "Test Key 5", _vendorRoot, (status, "2025-01-01")) };
        if (includeOther)
        {
            entries.Add(TestMetadataPki.Entry(OtherAaguid, "Compromised Key", _vendorRoot,
                ("ATTESTATION_KEY_COMPROMISE", "2025-01-01")));
        }
        string path = Path.Combine(Path.GetTempPath(), $"fidologon-blob-{Guid.NewGuid():N}.jwt");
        File.WriteAllText(path, _pki.Sign(TestMetadataPki.Payload(number, [.. entries])));
        return path;
    }

    [Fact]
    public void ModelsCanOnlyBeAllowedFromImportedMetadata()
    {
        Assert.Null(_policy.LoadMetadata());
        Assert.Throws<MetadataException>(() => _policy.Allow(Aaguid));

        MetadataImportResult result = _policy.Import(WriteBlob(10));
        Assert.Equal(10, result.Number);
        Assert.Equal(2, result.EntryCount);
        Assert.Equal(10, _policy.LoadMetadata()!.Number);

        MetadataEntry entry = _policy.Allow(Aaguid.ToUpperInvariant());
        Assert.Equal("Test Key 5", entry.Description);
        AllowedKeyModel model = Assert.Single(FidoLogonApi.ListAllowedModels());
        Assert.Equal(Aaguid, model.Aaguid);
        Assert.Equal(1, model.RootCount);
        Assert.False(model.IsBlocked);

        Assert.Throws<MetadataException>(() => _policy.Allow(OtherAaguid));  // compromised
        Assert.Throws<MetadataException>(() => _policy.Allow("11111111-1111-1111-1111-111111111111"));

        KeyModelPolicy.Remove(Aaguid);
        Assert.Empty(FidoLogonApi.ListAllowedModels());
    }

    [Fact]
    public void ImportRefreshesAllowedModelsAndRefusesOlderBlobs()
    {
        _policy.Import(WriteBlob(10));
        _policy.Allow(Aaguid);

        Assert.Throws<MetadataException>(() => _policy.Import(WriteBlob(9)));

        MetadataImportResult result = _policy.Import(WriteBlob(11, status: "REVOKED"));
        Assert.Equal([Aaguid], result.Updated);
        Assert.Equal([Aaguid], result.Blocked);
        Assert.True(Assert.Single(FidoLogonApi.ListAllowedModels()).IsBlocked);

        result = _policy.Import(WriteBlob(12, includeOther: false));
        Assert.Empty(result.Blocked);
        Assert.False(Assert.Single(FidoLogonApi.ListAllowedModels()).IsBlocked);
    }

    [Fact]
    public void EnrollmentRefusesKeysWithoutVerifiableAttestationOnceModelsAreRestricted()
    {
        _policy.Import(WriteBlob(10));
        _policy.Allow(Aaguid);

        // The simulated key returns no attestation certificate.
        var error = Assert.Throws<FidoLogonException>(() => FidoLogonApi.Enroll(DevicePath, AnyEnabledAccount(), "k",
            UnlockMode.PinAndTouch, Secret(Pin), Secret("Windows-Password")));
        Assert.Equal(FidoLogonErrorCode.AttestationRejected, error.Code);
        Assert.Empty(FidoLogonApi.ListEnrolledKeys());

        KeyModelPolicy.Remove(Aaguid);
        FidoLogonApi.Enroll(DevicePath, AnyEnabledAccount(), "k", UnlockMode.PinAndTouch, Secret(Pin),
            Secret("Windows-Password"));
        Assert.Equal("11111111-1111-1111-1111-111111111111", Assert.Single(FidoLogonApi.ListEnrolledKeys()).Aaguid);
    }

    [Fact]
    public void CliManagesModels()
    {
        var terminal = new FakeTerminal();
        var app = new FidoLogon.Cli.CliApp(terminal, models: _policy);
        Assert.Equal(0, app.Run(["models"]));
        Assert.Contains("No key model restriction: every FIDO2 key model can be enrolled.", terminal.Output);
        Assert.Contains("No FIDO Metadata Service BLOB imported.", terminal.Output);

        Assert.Equal(1, new FidoLogon.Cli.CliApp(new FakeTerminal(), models: _policy).Run(["models", "allow", Aaguid]));

        terminal = new FakeTerminal();
        Assert.Equal(0, new FidoLogon.Cli.CliApp(terminal, models: _policy).Run(["models", "import", WriteBlob(10)]));
        Assert.Contains(terminal.Output, l => l.StartsWith("Imported FIDO Metadata Service BLOB #10", StringComparison.Ordinal));

        terminal = new FakeTerminal();
        Assert.Equal(0, new FidoLogon.Cli.CliApp(terminal, models: _policy).Run(["models", "search", "key", "5"]));
        Assert.Contains(terminal.Output, l => l.StartsWith(Aaguid, StringComparison.Ordinal));
        Assert.Contains("1 model(s) found.", terminal.Output);

        Assert.Equal(0, new FidoLogon.Cli.CliApp(new FakeTerminal(), models: _policy).Run(["models", "allow", Aaguid]));
        terminal = new FakeTerminal();
        Assert.Equal(0, new FidoLogon.Cli.CliApp(terminal, models: _policy).Run(["models"]));
        Assert.Contains(terminal.Output, l => l.Contains("Test Key 5", StringComparison.Ordinal));
        Assert.Contains("Imported metadata: BLOB #10, next update 2030-01-01.", terminal.Output);

        terminal = new FakeTerminal();
        Assert.Equal(0, new FidoLogon.Cli.CliApp(terminal, models: _policy).Run(["models", "remove", Aaguid]));
        Assert.Contains("Model removed. The list is empty: every key model can be enrolled again.", terminal.Output);

        Assert.Equal(2, new FidoLogon.Cli.CliApp(new FakeTerminal(), models: _policy).Run(["models", "frobnicate"]));
        Assert.Equal(1, new FidoLogon.Cli.CliApp(new FakeTerminal(), models: _policy).Run(["models", "import", "missing.jwt"]));
    }

    private HttpClient ServeBlob(string? path, HttpStatusCode status = HttpStatusCode.OK) =>
        new(new StaticHandler(path is null ? "" : File.ReadAllText(path), status));

    [Fact]
    public async Task SyncDownloadsVerifiesAndImportsOnlyNewerBlobs()
    {
        MetadataSyncResult first = await _policy.SyncAsync(ServeBlob(WriteBlob(10)));
        Assert.False(first.UpToDate);
        Assert.Equal(10, _policy.LoadMetadata()!.Number);
        Assert.Equal(2, FidoLogonApi.CountCertifiedModels());

        MetadataSyncResult same = await _policy.SyncAsync(ServeBlob(WriteBlob(10)));
        Assert.True(same.UpToDate);
        Assert.True((await _policy.SyncAsync(ServeBlob(WriteBlob(9)))).UpToDate);

        Assert.Equal(11, (await _policy.SyncAsync(ServeBlob(WriteBlob(11)))).Number);
        Assert.False(_policy.NeedsSync(new DateOnly(2029, 12, 31)));
        Assert.True(_policy.NeedsSync(new DateOnly(2030, 1, 1)));

        // A BLOB signed by someone else, or a server error, changes nothing.
        using var other = new TestMetadataPki();
        string forged = Path.Combine(Path.GetTempPath(), $"fidologon-blob-{Guid.NewGuid():N}.jwt");
        File.WriteAllText(forged, other.Sign(TestMetadataPki.Payload(50)));
        await Assert.ThrowsAsync<MetadataException>(() => _policy.SyncAsync(ServeBlob(forged)));
        await Assert.ThrowsAsync<MetadataException>(() =>
            _policy.SyncAsync(ServeBlob(null, HttpStatusCode.ServiceUnavailable)));
        Assert.Equal(11, _policy.LoadMetadata()!.Number);
    }

    [Fact]
    public void CertifiedModelsCanBeAllowedOnceMetadataIsImported()
    {
        Assert.Throws<MetadataException>(() => _policy.SetAllowCertifiedModels(true));
        Assert.False(FidoLogonApi.AllowCertifiedModels);

        _policy.Import(WriteBlob(10));
        _policy.SetAllowCertifiedModels(true);
        Assert.True(FidoLogonApi.AllowCertifiedModels);
        Assert.Equal(2, FidoLogonApi.CountCertifiedModels());

        // The policy is now enforced: the simulated key has no verifiable attestation.
        var error = Assert.Throws<FidoLogonException>(() => FidoLogonApi.Enroll(DevicePath, AnyEnabledAccount(), "k",
            UnlockMode.PinAndTouch, Secret(Pin), Secret("Windows-Password")));
        Assert.Equal(FidoLogonErrorCode.AttestationRejected, error.Code);

        // A newer BLOB replaces the certified list.
        _policy.Import(WriteBlob(11, includeOther: false));
        Assert.Equal(1, FidoLogonApi.CountCertifiedModels());

        _policy.SetAllowCertifiedModels(false);
        FidoLogonApi.Enroll(DevicePath, AnyEnabledAccount(), "k", UnlockMode.PinAndTouch, Secret(Pin),
            Secret("Windows-Password"));
        Assert.Single(FidoLogonApi.ListEnrolledKeys());
    }

    [Fact]
    public void CliSynchronizesAndManagesCertifiedModels()
    {
        string blob = WriteBlob(10);
        FidoLogon.Cli.CliApp App(FakeTerminal terminal) => new(terminal, models: _policy, http: () => ServeBlob(blob));

        var terminal = new FakeTerminal();
        Assert.Equal(1, App(terminal).Run(["models", "certified", "on"]));  // no metadata yet

        terminal = new FakeTerminal();
        Assert.Equal(0, App(terminal).Run(["models", "sync"]));
        Assert.Contains(terminal.Output, l => l.StartsWith("Imported FIDO Metadata Service BLOB #10", StringComparison.Ordinal));
        terminal = new FakeTerminal();
        Assert.Equal(0, App(terminal).Run(["models", "sync"]));
        Assert.Contains("Already up to date: BLOB #10, next update 2030-01-01.", terminal.Output);

        terminal = new FakeTerminal();
        Assert.Equal(0, App(terminal).Run(["models", "certified", "on"]));
        Assert.Contains(terminal.Output, l => l.Contains("(2 models)", StringComparison.Ordinal));
        terminal = new FakeTerminal();
        Assert.Equal(0, App(terminal).Run(["models"]));
        Assert.Contains(terminal.Output, l => l.StartsWith("Every certified model", StringComparison.Ordinal));
        Assert.Equal(0, App(new FakeTerminal()).Run(["models", "certified", "off"]));
        Assert.False(FidoLogonApi.AllowCertifiedModels);
        Assert.Equal(2, App(new FakeTerminal()).Run(["models", "certified", "maybe"]));

        terminal = new FakeTerminal();
        Assert.Equal(0, App(terminal).Run(["config", "metadata-auto-sync", "on"]));
        Assert.True(FidoLogonApi.AutoSyncMetadata);
        terminal = new FakeTerminal();
        Assert.Equal(0, App(terminal).Run(["config"]));
        Assert.Contains("metadata-auto-sync: on", terminal.Output);
    }

    [Fact]
    public void ServiceSynchronizesOnlyWhenEnabledAndOutdated()
    {
        var log = new RecordingLog();
        int downloads = 0;
        string blob = WriteBlob(10);
        HttpClient Client()
        {
            downloads++;
            return ServeBlob(blob);
        }
        var sync = new FidoLogon.Service.MetadataAutoSync(_policy, Client, log);

        sync.CheckNow();  // turned off by default
        Assert.Equal(0, downloads);

        // Failures are logged, never thrown.
        FidoLogonApi.AutoSyncMetadata = true;
        var failing = new FidoLogon.Service.MetadataAutoSync(_policy,
            () => ServeBlob(null, HttpStatusCode.InternalServerError), log);
        failing.CheckNow();
        Assert.Contains(log.Warnings, m => m.StartsWith("FIDO Metadata Service synchronization failed", StringComparison.Ordinal));

        sync.CheckNow();
        Assert.Equal(1, downloads);
        Assert.Equal(10, _policy.LoadMetadata()!.Number);
        Assert.Contains(log.Infos, m => m.StartsWith("Downloaded FIDO Metadata Service BLOB #10", StringComparison.Ordinal));

        sync.CheckNow();  // next update in 2030: nothing to do
        Assert.Equal(1, downloads);
    }

    [Fact]
    public void InstallationModelPolicyIsAppliedOnlyOnce()
    {
        FidoLogonApi.ApplyDefaultModelPolicy(true);
        Assert.True(FidoLogonApi.AllowCertifiedModels);
        Assert.True(FidoLogonApi.AutoSyncMetadata);

        // A later choice of the administrator stays.
        FidoLogonApi.AllowCertifiedModels = false;
        FidoLogonApi.ApplyDefaultModelPolicy(true);
        Assert.False(FidoLogonApi.AllowCertifiedModels);
        Assert.True(FidoLogonApi.AutoSyncMetadata);
    }

    [Fact]
    public void CertifiedPolicyWithoutMetadataRefusesEnrollmentBeforeAnyTouch()
    {
        FidoLogonApi.ApplyDefaultModelPolicy(true);  // fresh installation, nothing downloaded yet
        int touches = 0;
        var error = Assert.Throws<FidoLogonException>(() => FidoLogonApi.Enroll(DevicePath, AnyEnabledAccount(),
            "Key", UnlockMode.PinAndTouch, Secret(Pin), Secret("Windows-Password"), (_, _) => touches++));
        Assert.Equal(FidoLogonErrorCode.AttestationRejected, error.Code);
        Assert.Contains("models sync", error.Message, StringComparison.Ordinal);
        Assert.Equal(0, touches);
        Assert.Empty(FidoLogonApi.ListEnrolledKeys());
    }

    [Fact]
    public void ImportedMetadataIsKeptInTheStoreOnly()
    {
        _policy.Import(WriteBlob(10));
        MetadataBlob stored = _policy.LoadMetadata()!;
        Assert.Equal(10, stored.Number);
        Assert.Equal("Test Key 5", Assert.Single(stored.Entries, e => e.Aaguid == Aaguid).Description);
        Assert.False(_policy.NeedsSync(new DateOnly(2026, 1, 1)));
    }

    private sealed class StaticHandler(string body, HttpStatusCode status) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Assert.Equal(KeyModelPolicy.MetadataServiceUrl, request.RequestUri!.ToString());
            return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body) });
        }
    }

    private sealed class RecordingLog : FidoLogon.Service.IServiceLog
    {
        public List<string> Infos { get; } = [];

        public List<string> Warnings { get; } = [];

        public void Info(string message) => Infos.Add(message);

        public void Warning(string message) => Warnings.Add(message);
    }
}
