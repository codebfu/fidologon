#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>

#include <memory>

#include "fidologon/attestation.h"
#include "fidologon/crypto.h"
#include "fidologon/enrollment.h"
#include "fidologon/errors.h"
#include "fidologon/fake_authenticator.h"
#include "test_framework.h"

#pragma comment(lib, "ncrypt.lib")

using namespace fidologon;

namespace {

constexpr wchar_t kAaguid[] = L"fa2b99dc-9e39-4257-8f92-4a30d23c4118";
const Bytes kAaguidBytes = {0xfa, 0x2b, 0x99, 0xdc, 0x9e, 0x39, 0x42, 0x57,
                            0x8f, 0x92, 0x4a, 0x30, 0xd2, 0x3c, 0x41, 0x18};

// Ephemeral ECDSA P-256 key used to issue test certificates.
class TestKey {
public:
    TestKey() {
        NCRYPT_PROV_HANDLE provider = 0;
        CHECK(NCryptOpenStorageProvider(&provider, MS_KEY_STORAGE_PROVIDER, 0) == ERROR_SUCCESS);
        CHECK(NCryptCreatePersistedKey(provider, &key_, NCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0, 0) == ERROR_SUCCESS);
        CHECK(NCryptFinalizeKey(key_, 0) == ERROR_SUCCESS);
        NCryptFreeObject(provider);
    }
    ~TestKey() { NCryptFreeObject(key_); }
    TestKey(const TestKey&) = delete;
    TestKey& operator=(const TestKey&) = delete;

    NCRYPT_KEY_HANDLE get() const { return key_; }

private:
    NCRYPT_KEY_HANDLE key_ = 0;
};

Bytes EncodeName(const wchar_t* x500) {
    DWORD size = 0;
    CHECK(CertStrToNameW(X509_ASN_ENCODING, x500, CERT_X500_NAME_STR, nullptr, nullptr, &size, nullptr));
    Bytes name(size);
    CHECK(CertStrToNameW(X509_ASN_ENCODING, x500, CERT_X500_NAME_STR, nullptr, name.data(), &size, nullptr));
    name.resize(size);
    return name;
}

Bytes Encode(LPCSTR structType, const void* value) {
    DWORD size = 0;
    CHECK(CryptEncodeObjectEx(X509_ASN_ENCODING, structType, value, 0, nullptr, nullptr, &size));
    Bytes encoded(size);
    CHECK(CryptEncodeObjectEx(X509_ASN_ENCODING, structType, value, 0, nullptr, encoded.data(), &size));
    encoded.resize(size);
    return encoded;
}

// Issues a certificate for subjectKey signed by issuerKey. aaguidExtension adds id-fido-gen-ce-aaguid.
Bytes IssueCertificate(const TestKey& issuerKey, const Bytes& issuerName, const TestKey& subjectKey,
                       const Bytes& subjectName, bool ca, const Bytes* aaguidExtension = nullptr) {
    DWORD size = 0;
    CHECK(CryptExportPublicKeyInfo(subjectKey.get(), 0, X509_ASN_ENCODING, nullptr, &size));
    Bytes publicKey(size);
    CHECK(CryptExportPublicKeyInfo(subjectKey.get(), 0, X509_ASN_ENCODING,
                                   reinterpret_cast<CERT_PUBLIC_KEY_INFO*>(publicKey.data()), &size));

    Bytes serial = crypto::RandomBytes(8);
    serial.back() &= 0x7F;  // positive INTEGER (little-endian blob)
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER start{now.dwLowDateTime, now.dwHighDateTime};
    ULARGE_INTEGER end = start;
    start.QuadPart -= 864000000000ULL;          // 1 day
    end.QuadPart += 10ULL * 365 * 864000000000ULL;  // 10 years

    CERT_BASIC_CONSTRAINTS2_INFO basic{ca ? TRUE : FALSE, FALSE, 0};
    Bytes basicEncoded = Encode(X509_BASIC_CONSTRAINTS2, &basic);
    std::vector<CERT_EXTENSION> extensions;
    extensions.push_back(CERT_EXTENSION{const_cast<LPSTR>(szOID_BASIC_CONSTRAINTS2), TRUE,
                                        {static_cast<DWORD>(basicEncoded.size()), basicEncoded.data()}});
    Bytes aaguidValue;
    if (aaguidExtension != nullptr) {
        aaguidValue = {0x04, 0x10};
        aaguidValue.insert(aaguidValue.end(), aaguidExtension->begin(), aaguidExtension->end());
        extensions.push_back(CERT_EXTENSION{const_cast<LPSTR>(kAaguidExtensionOid), FALSE,
                                            {static_cast<DWORD>(aaguidValue.size()), aaguidValue.data()}});
    }

    CERT_INFO info{};
    info.dwVersion = CERT_V3;
    info.SerialNumber = {static_cast<DWORD>(serial.size()), serial.data()};
    info.SignatureAlgorithm.pszObjId = const_cast<LPSTR>(szOID_ECDSA_SHA256);
    info.Issuer = {static_cast<DWORD>(issuerName.size()), const_cast<BYTE*>(issuerName.data())};
    info.Subject = {static_cast<DWORD>(subjectName.size()), const_cast<BYTE*>(subjectName.data())};
    info.NotBefore = {start.LowPart, start.HighPart};
    info.NotAfter = {end.LowPart, end.HighPart};
    info.SubjectPublicKeyInfo = *reinterpret_cast<CERT_PUBLIC_KEY_INFO*>(publicKey.data());
    info.cExtension = static_cast<DWORD>(extensions.size());
    info.rgExtension = extensions.data();

    CRYPT_ALGORITHM_IDENTIFIER algorithm{const_cast<LPSTR>(szOID_ECDSA_SHA256), {}};
    size = 0;
    CHECK(CryptSignAndEncodeCertificate(issuerKey.get(), 0, X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, &info,
                                        &algorithm, nullptr, nullptr, &size));
    Bytes certificate(size);
    CHECK(CryptSignAndEncodeCertificate(issuerKey.get(), 0, X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, &info,
                                        &algorithm, nullptr, certificate.data(), &size));
    certificate.resize(size);
    return certificate;
}

struct Pki {
    TestKey rootKey;
    TestKey intermediateKey;
    TestKey leafKey;
    Bytes rootName = EncodeName(L"CN=Test Vendor Root");
    Bytes intermediateName = EncodeName(L"CN=Test Vendor Attestation CA");
    Bytes root = IssueCertificate(rootKey, rootName, rootKey, rootName, true);
    Bytes intermediate = IssueCertificate(rootKey, rootName, intermediateKey, intermediateName, true);
    Bytes leaf = IssueCertificate(intermediateKey, intermediateName, leafKey, EncodeName(L"CN=Test Key"), false,
                                  &kAaguidBytes);
};

CredentialResult Attested(const Pki& pki) {
    CredentialResult result;
    result.credentialId = Bytes{1, 2, 3};
    result.aaguid = kAaguidBytes;
    result.attestationFormat = "packed";
    result.attestationCertificates = {pki.leaf, pki.intermediate};
    result.attestationSignatureValid = true;
    return result;
}

std::vector<AllowedModel> Allow(const Bytes& root, const std::wstring& status = L"FIDO_CERTIFIED_L1") {
    return {AllowedModel{kAaguid, L"Test key", status, {root}}};
}

}  // namespace

TEST(AaguidIsFormattedLikeTheMetadataService) {
    CHECK(FormatAaguid(kAaguidBytes) == kAaguid);
    CHECK(FormatAaguid(Bytes{1, 2}).empty());
    CHECK(IsBlockedStatus(L"REVOKED"));
    CHECK(IsBlockedStatus(L"attestation_key_compromise"));
    CHECK(!IsBlockedStatus(L"FIDO_CERTIFIED_L2"));
}

TEST(AttestationChainingToAnAllowedRootIsAccepted) {
    const Pki pki;
    CheckAttestation(Attested(pki), Allow(pki.root));
    CheckAttestation(Attested(pki), Allow(pki.intermediate));  // MDS anchors may be intermediate CAs

    CredentialResult leafOnly = Attested(pki);
    leafOnly.attestationCertificates = {pki.leaf};
    CheckAttestation(leafOnly, Allow(pki.intermediate));
}

TEST(AttestationIsRejectedForEveryBrokenLink) {
    const Pki pki;
    const Pki other;

    CHECK_THROWS_CODE(CheckAttestation(Attested(pki), Allow(other.root)), ErrorCode::AttestationRejected);
    CHECK_THROWS_CODE(CheckAttestation(Attested(pki), Allow(pki.root, L"REVOKED")), ErrorCode::AttestationRejected);

    std::vector<AllowedModel> otherModel = Allow(pki.root);
    otherModel[0].aaguid = L"00000000-0000-0000-0000-000000000001";
    CHECK_THROWS_CODE(CheckAttestation(Attested(pki), otherModel), ErrorCode::AttestationRejected);

    CredentialResult unsigned_ = Attested(pki);
    unsigned_.attestationSignatureValid = false;
    CHECK_THROWS_CODE(CheckAttestation(unsigned_, Allow(pki.root)), ErrorCode::AttestationRejected);

    CredentialResult self = Attested(pki);
    self.attestationCertificates.clear();
    CHECK_THROWS_CODE(CheckAttestation(self, Allow(pki.root)), ErrorCode::AttestationRejected);

    CredentialResult missingIntermediate = Attested(pki);
    missingIntermediate.attestationCertificates = {pki.leaf};
    CHECK_THROWS_CODE(CheckAttestation(missingIntermediate, Allow(pki.root)), ErrorCode::AttestationRejected);

    // A genuine certificate of another model of the same vendor cannot claim this AAGUID.
    const Bytes otherAaguid(16, 0x42);
    CredentialResult swapped = Attested(pki);
    swapped.attestationCertificates[0] = IssueCertificate(pki.intermediateKey, pki.intermediateName, pki.leafKey,
                                                          EncodeName(L"CN=Other Key"), false, &otherAaguid);
    CHECK_THROWS_CODE(CheckAttestation(swapped, Allow(pki.root)), ErrorCode::AttestationRejected);
}

TEST(AllowedModelsRoundTripInTheStore) {
    RecordStore store = RecordStore::OpenDefault();
    CHECK(store.ListAllowedModels().empty());
    store.SaveAllowedModel(AllowedModel{L"FA2B99DC-9E39-4257-8F92-4A30D23C4118", L"Test key", L"FIDO_CERTIFIED",
                                        {Bytes{1, 2, 3}, Bytes{4, 5}}});
    auto models = store.ListAllowedModels();
    CHECK_EQ(models.size(), 1u);
    CHECK(models[0].aaguid == kAaguid);  // stored lower-case
    CHECK_EQ(models[0].rootCertificates.size(), 2u);
    CHECK(models[0].rootCertificates[1] == (Bytes{4, 5}));

    store.SaveAllowedModel(AllowedModel{kAaguid, L"Test key", L"REVOKED", {Bytes{9}}});  // replaced, old roots gone
    models = store.ListAllowedModels();
    CHECK_EQ(models[0].rootCertificates.size(), 1u);
    CHECK(models[0].status == L"REVOKED");

    CHECK_THROWS_CODE(store.SaveAllowedModel(AllowedModel{L"not-a-guid", L"", L"", {Bytes{1}}}),
                      ErrorCode::InvalidArgument);
    CHECK_THROWS_CODE(store.SaveAllowedModel(AllowedModel{kAaguid, L"", L"", {}}), ErrorCode::InvalidArgument);
    CHECK(store.RemoveAllowedModel(kAaguid));
    CHECK(!store.RemoveAllowedModel(kAaguid));
}

TEST(EnrollmentEnforcesTheAllowedModels) {
    const Pki pki;
    auto fakeOwner = std::make_shared<FakeAuthenticator>();
    FakeAuthenticator& fake = *fakeOwner;
    ReplaceAuthenticatorForTests(fakeOwner);
    fake.PlugDevice(L"dev", L"1234");
    RecordStore store = RecordStore::OpenDefault();

    EnrollRequest request;
    request.devicePath = L"dev";
    request.userSid = L"S-1-5-21-1-1001";
    request.userName = L"alice";
    request.requirePin = true;
    request.pin = L"1234";
    request.password = L"WindowsPassword!";

    // No allowed model: any key is accepted and its model is recorded.
    fake.SetAttestation(L"dev", kAaguidBytes, {}, false);
    Enroll(request, store);
    CHECK(store.List().at(0).aaguid == kAaguid);

    // With an allow-list, a key without verifiable attestation is refused and nothing is stored.
    store.SaveAllowedModel(Allow(pki.root)[0]);
    CHECK_THROWS_CODE(Enroll(request, store), ErrorCode::AttestationRejected);
    CHECK_EQ(store.List().size(), 1u);

    // A key whose attestation chains to the allowed model's root is accepted.
    fake.SetAttestation(L"dev", kAaguidBytes, {pki.leaf, pki.intermediate}, true);
    Enroll(request, store);
    CHECK_EQ(store.List().size(), 2u);

    // Another model, even well attested by its own vendor, is refused.
    const Pki other;
    fake.SetAttestation(L"dev", Bytes(16, 0x42), {other.leaf, other.intermediate}, true);
    CHECK_THROWS_CODE(Enroll(request, store), ErrorCode::AttestationRejected);
    CHECK_EQ(store.List().size(), 2u);
}

TEST(CertifiedModelsAreReplacedAsAWhole) {
    RecordStore store = RecordStore::OpenDefault();
    CHECK(store.ListCertifiedModels().empty());
    CHECK(!store.AllowCertifiedModels());
    store.ReplaceCertifiedModels({AllowedModel{kAaguid, L"Test key", L"FIDO_CERTIFIED", {Bytes{1}}},
                                  AllowedModel{L"00000000-0000-0000-0000-000000000042", L"Other", L"", {Bytes{2}}}});
    CHECK_EQ(store.ListCertifiedModels().size(), 2u);
    store.ReplaceCertifiedModels({AllowedModel{kAaguid, L"Test key", L"REVOKED", {Bytes{3}}}});
    auto models = store.ListCertifiedModels();
    CHECK_EQ(models.size(), 1u);
    CHECK(models[0].status == L"REVOKED");
    CHECK(models[0].rootCertificates[0] == (Bytes{3}));
    // An invalid entry leaves the current list untouched.
    CHECK_THROWS_CODE(store.ReplaceCertifiedModels({AllowedModel{kAaguid, L"", L"", {}}}), ErrorCode::InvalidArgument);
    CHECK_EQ(store.ListCertifiedModels().size(), 1u);
    store.ReplaceCertifiedModels({});
    CHECK(store.ListCertifiedModels().empty());

    CHECK(!store.AutoSyncMetadata());
    store.SetAutoSyncMetadata(true);
    CHECK(store.AutoSyncMetadata());
}

TEST(EnrollmentAcceptsCertifiedModelsWhenAllowed) {
    const Pki pki;
    auto fakeOwner = std::make_shared<FakeAuthenticator>();
    FakeAuthenticator& fake = *fakeOwner;
    ReplaceAuthenticatorForTests(fakeOwner);
    fake.PlugDevice(L"dev", L"1234");
    RecordStore store = RecordStore::OpenDefault();

    EnrollRequest request;
    request.devicePath = L"dev";
    request.userSid = L"S-1-5-21-1-1001";
    request.userName = L"alice";
    request.requirePin = true;
    request.pin = L"1234";
    request.password = L"WindowsPassword!";
    fake.SetAttestation(L"dev", kAaguidBytes, {pki.leaf, pki.intermediate}, true);

    // Certified models allowed but none imported yet: every key is refused.
    store.SetAllowCertifiedModels(true);
    CHECK_THROWS_CODE(Enroll(request, store), ErrorCode::AttestationRejected);

    // The key's model is in the certified list: accepted, attestation still checked.
    store.ReplaceCertifiedModels(Allow(pki.root));
    Enroll(request, store);
    CHECK_EQ(store.List().size(), 1u);
    fake.SetAttestation(L"dev", kAaguidBytes, {}, false);
    CHECK_THROWS_CODE(Enroll(request, store), ErrorCode::AttestationRejected);

    // A revoked certified model is refused.
    fake.SetAttestation(L"dev", kAaguidBytes, {pki.leaf, pki.intermediate}, true);
    store.ReplaceCertifiedModels(Allow(pki.root, L"REVOKED"));
    CHECK_THROWS_CODE(Enroll(request, store), ErrorCode::AttestationRejected);

    // Turned off: the certified list no longer counts (and an empty allowed list accepts any key).
    store.SetAllowCertifiedModels(false);
    Enroll(request, store);
    CHECK_EQ(store.List().size(), 2u);
}
