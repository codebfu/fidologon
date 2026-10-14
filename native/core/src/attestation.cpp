#include "fidologon/attestation.h"

#include <windows.h>
#include <wincrypt.h>

#include <algorithm>
#include <cstring>
#include <cwctype>
#include <memory>

#include "fidologon/errors.h"

namespace fidologon {
namespace {

struct StoreCloser {
    void operator()(void* store) const { CertCloseStore(static_cast<HCERTSTORE>(store), 0); }
};
using StorePtr = std::unique_ptr<void, StoreCloser>;

struct CertFreer {
    void operator()(const CERT_CONTEXT* cert) const { CertFreeCertificateContext(cert); }
};
using CertPtr = std::unique_ptr<const CERT_CONTEXT, CertFreer>;

struct ChainFreer {
    void operator()(const CERT_CHAIN_CONTEXT* chain) const { CertFreeCertificateChain(chain); }
};
using ChainPtr = std::unique_ptr<const CERT_CHAIN_CONTEXT, ChainFreer>;

struct EngineFreer {
    void operator()(HCERTCHAINENGINE engine) const { CertFreeCertificateChainEngine(engine); }
};
using EnginePtr = std::unique_ptr<std::remove_pointer_t<HCERTCHAINENGINE>, EngineFreer>;

[[noreturn]] void Reject(const std::string& reason) { throw Error(ErrorCode::AttestationRejected, reason); }

StorePtr NewMemoryStore() {
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
    if (store == nullptr) {
        throw Error(ErrorCode::Internal, "CertOpenStore failed");
    }
    return StorePtr(store);
}

void AddToStore(HCERTSTORE store, const Bytes& der) {
    if (!CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING, der.data(), static_cast<DWORD>(der.size()),
                                          CERT_STORE_ADD_ALWAYS, nullptr)) {
        Reject("invalid certificate");
    }
}

std::string Narrow(const std::wstring& value) { return ToUtf8(value); }

bool SameAaguid(const std::wstring& left, const std::wstring& right) {
    return _wcsicmp(left.c_str(), right.c_str()) == 0;
}

void CheckAaguidExtension(const CERT_CONTEXT* leaf, const Bytes& aaguid) {
    const CERT_EXTENSION* extension =
        CertFindExtension(kAaguidExtensionOid, leaf->pCertInfo->cExtension, leaf->pCertInfo->rgExtension);
    if (extension == nullptr) {
        return;  // optional for certificates shared by several models
    }
    // The extension value is an OCTET STRING holding the 16-byte AAGUID.
    const CRYPT_OBJID_BLOB& value = extension->Value;
    if (value.cbData != 18 || value.pbData[0] != 0x04 || value.pbData[1] != 0x10 ||
        std::memcmp(value.pbData + 2, aaguid.data(), 16) != 0) {
        Reject("the attestation certificate belongs to another key model");
    }
}

bool ChainsToRoots(const CredentialResult& credential, const AllowedModel& model) {
    CertPtr leaf(CertCreateCertificateContext(X509_ASN_ENCODING, credential.attestationCertificates.front().data(),
                                              static_cast<DWORD>(credential.attestationCertificates.front().size())));
    if (!leaf) {
        Reject("invalid attestation certificate");
    }
    CheckAaguidExtension(leaf.get(), credential.aaguid);
    for (const Bytes& root : model.rootCertificates) {
        if (root == credential.attestationCertificates.front()) {
            return true;  // the attestation certificate itself is the published trust anchor
        }
    }

    StorePtr roots = NewMemoryStore();
    for (const Bytes& root : model.rootCertificates) {
        AddToStore(roots.get(), root);
    }
    StorePtr intermediates = NewMemoryStore();
    for (std::size_t i = 1; i < credential.attestationCertificates.size(); ++i) {
        AddToStore(intermediates.get(), credential.attestationCertificates[i]);
    }

    // Only the model's roots are trusted (not the machine's root store); MDS anchors may be
    // intermediate CAs, hence CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG.
    CERT_CHAIN_ENGINE_CONFIG config{};
    config.cbSize = sizeof(config);
    config.hExclusiveRoot = roots.get();
    config.dwExclusiveFlags = CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG;
    HCERTCHAINENGINE rawEngine = nullptr;
    if (!CertCreateCertificateChainEngine(&config, &rawEngine)) {
        throw Error(ErrorCode::Internal, "CertCreateCertificateChainEngine failed");
    }
    EnginePtr engine(rawEngine);

    CERT_CHAIN_PARA para{};
    para.cbSize = sizeof(para);
    const CERT_CHAIN_CONTEXT* rawChain = nullptr;
    if (!CertGetCertificateChain(engine.get(), leaf.get(), nullptr, intermediates.get(), &para,
                                 CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE | CERT_CHAIN_DISABLE_AIA, nullptr,
                                 &rawChain)) {
        return false;
    }
    ChainPtr chain(rawChain);
    constexpr DWORD kIgnored = CERT_TRUST_IS_NOT_TIME_VALID | CERT_TRUST_IS_NOT_TIME_NESTED |
                               CERT_TRUST_CTL_IS_NOT_TIME_VALID | CERT_TRUST_REVOCATION_STATUS_UNKNOWN |
                               CERT_TRUST_IS_OFFLINE_REVOCATION;
    return (chain->TrustStatus.dwErrorStatus & ~kIgnored) == CERT_TRUST_NO_ERROR;
}

}  // namespace

std::wstring FormatAaguid(const Bytes& aaguid) {
    if (aaguid.size() != 16) {
        return {};
    }
    static constexpr wchar_t kHex[] = L"0123456789abcdef";
    std::wstring text;
    for (std::size_t i = 0; i < aaguid.size(); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            text.push_back(L'-');
        }
        text.push_back(kHex[aaguid[i] >> 4]);
        text.push_back(kHex[aaguid[i] & 0x0F]);
    }
    return text;
}

bool IsBlockedStatus(const std::wstring& status) {
    static constexpr const wchar_t* kBlocked[] = {
        L"REVOKED",
        L"USER_VERIFICATION_BYPASS",
        L"ATTESTATION_KEY_COMPROMISE",
        L"USER_KEY_REMOTE_COMPROMISE",
        L"USER_KEY_PHYSICAL_COMPROMISE",
    };
    return std::any_of(std::begin(kBlocked), std::end(kBlocked),
                       [&](const wchar_t* blocked) { return _wcsicmp(blocked, status.c_str()) == 0; });
}

void CheckAttestation(const CredentialResult& credential, const std::vector<AllowedModel>& models) {
    const std::wstring aaguid = FormatAaguid(credential.aaguid);
    const auto model = std::find_if(models.begin(), models.end(),
                                     [&](const AllowedModel& m) { return SameAaguid(m.aaguid, aaguid); });
    if (aaguid.empty() || model == models.end()) {
        Reject("key model " + Narrow(aaguid.empty() ? L"(unknown)" : aaguid) +
               " is not allowed (not in the allowed list, nor a FIDO certified model when those are allowed)");
    }
    if (IsBlockedStatus(model->status)) {
        Reject("key model " + Narrow(aaguid) + " has FIDO Metadata Service status " + Narrow(model->status));
    }
    if (credential.attestationCertificates.empty() || !credential.attestationSignatureValid) {
        Reject("the key returned no verifiable attestation (format '" + credential.attestationFormat + "')");
    }
    if (!ChainsToRoots(credential, *model)) {
        Reject("the attestation certificate does not chain to a root published for key model " + Narrow(aaguid));
    }
}

}  // namespace fidologon
