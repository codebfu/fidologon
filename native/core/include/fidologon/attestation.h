#pragma once

#include <string>
#include <vector>

#include "fidologon/authenticator.h"
#include "fidologon/record_store.h"

namespace fidologon {

// X.509 extension holding the AAGUID in FIDO attestation certificates (id-fido-gen-ce-aaguid).
inline constexpr char kAaguidExtensionOid[] = "1.3.6.1.4.1.45724.1.1.4";

// Lower-case 8-4-4-4-12 form; empty when the value is not 16 bytes.
std::wstring FormatAaguid(const Bytes& aaguid);

// FIDO Metadata Service statuses that make a model unacceptable (compromised or revoked).
bool IsBlockedStatus(const std::wstring& status);

// Checks a new credential's attestation against the administrator's allowed models, whose root
// certificates come from the FIDO Metadata Service. Throws AttestationRejected unless:
// - the AAGUID is in the list and its status is not blocked;
// - the attestation has a certificate chain and its signature was verified by the authenticator layer;
// - the leaf certificate's AAGUID extension, when present, matches the credential's AAGUID;
// - the chain leads to one of that model's root certificates (revocation and expiry not checked:
//   the computer is offline by design and attestation certificates are long-lived).
void CheckAttestation(const CredentialResult& credential, const std::vector<AllowedModel>& models);

}  // namespace fidologon
