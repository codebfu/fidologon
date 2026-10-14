# Code signing

Release binaries (`.dll`, `.exe`) and the MSI are Authenticode-signed (SHA-256, RFC 3161
timestamp) by the release workflow with a **self-signed** certificate.

Windows does not trust a self-signed certificate by default, so a signed release still triggers
SmartScreen and Smart App Control warnings and may be flagged by antivirus or EDR products unless
the certificate is trusted on the machine.

## Trusting the certificate

The public certificate is `certs/FidoLogon-CodeSigning.cer` (also attached to every release).
Check its thumbprint against a trusted source, then on each machine, as administrator:

```powershell
./scripts/trust-certificate.ps1 -CertificatePath FidoLogon-CodeSigning.cer
```

This imports it into *Trusted Root Certification Authorities* and *Trusted Publishers* of the local
machine. For several machines, the same can be done with a Group Policy or Intune certificate profile.

Only do this if you trust whoever holds the private key: a trusted root certificate can sign any code.

The installer can do the same: tick *Trust the FidoLogon code-signing certificate* on its options
page, or pass `TRUST_CERTIFICATE=1` to `msiexec`. It is off by default, skipped when the
certificate is already trusted (machine store, Group Policy or Intune), and the certificate is
removed again when FidoLogon is uninstalled.

## Private key and GitHub secrets

`scripts/new-signing-certificate.ps1` creates the certificate:

- `.secrets/FidoLogon-CodeSigning.pfx` and `.secrets/FidoLogon-CodeSigning.password.txt`
  (git-ignored): **back them up somewhere safe** (password manager, encrypted storage).
- `certs/FidoLogon-CodeSigning.cer`: public part, committed.
- With `-GitHubRepository owner/repo`, the secrets `SIGNING_CERT_PFX_BASE64` and
  `SIGNING_CERT_PASSWORD` of the repository's `release-signing` GitHub Actions environment.

## Release pipeline

The `build` workflow (`.github/workflows/build.yml`) keeps the signing key away from the build:

- The `build` job compiles, tests and packages **unsigned**, with the vcpkg binary cache. It never
  receives the signing secrets.
- For `v*.*.*` tags only, the `sign` job downloads the staged files, signs them, builds and signs the
  MSI (`scripts/package.ps1`). It builds no code and restores no cache. It runs in the
  `release-signing` environment, which holds the two secrets, accepts only `v*.*.*` tags and waits
  for a reviewer's approval.
- `scripts/import-signing-certificate.ps1` imports the PFX from memory into the runner's
  `Cert:\CurrentUser\My` store with a non-exportable key; `signtool` then selects it by thumbprint
  (`/sha1`), so neither the key file nor its password appears on a command line. The certificate is
  removed at the end of the job.
- Every action is pinned by commit SHA; Dependabot (`.github/dependabot.yml`) proposes updates.

Secrets are not exposed to pull requests.

### Setting up the environment

`new-signing-certificate.ps1 -GitHubRepository` stores the secrets in the environment. To create it
by hand: *Settings → Environments → New environment* `release-signing`, add yourself as *Required
reviewer*, set *Deployment branches and tags* to *Selected* with the tag rule `v*.*.*`, then add the
secrets `SIGNING_CERT_PFX_BASE64` and `SIGNING_CERT_PASSWORD` to it (not to the repository).

## Signing locally

```powershell
$thumbprint = ./scripts/import-signing-certificate.ps1 -PfxPath .secrets/FidoLogon-CodeSigning.pfx `
    -PasswordPath .secrets/FidoLogon-CodeSigning.password.txt
./scripts/build.ps1 -Version 1.2.3 -CertificateThumbprint $thumbprint
./scripts/import-signing-certificate.ps1 -RemoveThumbprint $thumbprint
```

## Renewing

The certificate is valid 5 years. Timestamped signatures stay valid after it expires. To renew, run
`./scripts/new-signing-certificate.ps1 -Force -GitHubRepository codebfu/fidologon`, commit the new
`.cer` and redistribute it to the machines.

## Moving to a public certificate

To avoid warnings everywhere, use a certificate from a public CA or Azure Trusted Signing: replace
the PFX secrets (or adapt `scripts/import-signing-certificate.ps1` and `scripts/sign-files.ps1`);
nothing else changes.
