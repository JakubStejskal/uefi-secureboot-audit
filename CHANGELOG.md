# Changelog

## [Unreleased]

### Fixed — certificate inventory (v2.1)

- **`CertInventory = NOT_REPORTED` on every iLO 6 / iLO 7 host.** URIs were built by string
  concatenation from `@odata.id` values that end with `/`, producing
  `/redfish/v1/Systems/1//SecureBoot/SecureBootDatabases`; the rejection was swallowed as a
  404. Both HPE scripts now follow the `@odata.id` links iLO returns (`SecureBoot`,
  `SecureBootDatabases`, `Certificates`, `#SecureBoot.ResetKeys` target) and join paths with
  exactly one `/`.
- **Database ID parsed as empty string.** `'.../SecureBootDatabases/db/' -split '/'` ends
  in `''`, so every live database would have been skipped even with a correct URI. The ID
  now comes from `DatabaseId`, falling back to the trimmed last path segment.
- **Gen12 reported `COMPLIANT` without reading any certificate.** Gen12 is now evaluated
  from the live databases like Gen11; if they cannot be read the verdict is `UNVERIFIED`.
- **2023 certificates matched in any database.** A CA present only in `dbx` (revoked)
  counted as present. KEK 2023 is now required in `KEK` and the three CAs in `db`.
- **`-ILOHost https://10.0.0.5/` failed with `ERROR`.** Scheme, path and trailing slash are
  stripped; duplicates are removed.
- **Windows PowerShell 5.1: every request failed with "The underlying connection was closed:
  An unexpected error occurred on a send"** when `-SkipCertificateCheck` was used. The TLS
  bypass was a scriptblock (`{ $true }`), which cannot run on a handshake thread without a
  PowerShell runspace ("There is no Runspace available to run scripts in this thread"). Both
  HPE scripts now install a compiled `RemoteCertificateValidationCallback`. Reproduced on
  5.1.26100 against the mock iLO; PowerShell 7 was never affected (per-call
  `-SkipCertificateCheck`).

### Documentation

- README: quick start (requirements, path through the tooling), verdict → next-step table, audit
  output column reference, remediation checklist (recovery key, maintenance mode, `-WhatIf`,
  what `BLOCKED` means, where the key backup is written, that reboots are manual).
- Status line, timeline and rollout step 8 updated: `Microsoft Windows Production PCA 2011`
  expired on 2026-10-19.
- Runbook: manual read-only spot-check of the live databases.

### CI

- `actions/checkout` v4 → v7 (Node 24), runner pinned to `ubuntu-24.04`, `Install-Module`
  retried up to three times (PSGallery intermittently answers "No match was found").

### Added

- Audit columns: `SecureBootActive`, `CertInventoryNote`, `DbCounts`, `Has_PK`,
  `Has_VMwareDbCert`, `Legacy2011InDb`, `Legacy2011InKEK`, `Revoked2011InDbx`, `Missing2023`.
- Verdicts `CERTS_OK_SECUREBOOT_OFF` (certificates complete, Secure Boot not enforcing) and
  `UNVERIFIED` (Gen12, inventory unreadable). Inventory status `PARTIAL`.
- The summary now prints the reason for every non-compliant host; `Error` was previously
  hidden by the usual `Format-Table` column selection.
- Remediation preflight blocks `ResetKeys` when the live KEK and db already hold all four
  2023 certificates (overridable with `-Force`). `EnableSecureBoot` warns when no PK is
  enrolled. `Verify` checks each certificate in its own database and reports whether Secure
  Boot is enforcing. `-WhatIf` no longer claims the key backup was written.
- `tests/mock-ilo/`: HTTPS Redfish mock reproducing iLO link formatting (trailing `/`,
  `//` -> 404) with seven scenarios, used to regression-test both HPE scripts.

### Changed

- **Servers with iLO 5 (Gen10 / Gen10 Plus) are out of scope.** In practice they cannot be
  audited or remediated remotely: iLO 5 has no certificate inventory, and its only remote
  reset (`ResetAllKeysToDefault`) wipes every key and disables Secure Boot. The audit script
  reports them as `OUT_OF_SCOPE`; the remediation script refuses them (not overridable with
  `-Force`). ROM baselines for these generations were removed from both scripts.
- Removed iLO 5 rows from `examples/fleet.csv` and the legacy `list-ilo5-uefi-certs.py`
  (its premise, `SecureBootDatabases` on iLO 5, does not hold).

### Fixed

- `HPE-SecureBootRemediate.ps1`: the key-backup folder name is now sanitised, so an iLO
  address containing `:` (port or IPv6) no longer breaks the backup on Windows.

### Added

- Runbook section with a manual, field-tested RBSU procedure for iLO 5 servers: export keys
  to USB/SD, reset **only `db`** to platform defaults, re-enrol custom entries. Marked as
  not HPE-documented; the advisory prescribes only the all-keys reset.
- Note that Gen11 is listed as "reset required" per the advisory, while some hosts were
  observed to need no manual step; verify by reading the live `db`.

## [2.0.0] — 2026-08-04

Rewrite around HPE Customer Advisory a00156355en_us rev. 5 (2026-07-02) and Broadcom's
revised VM guidance. Documentation is now in English; the original Czech README is kept
at `legacy/README.cs.md`.

### Corrected

- **iLO 5 never exposes `SecureBootDatabases`.** The previous documentation stated it was
  available "only with a sufficiently new ROM". It is absent from the iLO 5 Redfish
  resource map for every firmware release including v3.19, and from the entire iLO 5
  changelog and API reference. It was introduced in iLO 6 v1.10. On Gen10 and Gen10 Plus
  certificate state cannot be read out-of-band at all.
- **Minimum System ROM versions raised.** Gen10 was listed as `3.40_01-16-2025`; the
  advisory requires **3.62** (Intel) / **3.70** (AMD), with **3.72** for DL20 Gen10,
  ML30 Gen10 and m750. Gen10 Plus AMD requires **3.50** and Gen11 AMD **2.30** — neither
  was previously listed.
- **Four certificates, not two.** The single 2011 third-party CA was replaced by two 2023
  CAs. `Microsoft Option ROM UEFI CA 2023` is separate from `Microsoft UEFI CA 2023` and
  is the one most often missing, since it landed in vendor firmware later.
- **The VMware PK is not expired — it is `VMW.NULLPK`**, a placeholder with a NULL
  signature and therefore no expiry date. The expired "VMware Certificate" (Dec 2019)
  sits in `db` and is inert.
- **Deleting or renaming `.nvram` is not supported.** Broadcom withdrew that guidance;
  KB 423919 replaced KB 421593 explicitly to remove it. On a vTPM VM it destroys the
  vTPM state.

### Added

- `scripts/HPE-SecureBootAudit.ps1` — read-only fleet audit across Gen10 → Gen12 with
  graceful degradation on iLO 5, reporting `ROM_OK_CERTS_UNKNOWN` rather than claiming
  unprovable compliance. CSV/JSON export, local PEM parsing fallback.
- `scripts/HPE-SecureBootRemediate.ps1` — staged remediation (`ResetKeys` →
  `EnableSecureBoot` → `Verify`) with `ShouldProcess`/`-WhatIf`, preflight guards that
  block a reset below the ROM baseline and on Gen12/Gen9, and pre-change key export.
- `scripts/VMware-SecureBootAudit.ps1` — ESXi host and VM risk classification per the
  KB 423893 matrix, with optional in-guest verification via `Invoke-VMScript`.
- Gen12 coverage — 2023 certificates active from factory, key reset must **not** be run.
- Gen9 coverage — no firmware path exists.
- ESXi host guidance: multi-signed builds (8.0 U3j `25429389`, 9.1 `25370933`), the
  TPM recovery key requirement, and why `secureBoot.py -c` is not a readiness test.
- `docs/runbook.md`, `docs/certificate-reference.md`, MIT `LICENSE`, PSScriptAnalyzer CI.

### Changed

- Previous scripts moved to `legacy/` with their inaccuracies documented. They retain
  OneView SSO discovery, which the v2 scripts do not yet implement.
