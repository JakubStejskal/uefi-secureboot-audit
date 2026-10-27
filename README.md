# UEFI Secure Boot Audit — Microsoft CA 2011 → 2023

Audit and remediation tooling for the Microsoft Secure Boot certificate expiration, covering **HPE ProLiant Gen11 / Gen12**, **VMware ESXi hosts**, and **virtual machines running on ESXi**.

> **Status as of 2026-08-04:** two of the three 2011 CAs have already expired. Nothing broke, and nothing was supposed to. The last live deadline is **19 October 2026**.

📘 **[Full runbook →](docs/runbook.md)** · 📋 **[Certificate reference →](docs/certificate-reference.md)**

---

## The 60-second version

**Expiration is not revocation.** UEFI firmware validates an image by checking membership in `db` and absence from `dbx` — it does **not** check the certificate's validity period (UEFI 2.10 §32). Microsoft confirmed this explicitly on 2026-06-24 and stated it has **no plan to revoke** the 2011 UEFI CA.

So what boots today keeps booting. Two things actually matter:

1. **Servicing is severed.** With `Microsoft Corporation KEK CA 2011` expired, any machine without `KEK 2K CA 2023` can no longer receive **any** future `db` or `dbx` update — including revocations for boot-level CVEs.
2. **A 2023-only binary meeting a 2011-only `db` fails to boot.** This is the real-world failure mode, and it arrives via a patched golden image, a re-spun Linux shim, or a replacement add-in card — not on the expiry date itself.

The documented at-scale outage so far is **Citrix MCS** ([CTX696696](https://support.citrix.com/external/article/CTX696696/vda-boot-failure-no-boot-media-after-mcs.html)): MCS replaces the OS disk but not the VM's NVRAM, so a master image patched to a 2023-signed bootloader clones onto VMs that cannot boot it. Check every golden image, template, linked-clone and Packer pipeline you run for the same pattern.

---

## Timeline

| Date | Certificate | Status |
|---|---|---|
| 2026-06-24 | Microsoft Corporation KEK CA 2011 | **Expired** |
| 2026-06-27 | Microsoft Corporation UEFI CA 2011 | **Expired** |
| **2026-10-19** | **Microsoft Windows Production PCA 2011** | **Upcoming** |

---

## HPE generation matrix

HPE delivers the 2023 certificates **only through System ROM**. There is no separate certificate utility, and iLO firmware is not the delivery vehicle.

| Generation | Min. System ROM | Key reset | iLO certificate read-out |
|---|---|---|---|
| **Gen11** (iLO 6 ≥ 1.10) | Intel **2.42** · AMD **2.30** | Required per advisory | ✅ Full inventory |
| **Gen12** (iLO 7 ≥ 1.11) | — (factory) | **Not required** | ✅ Full inventory |
| Gen9 (iLO 4) | *none exists* | — | ❌ No API |

Source: [HPE Customer Advisory a00156355en_us](https://support.hpe.com/hpesc/public/docDisplay?docId=a00156355en_us&docLocale=en_US), rev. 5 (2026-07-02). In practice **any 2026 SPP** satisfies the Gen11 baseline.

> Gen11 is listed as "required" because that is what the advisory states. Some Gen11 hosts were observed to need no manual step; confirm by reading the live `db` before skipping the reset.

### Servers with iLO 5 (Gen10 / Gen10 Plus) are out of scope

The tooling here does not audit or remediate iLO 5 servers, because **in practice it cannot be done remotely**:

- iLO 5 has no certificate inventory (`SecureBootDatabases` does not exist at any firmware level), so a fleet audit is not possible.
- The only remote reset iLO 5 offers wipes **all** keys and disables Secure Boot.
- Resetting a single database, exporting keys and enrolling keys are available only locally in RBSU (reachable through the iLO remote console, but not scriptable).

A manual, field-tested procedure and its caveats are in the [runbook](docs/runbook.md#servers-with-ilo-5-gen10--gen10-plus--manual-procedure).

### A ROM update alone does nothing

Flashing the System ROM refreshes only the **read-only `*Default` databases**. The live NVRAM variables are untouched — HPE states it plainly: *"Defaults are not used at runtime."*

The new keys reach the live databases only via an explicit **"Reset All Keys to Platform Defaults"**, which:

- **deletes every customer-enrolled key** (custom PK, MOK, OS-vendor certificates), and
- **turns Secure Boot off**, requiring a separate step to turn it back on.

Budget **three reboots** per server: ROM flash → key reset → re-enable Secure Boot.

---

## VMware

### Hosts — not the exposure

Broadcom [KB 434297](https://knowledge.broadcom.com/external/article/434297/secure-boot-certificate-expirations-guid.html): *"There is no impact on Secure Boot-enabled ESX hosts, and no immediate action is necessary."* That held — no ESXi boot failures were reported after 2026-06-27.

Multi-signed bootloaders (2011 + 2023) shipped in:

| Release | Date | Build |
|---|---|---|
| ESX 9.1.0.0 | 2026-05-12 | `25370933` |
| ESXi 8.0 U3j (P09) | 2026-05-27 | `25429389` |

vSphere 7.x will never get one (EOGS 2025-10-02).

> ⚠️ **The one action that genuinely bricks an ESXi host** is removing `Microsoft Corporation UEFI CA 2011` from `db`, or pushing it to `dbx`. That CA validates the firmware of RAID controllers, NICs and HBAs. Broadcom: *"Revoking this certificate without fully understanding its usage may result in an unbootable system."*

> ⚠️ **Before any firmware work on a TPM-enabled host**, save the recovery key **off-host**:
> ```
> esxcli system settings encryption recovery list
> ```
> A firmware flash that resets Secure Boot causes a PSOD, and Broadcom is explicit that configuration backups alone cannot recover it.

Also note: `secureBoot.py -c` is **not** a readiness test. It validates VIB signatures and acceptance levels; Broadcom states *"This script does not check for an up-to-date bootloader."* It tells you nothing about which CA signed your bootloader or what is in the firmware `db`.

### Virtual machines — this is the exposure

A VM's Secure Boot variables live in its `.nvram` file, seeded **once** at NVRAM creation from the host's EFI image. **Patching the host does not re-seed existing VMs. Neither does a hardware-version upgrade.**

| VM origin | PK | KEK / db | Risk |
|---|---|---|---|
| ESXi < 8.0 U2, or HW 13 | `VMW.NULLPK` | 2011 only | **HIGH** |
| ESXi 8.0 U2 – U3i, HW 14+ | `VMW.NULLPK` | 2023 present | **MEDIUM** — can never be updated again |
| Host 8.0 U3j+, no vTPM | SilentPK adds it | 2023 | **LOW** — power-cycle and done |
| Host U3j+, vTPM, non-Windows | `uefi.secureBoot.PK.resetOnce` | 2023 | MEDIUM |
| Host U3j+, vTPM, Windows | — | — | MEDIUM — **Broadcom says wait** for the capsule solution |
| ESX 9.x | Windows OEM Devices PK | 2023 | **LOW** |

Hardware version thresholds: **14+** is a hard requirement for any PK update; **20+** is the practical recommendation for enough EFI variable storage to absorb the enlarged DBX (below it, expect Event 1796 / `0x80070008`).

> ⚠️ **The VMware PK is not expired — it is NULL.** `VMW.NULLPK` is a placeholder with a NULL signature: no X.509, therefore no expiry date. The expired *"VMware Certificate"* (Dec 2019) that circulates in blog posts sits in `db` and is inert. What NULL PK actually does is block KEK update authorisation, surfacing in Windows as **Event ID 1803**.

> ⚠️ **Do not delete or rename `.nvram`.** Broadcom withdrew that guidance — KB 423919 replaced KB 421593 explicitly *"to avoid suggestions of deleting NVRAM, as that behavior can lead to unexpected corruptions of the associated VM."* On a vTPM VM it destroys the vTPM state, and with it the BitLocker / LUKS keys, irreversibly.

---

## Scripts

All scripts run on Windows PowerShell 5.1 and PowerShell 7+.

| Script | Mode | Purpose |
|---|---|---|
| [`scripts/HPE-SecureBootAudit.ps1`](scripts/HPE-SecureBootAudit.ps1) | read-only | Fleet audit via iLO Redfish, Gen11 / Gen12 |
| [`scripts/HPE-SecureBootRemediate.ps1`](scripts/HPE-SecureBootRemediate.ps1) | **destructive** | Staged key reset with preflight guards and pre-change key export |
| [`scripts/VMware-SecureBootAudit.ps1`](scripts/VMware-SecureBootAudit.ps1) | read-only | ESXi host and VM risk classification, optional in-guest verification |

### Audit an HPE fleet

```powershell
$cred = Get-Credential

# One or more hosts
$r = .\scripts\HPE-SecureBootAudit.ps1 -ILOHost ilo-esx01,ilo-esx02 -Credential $cred -SkipCertificateCheck
$r | Format-Table ILOHost,Model,Generation,RomStatus,SecureBootActive,CertInventory,DbCounts,Verdict -AutoSize

# Why a host is not COMPLIANT (reasons are also printed under the summary)
$r | Where-Object Verdict -ne 'COMPLIANT' | Format-List ILOHost,Verdict,Missing2023,CertInventoryNote,Action,Error

# From a CSV (see examples/fleet.csv)
.\scripts\HPE-SecureBootAudit.ps1 -InputCsv .\examples\fleet.csv -Credential $cred `
    -SkipCertificateCheck -OutputCsv .\hpe-audit.csv -OutputJson .\hpe-audit.json
```

**Verdicts:**

| Verdict | Meaning |
|---|---|
| `COMPLIANT` | Read from the live databases: KEK 2023 in `KEK`, the three 2023 CAs in `db`, Secure Boot enforcing (PK present, UserMode) |
| `CERTS_OK_SECUREBOOT_OFF` | Certificates complete, but Secure Boot is disabled or the platform is in SetupMode (no PK) |
| `NEEDS_KEY_RESET` | Live databases lack 2023 certs; ROM meets baseline (Gen11) or is factory-capable (Gen12) |
| `NEEDS_ROM_AND_RESET` | Live databases lack 2023 certs and System ROM is below the advisory baseline |
| `ROM_OK_CERTS_UNKNOWN` | Gen11: ROM meets baseline, live databases could not be read (see `CertInventoryNote`) |
| `UNVERIFIED` | Gen12: live databases could not be read (see `CertInventoryNote`) |
| `UNKNOWN` | Generation or System ROM version could not be determined |
| `OUT_OF_SCOPE` | iLO 5 server — no remote audit possible, see [runbook](docs/runbook.md) |
| `NOT_SUPPORTED` | Gen9 — no firmware path exists |
| `ERROR` | Unreachable, auth failure, or unexpected response |

### Remediate

Three stages, each requiring a reboot in between.

```powershell
# Always dry-run first
.\scripts\HPE-SecureBootRemediate.ps1 -ILOHost ilo-esx01 -Credential $cred -Stage ResetKeys -SkipCertificateCheck -WhatIf

# 1. Reset keys (deletes enrolled keys, disables Secure Boot) → reboot
.\scripts\HPE-SecureBootRemediate.ps1 -ILOHost ilo-esx01 -Credential $cred -Stage ResetKeys -SkipCertificateCheck

# 2. Re-enable Secure Boot → reboot
.\scripts\HPE-SecureBootRemediate.ps1 -ILOHost ilo-esx01 -Credential $cred -Stage EnableSecureBoot -SkipCertificateCheck

# 3. Verify
.\scripts\HPE-SecureBootRemediate.ps1 -ILOHost ilo-esx01 -Credential $cred -Stage Verify -SkipCertificateCheck
```

Preflight **blocks** the reset when the System ROM is below baseline (a reset would restore 2011-only defaults — a silent regression), when the live `KEK` and `db` already hold all four 2023 certificates (it would gain nothing, disable Secure Boot and discard custom keys), and on Gen12 and Gen9 where it is pointless or harmful. `-Force` overrides; the block exists for a reason. `EnableSecureBoot` warns when no PK is enrolled (SetupMode enforces nothing).

Before the reset, all readable certificates are exported to `.\secureboot-backup\<host>_<timestamp>\` as PEM plus a JSON manifest. The script refuses iLO 5 servers outright (not overridable with `-Force`).

### Audit VMware

```powershell
Connect-VIServer vcsa01

.\scripts\VMware-SecureBootAudit.ps1 -OutputCsv .\vmware-audit.csv |
    Where-Object Risk -in 'HIGH','MEDIUM' |
    Format-Table Name,HWVersion,vTPM,HostBuild,Risk,Action -AutoSize

# With in-guest verification (the only way to actually read NVRAM contents)
.\scripts\VMware-SecureBootAudit.ps1 -IncludeGuestCheck -GuestCredential (Get-Credential)
```

---

## Recommended rollout order

1. **Audit both sides.** Classify by verdict and risk before changing anything.
2. **Escrow the recovery material.** ESXi TPM recovery keys off-host; BitLocker recovery passwords out of the VMs.
3. **vCenter → ESXi hosts** to 8.0 U3j (`25429389`) or ESX 9.1 (`25370933`).
4. **HPE System ROM** (any 2026 SPP) in batches. iLO 5 servers follow the manual procedure in the runbook.
5. **Key reset + re-enable Secure Boot** in a maintenance window, three reboots per server.
6. **Power-cycle VMs** so SilentPK applies the PK.
7. **Windows in-guest servicing** — set `AvailableUpdates` to `0x5944`, run the scheduled task, confirm Event **1808**.
8. **Re-audit** and close out before **2026-10-19**.

Windows in-guest details, event IDs and Linux guidance are in the [runbook](docs/runbook.md).

---

## Before production

- **Verify the ROM baselines against the current advisory revision.** HPE revised a00156355en_us five times between January and July 2026. The values here are from rev. 5.
- **Test the remediation script on a lab server first.** The v2.1 scripts have been exercised against the mock iLO in [`tests/mock-ilo`](tests/mock-ilo/README.md) on PowerShell 7 and Windows PowerShell 5.1 (remediation: `Verify`, preflight blocks and `-WhatIf` only), not yet against live hardware. The audit is read-only; the remediation is not.
- **`SecureBootDatabases` is confirmed on live hardware** for both generations (2026-10-27), by reading the Redfish endpoints manually: DL320 Gen11 (iLO 6, System ROM U63 v2.80) and DL380 Gen12 (iLO 7, System ROM U68 v1.52). Both returned PK=1, KEK=3, db=8 certificates including all four 2023 CAs and a `VMware Secure Boot Signing` entry in `db` — full list in the [certificate reference](docs/certificate-reference.md#hpe-platform-default-inventory-observed-live).
- **The PCR indices ESXi seals its configuration against are unpublished.** Whether adding 2023 certificates to firmware `db` can break config unsealing on specific hardware is therefore untested. This is the highest-value lab test before a fleet rollout.

## Known gaps upstream

- Broadcom's promised **PowerCLI sample script** and the **capsule-based vTPM solution** (both announced in KB 423893) had not shipped as of 2026-08-04.
- **vLCM and hardware support managers have no compliance check** for Secure Boot certificates. Cluster compliance can read fully green while every host still has a 2011-only `db`.

---

## Legacy scripts

The previous OneView-based tooling is preserved under [`legacy/`](legacy/), including `hpe-secureboot-audit-v2.sh` with OneView SSO discovery — a capability the v2 scripts do not yet have. The original Czech README is at [`legacy/README.cs.md`](legacy/README.cs.md).

⚠️ The legacy scripts carry **outdated ROM baselines** and assumptions that no longer hold. Use them for OneView discovery only; take the certificate facts from this README.

---

## Sources

**HPE** — [a00156355en_us](https://support.hpe.com/hpesc/public/docDisplay?docId=a00156355en_us&docLocale=en_US) (advisory, rev. 5) · [a00159017en_us](https://support.hpe.com/hpesc/public/docDisplay?docId=a00159017en_us&docLocale=en_US) (Azure Stack Hub, includes BitLocker steps) · [Secure Boot Databases](https://servermanagementportal.ext.hpe.com/docs/concepts/securebootdatabases)

**Broadcom** — [KB 423893](https://knowledge.broadcom.com/external/article/423893/secure-boot-certificate-expirations-and.html) (VMs) · [KB 423919](https://knowledge.broadcom.com/external/article/423919/manual-update-of-secure-boot-variables-i.html) (manual vUEFI enrolment) · [KB 434297](https://knowledge.broadcom.com/external/article/434297/secure-boot-certificate-expirations-guid.html) (hosts) · [KB 316424](https://knowledge.broadcom.com/external/article/316424/how-to-prepare-a-tpm-enabled-esxi-host-f.html) (TPM recovery)

**Microsoft** — [KB5062710](https://support.microsoft.com/en-us/topic/windows-secure-boot-certificate-expiration-and-ca-updates-7ff40d33-95dc-4c3c-8725-a9b95457578e) · [KB5068202](https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d) (registry) · [Troubleshooting guide](https://support.microsoft.com/en-us/servicing/os/secure-boot/2026/03/secure-boot-troubleshooting-guide) · [Expiration is not revocation](https://techcommunity.microsoft.com/blog/linuxandopensourceblog/what-it-teams-need-to-know-about-linux-secure-boot-certificates-expiring-in-2026/4530725)

**Other** — [Citrix CTX696696](https://support.citrix.com/external/article/CTX696696/vda-boot-failure-no-boot-media-after-mcs.html) · [Red Hat 7128933](https://access.redhat.com/articles/7128933) · [AlmaLinux](https://wiki.almalinux.org/documentation/secure-boot-2023-certificates.html)

---

## Licence & disclaimer

[MIT](LICENSE). Provided **as-is, with no warranty of any kind**.

This project is **not affiliated with, endorsed by, or supported by** HPE, Broadcom, VMware, Microsoft or Citrix. All product names and knowledge-base references are the property of their respective owners.

Resetting Secure Boot keys and updating firmware carry a real risk of rendering a system unbootable and of triggering BitLocker or TPM recovery. You are responsible for validating these procedures in your own environment, on non-production hardware, before using them.
