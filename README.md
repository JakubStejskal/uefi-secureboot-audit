# UEFI Secure Boot Audit — Microsoft CA 2011 → 2023

Audit and remediation tooling for the Microsoft Secure Boot certificate expiration, covering **HPE ProLiant Gen11 / Gen12**, **VMware ESXi hosts**, and **virtual machines running on ESXi**.

> **Status as of 2026-10-27:** all three 2011 CAs are past their expiry date; the last one, `Microsoft Windows Production PCA 2011`, expired on **2026-10-19**. Expiry alone is not revocation (see below). The sourced findings in this README date from 2026-08-04 and were not re-researched after that last expiry.

📘 **[Full runbook →](docs/runbook.md)** · 📋 **[Certificate reference →](docs/certificate-reference.md)** · 🚀 **[Quick start →](#quick-start)**

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
| 2026-10-19 | Microsoft Windows Production PCA 2011 | **Expired** |

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

## Quick start

**Requirements**

- Windows PowerShell 5.1 or PowerShell 7+. The two HPE scripts need no modules. `VMware-SecureBootAudit.ps1` needs **VMware.PowerCLI** and a vCenter (or ESXi) connection.
- HTTPS (443) from the machine you run it on to every iLO. iLO certificates are usually self-signed, so pass `-SkipCertificateCheck`.
- Downloaded as a zip on Windows? Run `Get-ChildItem .\scripts | Unblock-File` first, otherwise PowerShell may refuse to run the scripts.
- An iLO account that can read the system. Remediation needs one that may change BIOS / Secure Boot settings. The minimum iLO privileges have not been verified, so use an administrator account in a lab until you have.
- Each script has built-in help: `Get-Help .\scripts\HPE-SecureBootAudit.ps1 -Full`.
- The HPE scripts log in with a Redfish session (not Basic auth) and log out when done, because iLO has a low simultaneous-session limit.

**The path through the tooling**

1. **Audit** (read-only, changes nothing): [Audit an HPE fleet](#audit-an-hpe-fleet) and [Audit VMware](#audit-vmware).
2. **Read the `Verdict`** against [the next-step table](#verdicts-and-next-steps). `COMPLIANT` means you are done with that host; do not run the remediation script on it.
3. **Remediate only `NEEDS_KEY_RESET` / `NEEDS_ROM_AND_RESET` / `CERTS_OK_SECUREBOOT_OFF`** hosts, following the [checklist](#remediate).
4. **Audit again** and confirm every host reports `COMPLIANT`.

Nothing in this repository reboots a server, puts a host into maintenance mode or touches a VM's NVRAM.

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

### Verdicts and next steps

| Verdict | Meaning | Next step |
|---|---|---|
| `COMPLIANT` | Read from the live databases: KEK 2023 in `KEK`, the three 2023 CAs in `db`, Secure Boot enforcing (PK present, UserMode) | **Nothing.** Do not run the remediation script. |
| `CERTS_OK_SECUREBOOT_OFF` | Certificates complete, but Secure Boot is disabled or the platform is in SetupMode (no PK) | `-Stage EnableSecureBoot`. If `Has_PK` is `False`, a key reset is needed to restore the PK; preflight will report that the certificates are already present, and that is the one case where `-Force` is appropriate |
| `NEEDS_KEY_RESET` | Live databases lack 2023 certs; ROM meets baseline (Gen11) or is factory-capable (Gen12) | [Remediate](#remediate). Gen12: the keys were customised after factory state, so compare with `dbDefault` / `KEKDefault` first ([runbook](docs/runbook.md#gen12)); preflight refuses a Gen12 reset without `-Force` |
| `NEEDS_ROM_AND_RESET` | Live databases lack 2023 certs and System ROM is below the advisory baseline | Flash System ROM first, re-audit, then [remediate](#remediate) |
| `ROM_OK_CERTS_UNKNOWN` | Gen11: ROM meets baseline, live databases could not be read (see `CertInventoryNote`) | Read `CertInventoryNote`, then verify in RBSU (*Advanced Secure Boot Options → View entries*) or the Embedded UEFI Shell |
| `UNVERIFIED` | Gen12: live databases could not be read (see `CertInventoryNote`) | Same as above |
| `UNKNOWN` | Generation or System ROM version could not be determined | Check `Model` and `BiosVersion`; verify by hand |
| `OUT_OF_SCOPE` | iLO 5 server — no remote audit possible | [Manual procedure](docs/runbook.md#servers-with-ilo-5-gen10--gen10-plus--manual-procedure) |
| `NOT_SUPPORTED` | Gen9 — no firmware path exists | None available |
| `ERROR` | Unreachable, auth failure, or unexpected response | Read the `Error` column (network, credentials, TLS) and re-run for that host |

### Output columns

The audit returns one object per host; `-OutputCsv` / `-OutputJson` write all of them. A healthy Gen11 / Gen12 host looks like this:

| Column | Meaning | Healthy value |
|---|---|---|
| `Reachable` | iLO login succeeded | `True` |
| `Model`, `SerialNumber`, `Generation`, `Arch`, `ILOModel`, `ILOFirmware` | Identity from Redfish | — |
| `BiosVersion`, `RomVersion`, `RomRequired` | System ROM found vs. advisory baseline | version ≥ `RomRequired` (Gen12: no baseline) |
| `RomStatus` | `OK`, `UPDATE_REQUIRED`, `NA_FactoryDefault` (Gen12), `NO_FIRMWARE_PATH` (Gen9), `OUT_OF_SCOPE` (iLO 5), `Unknown` | `OK` or `NA_FactoryDefault` |
| `SecureBootEnable`, `SecureBootCurrentBoot`, `SecureBootMode` | Raw values from the `SecureBoot` resource | `True` / `Enabled` / `UserMode` |
| `SecureBootActive` | Booted with Secure Boot **and** a PK enrolled | `True` |
| `CertInventory` | `OK`, `PARTIAL`, `EMPTY`, `NOT_REPORTED`, `UNSUPPORTED_ILO5`, `NotAttempted` | `OK` |
| `CertInventoryNote` | Why the inventory is not `OK` | empty |
| `DbCounts` | Certificates read per live database | `PK=1 KEK=3 db=8 dbx=3` on the two reference platforms; other platforms differ |
| `Has_PK` | A PK is enrolled | `True` |
| `Has_KEK2023`, `Has_WindowsUEFICA2023`, `Has_MicrosoftUEFICA2023`, `Has_OptionRomCA2023` | Each 2023 certificate in **its own** live database | all `True` |
| `Missing2023` | The 2023 certificates not found, as `db:CN; …` | empty |
| `Legacy2011InDb`, `Legacy2011InKEK` | 2011 certificates still present | `True` (expected; keep them) |
| `Revoked2011InDbx` | A 2011 CA sits in `dbx` | `False` (if `True`, hosts that boot through it may stop booting) |
| `Has_VMwareDbCert` | A `db` entry whose CN contains "VMware" | informational |
| `CertDetail` | Every certificate read, as `db:CN (exp yyyy-MM-dd)` | — |
| `Verdict`, `Action`, `Error` | Result, recommended action, failure reason | — |

### Remediate

`HPE-SecureBootRemediate.ps1` takes **one** iLO per call (`-ILOHost`), is meant for Gen11 (Gen12 and Gen9 are blocked, iLO 5 is refused) and **never reboots the server**: the BIOS applies each change at the next POST, and the reboots in between are yours.

**Checklist before stage 1**

1. The audit says `NEEDS_KEY_RESET` or `NEEDS_ROM_AND_RESET` (System ROM flashed first), or `CERTS_OK_SECUREBOOT_OFF` for stage 2 only.
2. **ESXi with TPM:** the recovery key is saved **off-host** (`esxcli system settings encryption recovery list`). For many hosts at once, [`esxi-tpm-recovery-export`](https://github.com/JakubStejskal/esxi-tpm-recovery-export) collects them through vCenter and can be limited to chosen hosts with `-VMHost`. Without the key a PSOD after the reset is unrecoverable.
3. **Windows / Linux on the host:** BitLocker suspended and recovery passwords escrowed; TPM-sealed LUKS re-seal planned (PCR 7 changes).
4. The ESXi host is in maintenance mode (you do this; the script does not). HPE recommends running Secure Boot database operations with the server powered off.
5. Dry-run with `-WhatIf` (below). It prints the preflight result and sends no reset; it writes no backup either.

```powershell
$cred = Get-Credential

# 0. Dry-run: preflight + what would be sent, nothing changed
.\scripts\HPE-SecureBootRemediate.ps1 -ILOHost ilo-esx01 -Credential $cred -Stage ResetKeys -SkipCertificateCheck -WhatIf

# 1. Reset keys (deletes enrolled keys, disables Secure Boot) → reboot yourself
.\scripts\HPE-SecureBootRemediate.ps1 -ILOHost ilo-esx01 -Credential $cred -Stage ResetKeys -SkipCertificateCheck

# 2. Re-enable Secure Boot → reboot yourself
.\scripts\HPE-SecureBootRemediate.ps1 -ILOHost ilo-esx01 -Credential $cred -Stage EnableSecureBoot -SkipCertificateCheck

# 3. Verify (read-only): all four 2023 certificates present and Secure Boot enforcing
.\scripts\HPE-SecureBootRemediate.ps1 -ILOHost ilo-esx01 -Credential $cred -Stage Verify -SkipCertificateCheck
```

On ESXi, run `/sbin/auto-backup.sh` once the host is up after stage 2, or the new state is not re-sealed.

To dry-run several hosts: `'ilo-esx01','ilo-esx02' | ForEach-Object { .\scripts\HPE-SecureBootRemediate.ps1 -ILOHost $_ -Credential $cred -Stage ResetKeys -SkipCertificateCheck -WhatIf }`. Run the real stages host by host or in small batches.

**`BLOCKED`** means preflight refused stage 1 and printed the reason in red. It blocks when:

- the System ROM is below baseline (a reset would restore 2011-only defaults, a silent regression): flash the ROM, do not override;
- the live `KEK` and `db` already hold all four 2023 certificates (a reset gains nothing, disables Secure Boot and discards custom keys): do not override unless you are restoring a missing PK, see [the verdict table](#verdicts-and-next-steps);
- the server is Gen12 or Gen9 (pointless or harmful).

`-Force` overrides these; the block exists for a reason. It does **not** override the refusal of iLO 5 servers. `EnableSecureBoot` warns when no PK is enrolled (SetupMode enforces nothing).

**Backup.** Before the reset, the readable certificates are exported to `.\secureboot-backup\<host>_<yyyyMMdd-HHmmss>\` as `certificates.json` plus one PEM per certificate (`-BackupPath` changes the root folder). Only certificate entries are exported (no `dbx` hashes). The script has no restore function; re-enrolling a custom key is manual (RBSU or the UEFI Shell).

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
8. **Re-audit** and confirm every host reports `COMPLIANT`. The last 2011 CA expired on 2026-10-19, so any host that does not is an open item.

Windows in-guest details, event IDs and Linux guidance are in the [runbook](docs/runbook.md).

---

## Before production

- **Verify the ROM baselines against the current advisory revision.** HPE revised a00156355en_us five times between January and July 2026. The values here are from rev. 5.
- **Test the remediation script on a lab server first.** The v2.1 scripts have been exercised against the mock iLO in [`tests/mock-ilo`](tests/mock-ilo/README.md) on PowerShell 7 and Windows PowerShell 5.1 (remediation: `Verify`, preflight blocks and `-WhatIf` only). **They have not been run against a live iLO**, and that caveat stays until someone does so: in particular the session login (`POST SessionService/Sessions/` → `X-Auth-Token`) and the `ResetKeys` / `SecureBootEnable` writes are unproven on real hardware. The audit is read-only; the remediation is not.
- **The Redfish read paths are confirmed on live hardware** for both generations (2026-10-27), by reading the endpoints manually (`.../SecureBoot/SecureBootDatabases/{PK|KEK|db|dbx}/Certificates/`, then each member): DL320 Gen11 (iLO 6, System ROM U63 v2.80) and DL380 Gen12 (iLO 7, System ROM U68 v1.52). Both returned PK=1, KEK=3, db=8 certificates including all four 2023 CAs and a `VMware Secure Boot Signing` entry in `db`; the scripts follow the same path. Full list in the [certificate reference](docs/certificate-reference.md#hpe-platform-default-inventory-observed-live). To repeat the read by hand (for example when a host shows `ERROR`), see the [runbook](docs/runbook.md#manual-spot-check-of-the-live-databases).
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
