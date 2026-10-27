# Runbook — Microsoft Secure Boot CA 2011 → 2023

Operational procedures for HPE ProLiant Gen11 / Gen12 (iLO 5 servers: see the manual procedure), VMware ESXi hosts, and virtual machines running on ESXi.

State as of **2026-08-04**. See the [certificate reference](certificate-reference.md) for thumbprints and verification snippets.

---

## Contents

- [What actually breaks](#what-actually-breaks)
- [HPE ProLiant](#hpe-proliant)
- [ESXi hosts](#esxi-hosts)
- [Virtual machines](#virtual-machines)
- [Windows in-guest servicing](#windows-in-guest-servicing)
- [Linux guests](#linux-guests)
- [Rollout order](#rollout-order)

---

## What actually breaks

**Expiration is not revocation.** UEFI firmware validates an image against `db` membership and `dbx` absence. It does **not** check the certificate's validity period — that behaviour is defined in UEFI 2.10 §32, and Microsoft confirmed it explicitly on 2026-06-24, adding that it has **no plan to revoke** the 2011 UEFI CA.

The corollary that matters operationally: **do not remove the 2011 CA from `db`**, and do not push it to `dbx`.

### Does not break

- Boot of already-signed binaries — bootmgfw.efi, shim, GRUB, option ROMs
- Normal OS operation and standard Windows Update servicing
- ESXi hosts (Broadcom KB 434297, confirmed by the absence of any reported failures after 2026-06-27)

### Does break

| Trigger | Consequence |
|---|---|
| KEK CA 2011 expired (2026-06-24) | Machines without `KEK 2K CA 2023` can no longer receive **any** future `db` or `dbx` update, including revocations for boot-level CVEs. This is the servicing hard-stop. |
| UEFI CA 2011 expired (2026-06-27) | Microsoft can only sign third-party binaries with the 2023 CAs. The failure fires when a 2023-only shim or option ROM first reaches a system whose `db` lacks the 2023 CA — a pre-OS boot failure, not recoverable by package rollback. |
| Windows Production PCA 2011 expires 2026-10-19 | New Windows Boot Manager builds are signed by `Windows UEFI CA 2023` only. Devices without it in `db` stop receiving boot-manager security fixes. |

### Compatibility matrix

| Firmware `db` contains | 2011-only shim | 2023-only shim | Dual-signed shim |
|---|---|---|---|
| 2011 CA only | Boots | **Does not boot** | Should boot |
| 2023 CA only | **Does not boot** | Boots | Should boot |
| Both | Boots | Boots | Boots |

Microsoft's own caveat: dual-signing is not a guarantee — *"some firmware mishandles multiple signatures and evaluates only one of them."*

### The documented at-scale outage

Citrix MCS, [CTX696696](https://support.citrix.com/external/article/CTX696696/vda-boot-failure-no-boot-media-after-mcs.html): *"MCS replaces the OS disk but does not update the VM's NVRAM — it retains original Secure Boot certificates from initial VM creation."* A master image patched to a 2023-signed bootloader, cloned onto VMs whose NVRAM trusts only 2011, produces immediate **"No Boot Media"**. ESXi builds before 8.0 U3j (25429389) are named explicitly, alongside XenServer, Hyper-V/SCVMM, Nutanix AHV, Azure, GCP and AWS.

This is the archetype: **not the expiry, but a 2023-only boot chain meeting a 2011-only `db`.** Audit every golden image, template, linked-clone and Packer pipeline for the same pattern.

---

## HPE ProLiant

### Delivery mechanism

HPE delivers the 2023 certificates **only through System ROM**. There is no separate certificate utility, and iLO firmware is not the delivery vehicle.

### Minimum System ROM

Per [advisory a00156355en_us](https://support.hpe.com/hpesc/public/docDisplay?docId=a00156355en_us&docLocale=en_US), rev. 5 (2026-07-02):

| Generation | Intel | AMD | Exception |
|---|---|---|---|
| Gen11 | **2.42** | **2.30** | — |
| Gen12 | — | — | 2023 certificates included **and enabled** from the first factory BIOS |
| Gen9 | *none exists* | | Last ROM P89 v3.30 (2023-09) contains no 2023 certificates |

The published minimum is the version in which the **last** of the four certificates — `Microsoft Option ROM UEFI CA 2023` — landed. Earlier ROMs typically already carry the other three.

In practice **any 2026 SPP** satisfies the Gen11 baseline: bundle 2026.05.00.00 carries U54 2.84.

### iLO capability by generation

| iLO | Servers | `/SecureBoot` | `SecureBoot.ResetKeys` | `SecureBootDatabases` |
|---|---|---|---|---|
| iLO 4 | Gen9 | ❌ | ❌ | ❌ |
| iLO 5 | iLO 5 servers | ✅ | ✅ (all keys only) | ❌ **never, at any firmware level** |
| iLO 6 | Gen11 | ✅ | ✅ | ✅ since v1.10 |
| iLO 7 | Gen12 | ✅ | ✅ | ✅ since v1.11 |

`SecureBootDatabases` was read successfully on a live DL320 Gen11 (iLO 6) and a live DL380 Gen12 (iLO 7) on 2026-10-27 — inventory in the [certificate reference](certificate-reference.md#hpe-platform-default-inventory-observed-live).

iLO 5 servers are out of scope for the tooling — see [Servers with iLO 5](#servers-with-ilo-5-gen10--gen10-plus--manual-procedure).

### A ROM update alone changes nothing

A System ROM flash refreshes only the read-only **Default** databases — `PKDefault`, `KEKDefault`, `dbDefault`, `dbxDefault`, `dbtDefault`, `dbrDefault`. The live UEFI NVRAM variables are untouched. HPE documents this directly:

> "Defaults contain OEM's or platform defined default keys (certificates/signatures). **Defaults are not used at runtime** but is provided in order to allow the OS to recover the OEM's default key setup. Defaults are `read-only`."

New keys reach the live databases only via an explicit **"Reset All Keys to Platform Defaults"**. Advisory rev. 5, verbatim:

> "**"Reset All Keys to Platform Defaults" is required to activate these digital certificates** after the minimum BIOS version that includes the digital certificates is installed."

### Procedure — Gen11

Budget **three reboots** per server.

**1. Audit**

```powershell
$cred = Get-Credential
.\scripts\HPE-SecureBootAudit.ps1 -InputCsv .\examples\fleet.csv -Credential $cred `
    -SkipCertificateCheck -OutputCsv .\hpe-audit.csv
```

`COMPLIANT` is only issued after the live `KEK` and `db` were read: `KEK 2K CA 2023` in `KEK`, the three 2023 CAs in `db`, Secure Boot enforcing (PK present, `UserMode`). Everything else needs a look — the summary prints the reason for every non-compliant host, and the `Missing2023`, `CertInventoryNote` and `Error` columns carry the detail. Verdict meanings are in the [README](../README.md#audit-an-hpe-fleet); the ones you will act on:

| Verdict | Next step |
|---|---|
| `NEEDS_ROM_AND_RESET` | Flash System ROM (step 4), then reset keys |
| `NEEDS_KEY_RESET` | Reset keys (step 5) |
| `CERTS_OK_SECUREBOOT_OFF` | Certificates are complete; re-enable Secure Boot (step 6). If `Has_PK` is `False` the platform is in SetupMode — reset keys first |
| `ROM_OK_CERTS_UNKNOWN` (Gen11) / `UNVERIFIED` (Gen12) | Live databases could not be read. Check `CertInventoryNote`, then verify in RBSU (*Advanced Secure Boot Options → View entries*) or the Embedded UEFI Shell |

**2. Capture rollback state**

- `GET` every `CertificateString` (the remediation script does this automatically)
- Record the current ROM version and confirm downgrade is still permitted — Gen11 U54 2.30 is the first ROM supporting iLO 6 1.6.2, and HPE does not support downgrading below it afterwards

**3. Protect the OS**

| OS | Action |
|---|---|
| ESXi with TPM | `esxcli system settings encryption recovery list` — store the key **off-host**. Without it a PSOD is unrecoverable. |
| Windows with BitLocker | `Suspend-BitLocker -MountPoint C: -RebootCount 2`, and escrow recovery passwords regardless |
| Linux with TPM-sealed LUKS | Plan the re-seal — PCR7 changes |

**4. Flash System ROM**, then reboot.

**5. Reset keys**, then reboot.

RBSU path:
```
F9 → System Utilities → System Configuration → BIOS/Platform Configuration (RBSU)
   → Server Security → Secure Boot Settings → Advanced Secure Boot Options
   → Reset all keys to platform defaults → Yes
```

Redfish:
```http
POST /redfish/v1/Systems/1/SecureBoot/Actions/SecureBoot.ResetKeys
{ "ResetKeysType": "ResetAllKeysToDefault" }
```

Or:
```powershell
.\scripts\HPE-SecureBootRemediate.ps1 -ILOHost ilo-esx01 -Credential $cred -Stage ResetKeys -SkipCertificateCheck
```

`ResetKeysType` accepts exactly three values: `ResetAllKeysToDefault`, `DeleteAllKeys`, `DeletePK`. There is no `ResetPK`. The latter two put the system into Setup Mode and will leave it unbootable with Secure Boot enabled.

The script's preflight **blocks** the reset when the System ROM is below baseline and when the live `KEK` and `db` already contain all four 2023 certificates (a reset would gain nothing, disable Secure Boot and discard custom keys). `-Force` overrides; use `-WhatIf` first.

**6. Re-enable Secure Boot**, then reboot. The reset turned it off. The script warns if no PK is enrolled: in SetupMode `SecureBootEnable = true` is accepted but nothing is enforced, so run the key reset first.

```http
PATCH /redfish/v1/Systems/1/SecureBoot
{ "SecureBootEnable": true }
```

**7. Verify**

- `-Stage Verify` (or re-run the audit): `Microsoft Corporation KEK 2K CA 2023` in `KEK` and `Windows UEFI CA 2023`, `Microsoft UEFI CA 2023`, `Microsoft Option ROM UEFI CA 2023` in `db` — each checked in its own database, a hit in `dbx` does not count. The audit should now return `COMPLIANT`; `CERTS_OK_SECUREBOOT_OFF` means the certificates are there but Secure Boot is not enforcing yet (step 6 missing)
- ESXi: run `/sbin/auto-backup.sh` once the host is up, or the configuration is not re-sealed

**8. Re-enrol custom keys** that step 5 destroyed.

### Servers with iLO 5 (Gen10 / Gen10 Plus) — manual procedure

Out of scope for `HPE-SecureBootAudit.ps1` and `HPE-SecureBootRemediate.ps1`, because in practice it cannot be done remotely:

- **No audit.** The iLO 5 Redfish API exposes `SecureBootEnable`, `SecureBootCurrentBoot` and `SecureBootMode` but no certificate inventory, at any firmware level including v3.19. The System ROM version only shows what the *default* databases contain, never what is active in `db`. Certificate contents are visible only in the Embedded UEFI Shell, RBSU, or from inside the OS.
- **No selective reset.** `SecureBoot.ResetKeys` accepts exactly `ResetAllKeysToDefault`, `DeleteAllKeys` and `DeletePK`. No iLO 5 Redfish resource, BIOS attribute or `ilorest` command resets a single database, exports keys, or enrols keys.
- **The only remote reset wipes everything** (PK, KEK, db, dbx and all customer keys) and disables Secure Boot. It is HPE's documented method in the advisory, but it is not validated here and the scripts do not issue it against iLO 5.

Everything selective happens in RBSU, reachable through the iLO remote console but interactive. The following is **field-tested, not HPE-documented**. HPE's advisory prescribes only the all-keys reset and says nothing about resetting `db` alone. On the tested servers, only the `db` variable needed resetting to load the new certificates from the updated System ROM; some firmware could not be installed until that was done.

1. Update the System ROM to the baseline in the [advisory](https://support.hpe.com/hpesc/public/docDisplay?docId=a00156355en_us&docLocale=en_US).
2. RBSU → *Server Security → Secure Boot Settings → Advanced Secure Boot Options* → **Export all keys** to a USB or SD device in the server. Resetting `db` removes custom entries.
3. In the same menu, open **DB** → **Reset to platform defaults**.
4. Re-enrol any custom entries from the exported media.
5. Verify in the Embedded UEFI Shell or from inside the OS that the 2023 certificates are present, and that Secure Boot is still enabled.

HPE does not document whether a `db`-only reset keeps Secure Boot enabled or leaves PK, KEK and dbx untouched — record the before and after state on the first server of each model. Apply the same BitLocker and TPM precautions as for the all-keys reset.

### Gen12

Skip steps 2–6, 8 **if the audit returns `COMPLIANT`**. Advisory rev. 5: the certificates are *"included and enabled for all HPE Gen12 platforms since its first original BIOS release; therefore, the action to 'Reset All Keys to Platform Defaults' **is not required**."* Performing the reset gains nothing and discards any custom keys.

The audit does not take that on trust: Gen12 is judged from the live databases like Gen11. `UNVERIFIED` means they could not be read — verify in RBSU. `NEEDS_KEY_RESET` on a Gen12 server means the keys were customised or replaced after the factory state; compare with `dbDefault` / `KEKDefault` before resetting.

### Gen9

No firmware path exists. The last DL380 Gen9 System ROM (P89 v3.30, 2023-09-21) contains the three 2011 certificates and none of the four 2023 certificates, and Gen9 is not listed in any HPE advisory. Options: manual enrolment via RBSU or UEFI Shell (Gen9 also requires physical presence to enable Secure Boot), run without Secure Boot, or hardware refresh.

### Known traps

- **HPE's own option ROM signing certificate lives in the default `db`.** Hand-curating the database instead of resetting to defaults, and dropping the HPE entry, means Smart Array and NIC option ROMs will not load and the server will not boot with Secure Boot enabled.
- **HPE prunes expired vendor certificates from defaults.** Older ROMs, e.g. 3.50 (2025-04): *"Removed Expired SUSE and Vmware Certificates."* If you depend on them, a reset removes them. The platform-default `db` observed on 2026-10-27 does contain a current `VMware Secure Boot Signing` entry (valid to 2037) — see the [certificate reference](certificate-reference.md#hpe-platform-default-inventory-observed-live).
- **iLO 6 1.61 ↔ 1.62 requires a server reboot** in either direction, or the BIOS and iLO Secure Boot databases desynchronise.
- **iLO 6 1.62 added `DELETE` on certificates in the read-only Default databases.** Deleting entries from `dbDefault` or `KEKDefault` silently degrades the very defaults remediation depends on.
- **Option ROM failures are OS-independent and look like missing hardware.** A card with a 2023-signed option ROM in a system without `Option ROM UEFI CA 2023` will not initialise and **disappears from RBSU** — it presents as a missing PCIe device, not a boot error.

---

## ESXi hosts

### Trust chain

```
Firmware db  (MS Corporation UEFI CA 2011  →  + Microsoft UEFI CA 2023)
  └─ ESX boot shim / bootloader        ← the ONLY Microsoft-dependent link
       └─ VMware public key (embedded in the bootloader)
            ├─ vmkernel
            └─ secure boot VIB verifier
                 └─ every installed VIB   ← "VMware Secure Boot Signing", valid to 2037-10
```

ESXi sits in the same third-party trust bucket as Linux shim, not the Windows PCA bucket.

### Multi-signed builds

| Release | Date | Build | Multi-signed |
|---|---|---|---|
| ESX 9.1.0.0 | 2026-05-12 | `25370933` | ✅ |
| ESXi 8.0 U3j (P09) | 2026-05-27 | `25429389` | ✅ |
| ESXi 8.0 U3i (P08) | 2026-02-24 | `25205845` | ❌ |
| ESX 9.0.2 | 2026-01-20 | `25148076` | ❌ |
| ESXi 7.0 U3w (last 7.0) | 2025-07-15 | `24784741` | ❌ never — EOGS 2025-10-02 |

From the 8.0 U3j release notes:

> "The expiration of the 2011 certificates only prevents Microsoft from creating **new signatures** with them; it does not invalidate existing signatures created prior to the expiration. Therefore, **any version of ESXi that can Secure Boot on a host machine before the expiration can still do so afterward**, unless you actively remove the expired certificate from the machine's firmware, which is not generally recommended."

Multi-signing is forward-compatibility insurance, not a fix for a live outage. For vSphere 7 estates it is a concrete upgrade driver — no 2023-signed bootloader will ship.

### The one action that bricks a host

Removing `Microsoft Corporation UEFI CA 2011` from `db`, or pushing it to `dbx`. Broadcom KB 434297:

> "the Microsoft Corporation UEFI CA 2011 is used to validate a wide range of pre-boot components beyond the OS bootloader. This includes, but is not limited to, firmware for hardware components such as **RAID controllers, NICs, and HBAs** … **Revoking this certificate without fully understanding its usage may result in an unbootable system.**"

Any tooling you build should refuse to do this by default. Recovery requires physical or iLO console access.

### TPM — the real operational risk

From vSphere 7.0 U2 onward the ESXi configuration is sealed against a PCR policy that checks Secure Boot is still enabled. A key reset turns Secure Boot off, so the host boots to a PSOD: *"Unable to restore the system configuration. A security violation was detected."*

```sh
# BEFORE any firmware work — store the recovery key OFF-HOST
esxcli system settings encryption get
esxcli system settings encryption recovery list
vim-cmd /hostsvc/firmware/sync_config
vim-cmd /hostsvc/firmware/backup_config

# Recovery at boot: press SHIFT+O, append after bootUUID=... a space and:
#   encryptionRecoveryKey=######-######-######-...

# AFTER a successful boot — otherwise the state is not re-sealed
esxcli system settings encryption set --mode=TPM
/sbin/auto-backup.sh
```

Broadcom KB 316424 is explicit: *"Configuration backups alone are insufficient for recovery"* — without the encryption recovery key the only path is a complete rebuild.

Other documented causes of the same PSOD: TPM or system board replaced, TPM 2.0 disabled in firmware, `execInstalledOnly` flipped, BIOS date/time reset (dead CMOS battery).

### `secureBoot.py` is not a readiness test

```sh
/usr/lib/vmware/secureboot/bin/secureBoot.py -s   # Enabled / Disabled
/usr/lib/vmware/secureboot/bin/secureBoot.py -c   # VIB signatures, NOT certificates
esxcli hardware trustedboot get
esxcli system settings encryption get
```

Broadcom states it directly: *"This script does not check for an up-to-date bootloader."* It validates VIB signatures, tardisks and acceptance levels. It tells you nothing about which CA signed your bootloader or what is in the firmware `db`.

ESXi exposes no `efivars`, no `mokutil` equivalent, and no esxcli namespace for UEFI Secure Boot variables. Certificate enumeration has to go through the BMC — see [HPE ProLiant](#hpe-proliant).

### vLCM has no compliance check

vSphere Lifecycle Manager and hardware support managers (HPE OneView for vCenter, Dell OMIVV, Lenovo XCC) apply vendor firmware add-ons, but there is **no compliance check, no drift detection, and no reporting** for Secure Boot certificate state. The 2023 certificates ride along only as a side effect of the System ROM payload.

**Cluster compliance can read fully green while every host still has a 2011-only `db`.**

Broadcom's promised *"comprehensive solution … to ensure firmware readiness during the vSphere lifecycle"* (KB 434297) had not shipped as of VCF 9.1.0.0200 (2026-07-13).

---

## Virtual machines

### How VM Secure Boot works

A VM's Secure Boot variables live in the per-VM `<vm>.nvram` file, seeded **once** — at NVRAM creation — from the EFI firmware image of the host that created it.

**Patching the host does not re-seed existing VMs. Neither does a virtual hardware version upgrade.** Any blog claiming "upgrade the HW version to get the 2023 certificates" is wrong; defaults are written at NVRAM creation, and a `vmx-XX` bump changes the hardware definition, not the existing variable store.

### The VMware PK

The PK on VMs created before ESXi 9.0 is **not expired — it is NULL**. `VMW.NULLPK` is a placeholder with a NULL signature: no X.509, no private key, no expiry date. The expired *"VMware Certificate"* (Dec 2019) that circulates in blog posts sits in `db` and is inert; conflating the two is the most common error in third-party writeups.

What NULL PK actually causes:

1. UEFI requires the KEK update payload to be authenticated by the PK. With no valid PK, the KEK update is rejected and the VM never gains `Microsoft Corporation KEK 2K CA 2023`.
2. `db`/`dbx` updates must in turn be authenticated by a valid KEK. The only KEK present is the 2011 one, expired since 2026-06-24. **All future `db` and `dbx` servicing is therefore dead.**

Windows reports this as **Event ID 1803**. On vSphere, "OEM" in that message means Broadcom.

### Decision matrix

Per Broadcom [KB 423893](https://knowledge.broadcom.com/external/article/423893/secure-boot-certificate-expirations-and.html). All paths require **HW version 14+**.

| VM origin / host | PK | KEK / db | Risk | Action |
|---|---|---|---|---|
| ESXi < 8.0 U2, or HW 13 | `VMW.NULLPK` | 2011 only | **HIGH** | Upgrade HW to 14+, host to U3j+; or manual vUEFI enrolment (KB 423919) |
| ESXi 8.0 U2 – U3i, HW 14+ | `VMW.NULLPK` | 2023 present | **MEDIUM** | Boots fine but will never receive DBX revocations. Patch host to U3j+ → SilentPK |
| Host 8.0 U3j+, no vTPM | SilentPK adds it | 2023 | **LOW** | Zero-touch: power-cycle the VM |
| Host U3j+, vTPM, non-Windows | VMX `resetOnce` | 2023 | MEDIUM | `uefi.secureBoot.PK.resetOnce = "TRUE"` on the powered-off VM |
| Host U3j+, vTPM, Windows | — | — | MEDIUM | **Broadcom recommends waiting** for the capsule solution |
| ESX 9.x | Windows OEM Devices PK | 2023 | **LOW** | New VMs correct from creation |

Note the nuance most writeups miss: on ESXi 8.0 U2 through U3i the VM **already has** the 2023 KEK and db certificates as factory defaults — it simply cannot *update* them. The genuinely exposed population is VMs whose NVRAM was created on ESXi 7.x, 8.0, 8.0 U1, or at HW 13.

### Hardware version thresholds

| Version | Meaning |
|---|---|
| HW 13 | Minimum for Secure Boot at all |
| **HW 14+** | Hard requirement for **any** PK update — all four Broadcom methods |
| **HW 20+** | Practical recommendation: enough EFI variable storage for the enlarged DBX. Below this, expect Event 1796 / `0x80070008` |

### Do not delete or rename `.nvram`

Broadcom **withdrew** this guidance. KB 423919 replaced KB 421593 explicitly *"to avoid suggestions of deleting NVRAM, as that behavior can lead to unexpected corruptions of the associated VM."* A Broadcom employee confirmed in the community forums that it is not endorsed by VMware engineering and not supported, and there is at least one field report of it causing a boot failure.

The cost, beyond that: loss of EFI boot entries and boot order, RTC drift, and — decisively — **destruction of vTPM state**, because vTPM data is stored in the NVRAM file. On a BitLocker or LUKS-protected VM that is irreversible key loss.

### vTPM VMs

- Any `db`/`KEK`/`PK` write changes **PCR 7**, breaking BitLocker TPM-only unseal, TPM-bound LUKS, and Measured Boot attestation.
- vTPM uses VM Encryption underneath and requires a configured key provider. If the key provider is unavailable the VM will not power on at all — verify key provider health *before* touching Secure Boot.
- Broadcom's own warning: updating these from outside the guest *"carries the risk of breaking applications (such as triggering BitLocker recovery) for vTPM-enabled VMs, as it alters Secure Boot variables and vTPM measurements without the OS's awareness."*

Pre-flight:

```powershell
# 1. Get recovery keys OUT of the VM first
(Get-BitLockerVolume -MountPoint "C:").KeyProtector |
    Where-Object KeyProtectorType -eq 'RecoveryPassword'

# 2. Suspend across the whole reboot chain
Suspend-BitLocker -MountPoint "C:" -RebootCount 2

# 3. Verify afterwards
Get-BitLockerVolume -MountPoint "C:" | Select MountPoint, ProtectionStatus
```

Take a powered-off, no-memory, no-quiesce snapshot first.

### Inventory

```powershell
Connect-VIServer vcsa01
.\scripts\VMware-SecureBootAudit.ps1 -OutputCsv .\vmware-audit.csv |
    Where-Object Risk -in 'HIGH','MEDIUM' |
    Format-Table Name,HWVersion,vTPM,HostBuild,Risk,Action -AutoSize
```

There is **no vSphere API to read the contents of a VM's NVRAM Secure Boot databases.** In-guest checking via `Invoke-VMScript` is the only reliable verification — use `-IncludeGuestCheck -GuestCredential`.

---

## Windows in-guest servicing

Works on physical HPE servers and in VMs alike, provided a valid PK and KEK exist. On a VM with `VMW.NULLPK` it fails reliably at Event 1803.

```powershell
# 0x5944 = all four 2023 CAs + KEK + 2023-signed boot manager
reg add HKLM\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x5944 /f
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
```

### Bitmask progression

`0x5944` → `0x5904` → `0x5104` → `0x4104` → *(reboot)* → `0x4100` → **`0x4000` = complete**

| Bit | Action |
|---|---|
| `0x0004` | Apply OEM PK-signed KEK 2023 |
| `0x0040` | Add `Windows UEFI CA 2023` to db |
| `0x0100` | Install boot manager signed by `Windows UEFI CA 2023` |
| `0x0800` | Add `Microsoft Option ROM UEFI CA 2023` (conditional) |
| `0x1000` | Add `Microsoft UEFI CA 2023` (conditional) |
| `0x4000` | Modifier gating the conditional behaviour — **remains set after completion** |

> **`0x4000` means done, not pending.** A naive `-ne 0` check reports every successfully updated machine as failed. Assert on `UEFICA2023Status -eq 'Updated'` instead.

The scheduled task runs at startup and every 12 hours. Budget roughly 48 hours and at least one restart in production.

### Status

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' |
    Select UEFICA2023Status, UEFICA2023Error, WindowsUEFICA2023Capable

Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' |
    Select AvailableUpdates, HighConfidenceOptOut, MicrosoftUpdateManagedOptIn
```

| Value | Meaning |
|---|---|
| `UEFICA2023Status` | `NotStarted` → `InProgress` → **`Updated`** |
| `WindowsUEFICA2023Capable` | `0` not in db · `1` in db · `2` in db and running the 2023 boot manager |
| `HighConfidenceOptOut` | Absent or `0` = opted **in** (automatic LCU-driven deployment is the default for eligible devices) |
| `MicrosoftUpdateManagedOptIn` | Absent or `0` = opted out of Microsoft-managed CFR |

Do not mix deployment methods on the same device.

### Event IDs — source `TPM-WMI`, log `System`

| ID | Meaning | Response |
|---|---|---|
| **1808** | Success — all certificates and boot manager applied | Done |
| 1801 | Certificates staged but not applied to firmware | Reboot, re-run the task |
| 1800 | Reboot required before proceeding | Not an error |
| 1032 | Blocked by BitLocker configuration | `manage-bde -protectors -disable C: -RebootCount 2` |
| 1795 | Firmware returned an error on variable write | Physical: BIOS update. VM: HW version / NVRAM capacity |
| 1797 | `Windows UEFI CA 2023` not yet in db — blocks the dbx step | Complete the db step first |
| 1802 | Deliberately blocked by Microsoft (known firmware issue) | **No manual override exists.** Wait for the bucket to unblock |
| **1803** | No PK-signed KEK payload available | Physical: escalate to OEM. **vSphere VM: `VMW.NULLPK`** — fix from the hypervisor side |

### Verification traps

- `Get-AuthenticodeSignature` on `bootmgfw.efi` reads only the catalog (2011) signature and hides the dual-signed embedded 2023 certificate. Use `Get-PfxCertificate -FilePath "S:\EFI\Microsoft\Boot\bootmgfw.efi" | fl Subject,Issuer`.
- `C:\Windows\Boot\EFI\bootmgfw.efi` staying 2011-signed is **by design** — it is the `bcdboot` repair template, not the active loader.
- `Confirm-SecureBootUEFI` **throws** rather than returning `$false` on non-UEFI systems. Wrap it, and fall back to `HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled`.

### Boot media

WinPE, recovery and imaging media signed only by `Microsoft Windows Production PCA 2011` will stop receiving updates after 2026-10-19 and will not boot on 2023-only-`db` machines. Rebuild WinPE, backup rescue ISOs and PXE boot images.

---

## Linux guests

`shim` is the only component signed by `Microsoft Corporation UEFI CA 2011`. Expiry does not unsign existing shims — the break arrives with the **next shim respin**, driven by a CVE. In July 2026 eleven older Microsoft-signed shims were found to be bypassable, which raises the odds of a forced respin plus DBX revocations that NULL-PK VMs cannot receive.

| Distribution | Status |
|---|---|
| RHEL 9 / 10 x86_64 | Dual-signed (2011 + 2023) since May 2026 |
| RHEL 8 x86_64 | Dual-signed since June 2026 |
| RHEL 9.7 aarch64 | **2023-only** |
| AlmaLinux x86_64 | Dual-signed |
| AlmaLinux aarch64 | **2023-only** |

```bash
mokutil --sb-state
mokutil --pk                              # empty on a vSphere VM = VMW.NULLPK
mokutil --db  | grep -i 'UEFI CA 2023'
mokutil --kek | grep -i 'KEK 2K CA 2023'
sudo fwupdmgr refresh && sudo fwupdmgr update    # requires fwupd >= 2.0.8
```

Two caveats:

- In-guest `fwupd` still needs a working KEK chain, so a `VMW.NULLPK` VM hits the same wall as Windows.
- Broadcom notes that `fwupd` **does not install** `Microsoft Option ROM UEFI CA 2023`. Import it manually via vUEFI or VMX before upgrading passthrough device firmware, or the device will stop initialising.

Adding the 2023 CA to `db` is purely additive — the 2011 certificate stays and dual-signed shims validate either way. The risk is not boot; it is the **PCR 7 change** breaking TPM-sealed LUKS. Re-seal before rebooting.

---

## Rollout order

1. **Audit both sides.** Classify by verdict and risk before changing anything.
2. **Escrow recovery material.** ESXi TPM recovery keys off-host; BitLocker recovery passwords out of the VMs.
3. **vCenter → ESXi hosts** to 8.0 U3j (`25429389`) or ESX 9.1 (`25370933`).
4. **HPE System ROM** (any 2026 SPP) in batches.
5. **Key reset + re-enable Secure Boot** in a maintenance window — three reboots per server.
6. **Power-cycle VMs** so SilentPK applies the PK.
7. **Windows in-guest servicing** — `AvailableUpdates = 0x5944`, run the task, confirm Event 1808.
8. **Re-audit** and close out before **2026-10-19**.

Priority order if resources are limited: golden images and template pipelines first (that is where breakage actually originates), then anything that must receive future DBX revocations, then the long tail.
