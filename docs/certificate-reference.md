# Certificate reference

State as of **2026-08-04**. SHA-1 thumbprints computed from the DER files Microsoft distributes via `go.microsoft.com/fwlink`.

## Expiring 2011 CAs

| CN | Database | Expires | SHA-1 thumbprint |
|---|---|---|---|
| `Microsoft Corporation KEK CA 2011` | KEK | **2026-06-24** 20:51:29Z | `31590BFD89C9D74ED087DFAC66334B3931254B30` |
| `Microsoft Corporation UEFI CA 2011` | db | **2026-06-27** 21:32:45Z | `46DEF63B5CE61CF8BA0DE2E6639C1019D0ED14F3` |
| `Microsoft Windows Production PCA 2011` | db | **2026-10-19** 18:51:42Z | `580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D` |

## 2023 replacements

| CN | Database | Expires | SHA-1 thumbprint |
|---|---|---|---|
| `Microsoft Corporation KEK 2K CA 2023` | KEK | 2038-03-02 | `459AB6FB5E284D272D5E3E6ABC8ED663829D632B` |
| `Windows UEFI CA 2023` | db | **2035-06-13** | `45A0FA32604773C82433C3B7D59E7466B3AC0C67` |
| `Microsoft UEFI CA 2023` | db | 2038-06-13 | `B5EEB4A6706048073F0ED296E7F580A790B59EAA` |
| `Microsoft Option ROM UEFI CA 2023` | db | 2038-10-26 | `3FB39E2B8BD183BF9E4594E72183CA60AFCD4277` |

Microsoft SignatureOwner GUID for all of the above: `77fa9abd-0359-4d32-bd60-28f4e78f784b`

## Three things that catch people out

**1. The naming trap.** Microsoft's KB tables write *"Microsoft UEFI CA 2011"*, but the actual X.509 CN is **`Microsoft Corporation UEFI CA 2011`**. Match on CN or thumbprint in scripts, never on the string from the KB article.

**2. One 2011 CA became two 2023 CAs.** The third-party CA was split so a platform can trust signed option ROMs without trusting third-party bootloaders. Check for **four** certificates, not three — `Microsoft Option ROM UEFI CA 2023` is separate and is the one most often missing, because it landed in vendor firmware later than the other three.

**3. `Windows UEFI CA 2023` is a 12-year certificate.** It expires in **2035**; the other three run to 2038. Plan the next rotation for 2035.

## Platform Key

No PK expires in this event. The Microsoft-managed PK is `CN=Windows OEM Devices PK`, valid 2023-09-21 → 2038-09-18, thumbprint `3D8660C0CB2D57B189C3D7995572A552F75E48B5`.

The PK still matters operationally: the KEK update payload must be signed by *the device's own PK*. If the OEM never produced a PK-signed KEK-2023 payload, KEK enrolment is permanently blocked (Windows Event ID **1803**), with no OS-side workaround.

On vSphere, VMs created on ESXi before 9.0 carry `VMW.NULLPK` — a placeholder with a NULL signature — which blocks KEK authorisation entirely. See the [runbook](runbook.md#virtual-machines).

## HPE platform-default inventory (observed live)

Read through iLO Redfish (`/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/{PK|KEK|db|dbx}/Certificates/`) on **2026-10-27**:

| Platform | iLO | System ROM |
|---|---|---|
| ProLiant DL320 Gen11 | iLO 6 | U63 v2.80 (01/29/2026) |
| ProLiant Compute DL380 Gen12 | iLO 7 | U68 v1.52 (10/03/2025) |

Both servers returned the **same** live certificate set (PK = 1, KEK = 3, db = 8, dbx = 3 certificates):

| Database | CN | Expires |
|---|---|---|
| PK | `HPE UEFI Secure Boot 2016 PK Key` | 2031-01-30 |
| KEK | `HPE UEFI Secure Boot 2016 KEK Key` | 2031-01-30 |
| KEK | `Microsoft Corporation KEK CA 2011` | 2026-06-24 |
| KEK | `Microsoft Corporation KEK 2K CA 2023` | 2038-03-02 |
| db | `HP UEFI Secure Boot 2013 DB key` | 2033-08-23 |
| db | `HPE UEFI Secure Boot 2016 DB Key` | 2031-01-30 |
| db | `Microsoft Corporation UEFI CA 2011` | 2026-06-27 |
| db | `Microsoft Windows Production PCA 2011` | 2026-10-19 |
| db | `Microsoft UEFI CA 2023` | 2038-06-13 |
| db | `Microsoft Option ROM UEFI CA 2023` | 2038-10-26 |
| db | `Windows UEFI CA 2023` | 2035-06-13 |
| db | **`VMware Secure Boot Signing`** | 2037-10-19 |
| dbx | `Canonical Ltd. Secure Boot Signing`, `Virtual UEFI SubCA`, `Debian Secure Boot Signer` | — |

Notes:

- The 2011 CAs are still present next to the 2023 ones, as intended — see [do not remove the 2011 CA](runbook.md#what-actually-breaks).
- `dbx` mostly holds SHA-256 hashes (`.../dbx/Signatures`); the scripts read only its certificate entries.
- Members of the `Certificates` collections contain only `@odata.id`; `$expand` is not honoured, so each certificate is fetched individually.
- `VMware Secure Boot Signing` is a platform-default `db` entry on both generations. The runbook names the same CN as the signer of ESXi VIBs. Whether the ESXi *bootloader* on these platforms is trusted through this entry instead of the Microsoft third-party CA has **not been verified** — do not read a lower host risk out of it until the Authenticode signer chain of the ESXi boot files has been checked.

## Signature owner GUIDs for manual enrolment

| Vendor | GUID |
|---|---|
| Microsoft | `77fa9abd-0359-4d32-bd60-28f4e78f784b` |
| HPE | `F5A96B31-DBA0-4faa-A42A-7A0C9832768E` |
| SUSE | `2879c886-57ee-45cc-b126-f92f24f906b9` |

## Verification snippets

**Windows** — `-Decoded` was added in KB5093574 (April 2026 CU and later) and is still absent from the online cmdlet reference, so feature-detect rather than assume:

```powershell
$hasDecoded = (Get-Command Get-SecureBootUEFI).Parameters.ContainsKey('Decoded')

Get-SecureBootUEFI -Name db  -Decoded
Get-SecureBootUEFI -Name KEK -Decoded
```

Fallback for older builds:

```powershell
[Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).Bytes)  -match 'Microsoft Option ROM UEFI CA 2023'
[Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek).Bytes) -match 'Microsoft Corporation KEK 2K CA 2023'
```

This substring match works because the CN is a DER PrintableString, but it gives you no expiry date, no thumbprint, and cannot distinguish `db` from `dbx`. Adequate for a boolean remediation check; not adequate for an expiry audit.

**Linux:**

```bash
mokutil --sb-state
mokutil --pk                              # empty output on a vSphere VM = VMW.NULLPK
mokutil --db  | grep -i 'UEFI CA 2023'
mokutil --kek | grep -i 'KEK 2K CA 2023'

# Raw variables — strip the 4-byte attribute prefix before parsing the ESL
tail -c +5 /sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f > db.esl
```

**HPE Embedded UEFI Shell** — the only out-of-band option on servers with iLO 5:

```
secboot -l KEK
secboot -l db
```
