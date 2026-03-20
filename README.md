# UEFI MS CA 2011 Expiry / Secure Boot Audit
**Status:** Active

## Kontext

Audit a náprava expirace Microsoft UEFI CA 2011 certifikátů v HPE fleet (Secure Boot).  
KBs: **KB423893**, **KB423919**, **KB421593**, **KB424429**  
Zdroje: Broadcom TAM session 5. 2. 2026, HPE TAM Slack (Scott Wiginton, derek.lin2)

---

## Skripty

| Soubor | Jazyk | Popis |
|--------|-------|-------|
| `hpe-secureboot-audit-v2.sh` | Bash | Hlavní auditní script — OneView discovery nebo static file, iLO 5/6/7, SSO, CSV report, optional reset |
| `Check-SecureBoot-OneView.ps1` | PowerShell | OneView → SSO → iLO Redfish audit + optional reset, PS 5.1 i PS 7+ |
| `list-ilo5-uefi-certs.py` | Python | Výpis UEFI `db`/`KEK` certifikátů přes iLO5 Redfish (read-only) |
| `Check-SecureBootiLO.ps1` | PowerShell | Přímá kontrola Secure Boot přes iLO credentials (bez OneView), PS 5.1 i PS 7+ |
| `Inventory-SecureBootVMs.ps1` | PowerShell | Inventura VM Secure Boot nastavení přes PowerCLI/vCenter |

---

## Použití: hpe-secureboot-audit-v2.sh

```bash
# Inventura celého fleetu přes OneView (SSO, bez iLO hesel)
./hpe-secureboot-audit-v2.sh --ov-host ov.lab.local

# Filtrovat pouze DL380 servery
./hpe-secureboot-audit-v2.sh --ov-host ov.lab.local --filter-name DL380

# Dry-run — zobraz co by bylo resetováno, ale neprováděj
./hpe-secureboot-audit-v2.sh --ov-host ov.lab.local --reset --dry-run

# Skutečný reset (kde chybí 2023 certy)
./hpe-secureboot-audit-v2.sh --ov-host ov.lab.local --reset

# Bez OneView — statický seznam iLO IP adres, manuální credentials
./hpe-secureboot-audit-v2.sh --servers ilo_list.txt --auth manual \
    --ilo-user Administrator --csv report.csv

# Verbose debug výstup
./hpe-secureboot-audit-v2.sh --ov-host ov.lab.local --verbose
```

**Formát `ilo_list.txt`:**
```
# komentáře ignorovány
10.3.18.50
server-name|10.3.18.51
server-name|10.3.18.52|server-hw-uuid
```

**CSV výstup obsahuje:** ServerName, iLO_IP, iLO_Generation, AuthSource, SecureBootEnabled, SecureBootMode, db_Has2023Cert, KEK_Has2023Cert, db_Subjects, KEK_Subjects, Error

---

## Použití: Check-SecureBoot-OneView.ps1

```powershell
# Inventura všech serverů
$cred = Get-Credential
.\Check-SecureBoot-OneView.ps1 -OneViewAddress 'ov.lab.local' -OVCredential $cred

# Export do CSV
.\Check-SecureBoot-OneView.ps1 -OneViewAddress 'ov.lab.local' -OVCredential $cred `
    -ExportCsv 'C:\sb_report.csv'

# Filtrovat jen DL360
.\Check-SecureBoot-OneView.ps1 -OneViewAddress 'ov.lab.local' -OVCredential $cred `
    -ServerFilter 'DL360*'

# Dry-run reset
.\Check-SecureBoot-OneView.ps1 -OneViewAddress 'ov.lab.local' -OVCredential $cred `
    -ResetKeysOnMissing -WhatIf

# Skutečný reset (s potvrzením pro každý server)
.\Check-SecureBoot-OneView.ps1 -OneViewAddress 'ov.lab.local' -OVCredential $cred `
    -ResetKeysOnMissing
```

**Požadavky:**
```powershell
# Nainstalovat aktuální HPEOneView modul
Find-Module HPEOneView.* | Sort-Object Version -Desc | Select -First 1 | Install-Module
```

**Kompatibilita:**
- PS 5.1 — automaticky používá `TrustAllCertsPolicy` (iLO self-signed cert)
- PS 7+ — používá nativní `-SkipCertificateCheck`

---

## Použití: Check-SecureBootiLO.ps1

```powershell
# Jeden server — přímé iLO credentials
$cred = Get-Credential
.\Check-SecureBootiLO.ps1 -IloHost '10.3.18.50' -IloCredential $cred

# Více serverů najednou
.\Check-SecureBootiLO.ps1 -IloHost '10.3.18.50','10.3.18.51','10.3.18.52' -IloCredential $cred

# Ze souboru (formát: name|ip nebo jen ip)
.\Check-SecureBootiLO.ps1 -HostsFile 'ilo_hosts.txt' -IloCredential $cred

# Export do CSV
.\Check-SecureBootiLO.ps1 -HostsFile 'ilo_hosts.txt' -IloCredential $cred `
    -ExportCsv 'C:\sb_direct.csv'

# Dry-run reset (zobraz co by bylo resetováno)
.\Check-SecureBootiLO.ps1 -IloHost '10.3.18.50' -IloCredential $cred `
    -ResetKeysOnMissing -WhatIf

# Skutečný reset
.\Check-SecureBootiLO.ps1 -IloHost '10.3.18.50' -IloCredential $cred `
    -ResetKeysOnMissing
```

**Formát `ilo_hosts.txt`:**
```
# komentáře ignorovány
10.3.18.50
server-name|10.3.18.51
```

**Poznámky:**
- Nevyžaduje OneView — vhodné pro standalone servery nebo prostředí bez OV
- Detekuje KEK_2023 a DB_2023 certifikáty
- PS 5.1 kompatibilní (TrustAllCertsPolicy)
- Session management: POST SessionService → DELETE po dokončení

---

## Použití: list-ilo5-uefi-certs.py (read-only)

```bash
# Jeden host — text výstup
export ILO_PASSWORD='heslo'
python3 list-ilo5-uefi-certs.py --host 10.3.18.50 --user Administrator

# Hromadně ze souboru → CSV
python3 list-ilo5-uefi-certs.py \
  --hosts-file ilo-hosts.txt --user Administrator --csv uefi-certs.csv

# Pouze KEK a db databáze, JSON výstup
python3 list-ilo5-uefi-certs.py \
  --host ilo-gen10-01 --user Administrator \
  --databases KEK,db --json | jq '.[] | .databases[] | .certificates[] | .subject_cn'
```

> Pokud iLO5/ROM neexponuje `SecureBootDatabases`, skript vrátí stav `unsupported` —
> očekávané chování na části Gen10 serverů se starším ROM.

---

## Použití: Inventory-SecureBootVMs.ps1

```powershell
# Inventura všech VM ve vCenter
$vcCred = Get-Credential
.\Inventory-SecureBootVMs.ps1 -VCenterServer 'vcenter.lab.local' -Credential $vcCred

# Filtrovat jen konkrétní cluster
.\Inventory-SecureBootVMs.ps1 -VCenterServer 'vcenter.lab.local' -Credential $vcCred `
    -Cluster 'Tanzu-Cluster-01'

# Filtrovat jen konkrétní datacenter
.\Inventory-SecureBootVMs.ps1 -VCenterServer 'vcenter.lab.local' -Credential $vcCred `
    -Datacenter 'Prague-DC'

# Filtrovat VM podle jména (wildcard)
.\Inventory-SecureBootVMs.ps1 -VCenterServer 'vcenter.lab.local' -Credential $vcCred `
    -VMFilter 'tkc-*'

# Zobrazit pouze VM kde Secure Boot NENÍ zapnuto
.\Inventory-SecureBootVMs.ps1 -VCenterServer 'vcenter.lab.local' -Credential $vcCred `
    -ShowOnlyNoSecureBoot

# Export do CSV
.\Inventory-SecureBootVMs.ps1 -VCenterServer 'vcenter.lab.local' -Credential $vcCred `
    -ExportCsv 'C:\vm_sb_inventory.csv'
```

**Požadavky:**
```powershell
Install-Module VMware.PowerCLI
```

**Co script kontroluje:**
- Firmware typ (EFI vs BIOS)
- `EfiSecureBootEnabled` flag
- Hardware version (vmx-XX)
- Guest OS typ
- **Souhrn:** počty EFI+SB ON / EFI+SB OFF / BIOS (bez SB)

---

## Technické detaily

### Redfish Secure Boot Reset
```
POST /redfish/v1/Systems/1/SecureBoot/Actions/SecureBoot.ResetKeys/
Body: {"ResetKeysType":"ResetAllKeysToDefault"}
```
**Po resetu nutný cold reboot!**

### iLO generace a omezení

| iLO | SecureBootDatabases | SSO metoda |
|-----|---------------------|------------|
| iLO 5 (Gen10) | Pouze s dostatečně novým ROM | `SSOToken` přímo jako `X-Auth-Token` (LoginToken POST nepodporován) |
| iLO 6 (Gen11) | ✅ Plná podpora | LoginToken session POST nebo přímý SSOToken |
| iLO 7 (Gen12) | ✅ Plná podpora | LoginToken session POST nebo přímý SSOToken |

### Min. verze BIOS pro Reset Keys
| Generace | Min. ROM verze |
|----------|----------------|
| Gen10 (DL/ML) | 3.40_01-16-2025 + Reset Keys |
| Gen10 Plus    | 2.30_01-16-2025 |
| Gen11         | 2.42_12-06-2024 |

### PowerShell gotchas
- `-SkipCertificateCheck` je pouze PS 6+ — v PS 5.1 nutná `TrustAllCertsPolicy` (viz skripty)
- `-ResponseHeadersVariable` je pouze PS 7+ — v PS 5.1 použít `$resp.Headers['X-Auth-Token']`
- `$host` je rezervovaná proměnná — vždy přejmenovat na `$iloHost` nebo podobně
