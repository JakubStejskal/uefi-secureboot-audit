# UEFI MS CA 2011 Expiry / Secure Boot Audit
# Status: Active (deadline June–October 2026)

## Kontext

Claude.ai projekt "UEFI MS CA 2011 exipiry"
Vytvořeno: 2026-03-09
Cíl: Expert skripty pro audit a nápravu expirace UEFI MS CA 2011 certifikátů v HPE fleet

## Persona (Claude project prompt)

Specialist on Enterprise Infrastructure & UEFI Security
- Expert na UEFI Secure Boot, PKI, HPE iLO/Redfish, Dell iDRAC
- PowerShell & Python jako primární jazyky
- Safety-first: vždy upozornit na rizika před zápisem do NVRAM / aktualizací firmwaru
- Modularita: try-catch, detailní logging
- Edge cases: iLO nedostupné, Secure Boot zakázán, custom cert v DB

## Termíny

- Deadline: červen–říjen 2026
- KBs: KB423893, KB423919, KB421593, KB424429

## Skripty

- `Check-SecureBootiLO.ps1` — PS kontrola Secure Boot stavu přes iLO
- `Inventory-SecureBootVMs.ps1` — inventura VM Secure Boot nastavení
- `Check-SecureBoot-OneView.ps1` — OV discovery → iLO SSO → optional reset
- `hpe-secureboot-audit-v2.sh` — Bash: SSO fix, iLO 5/6/7 cert parsing, --filter-name, --reset/--dry-run, CSV output
- `list-ilo5-uefi-certs.py` — Python: výpis UEFI `db`/`dbDefault` a `KEK`/`KEKDefault` certifikátů přes iLO5 Redfish

## Technické detaily

### Redfish Secure Boot Reset
```
POST /redfish/v1/Systems/1/SecureBoot/Actions/SecureBoot.ResetKeys/
Body: {"ResetKeysType":"ResetAllKeysToDefault"}
```
Po resetu nutný cold reboot!

### Omezení
- `SecureBootDatabases` endpoint: iLO 6/Gen11+ nebo iLO 5 s dostatečně novým ROM
- iLO 5 (starší): SSO přes `SSOToken` jako `X-Auth-Token` header (ne LoginToken)
- `-ResponseHeadersVariable`: pouze PowerShell 7+; v PS 5.1 použít `$resp.Headers['X-Auth-Token']`

## Použití: výpis UEFI CA / KEK přes iLO5

Výchozí dotazované databáze:
- `KEK`
- `KEKDefault`
- `db`
- `dbDefault`

Příklad:

```bash
export ILO_PASSWORD='tajneheslo'
python3 ./list-ilo5-uefi-certs.py \
  --host 10.10.10.25 \
  --user Administrator
```

Více iLO najednou:

```bash
python3 ./list-ilo5-uefi-certs.py \
  --hosts-file ./ilo-hosts.txt \
  --user Administrator \
  --csv ./uefi-certs.csv
```

JSON výstup:

```bash
python3 ./list-ilo5-uefi-certs.py \
  --host ilo-gen10-01 \
  --user Administrator \
  --json
```

Poznámka:
- Pokud iLO5/ROM neexponuje `SecureBootDatabases`, skript vrátí stav `unsupported`. To je očekávané chování na části Gen10 serverů se starším firmware/ROM.
