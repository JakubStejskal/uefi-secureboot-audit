# Mock iLO Redfish endpoint

Regression harness for `HPE-SecureBootAudit.ps1` and `HPE-SecureBootRemediate.ps1`.
Mimics the iLO 6 / iLO 7 behaviour that broke v2.0: member links end with `/`, a `//` in
the path returns 404, certificate collection members carry only `@odata.id`.

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -days 1 -subj /CN=ilo
port=8441
for sc in gen11 gen12 legacy2011 sboff nodb partial oldrom; do
  python3 -I mock_ilo.py $port $sc c.pem k.pem 2>log_$sc.txt &
  port=$((port+1))
done
```

```powershell
# PowerShell 7 (the mock uses a self-signed certificate)
$c = [pscredential]::new('a', (ConvertTo-SecureString x -AsPlainText -Force))
$h = 8441..8447 | ForEach-Object { "127.0.0.1:$_" }
../../scripts/HPE-SecureBootAudit.ps1 -ILOHost $h -Credential $c -SkipCertificateCheck |
    Format-Table ILOHost,Generation,RomStatus,SecureBootActive,CertInventory,DbCounts,Verdict
```

Expected verdicts:

| Port | Scenario | Verdict |
|---|---|---|
| 8441 | `gen11` – DL320 Gen11, live data from 2026-10-27 | `COMPLIANT` |
| 8442 | `gen12` – DL380 Gen12, live data from 2026-10-27 | `COMPLIANT` |
| 8443 | `legacy2011` – ROM OK, keys never reset | `NEEDS_KEY_RESET` |
| 8444 | `sboff` – certificates OK, PK wiped (SetupMode) | `CERTS_OK_SECUREBOOT_OFF` |
| 8445 | `nodb` – no `SecureBootDatabases` | `ROM_OK_CERTS_UNKNOWN` |
| 8446 | `partial` – one `db` certificate unreadable | `ROM_OK_CERTS_UNKNOWN` |
| 8447 | `oldrom` – ROM below baseline, 2011-only keys | `NEEDS_ROM_AND_RESET` |

The v2.0 script returns `ROM_OK_CERTS_UNKNOWN` for 8441 and `COMPLIANT` (without data) for
8442 – the behaviour observed on live hardware.
