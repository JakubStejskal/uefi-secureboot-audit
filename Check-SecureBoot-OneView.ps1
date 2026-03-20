#Requires -Version 5.1
<#
.SYNOPSIS
    OneView + iLO Redfish – UEFI CA 2023 Secure Boot Inventory & Remediation

.DESCRIPTION
    Flow:
      1. Pripojeni na OneView (Connect-OVMgmt)
      2. Get-OVServer -> pro kazdy server vycte iLO IP z mpHostInfo
      3. Get-OVIloSso -> ziska SSO X-Auth-Token (bez nutnosti iLO hesla)
      4. Redfish GET na /SecureBoot + /SecureBootDatabases/db/Certificates
      5. Vyhodnoceni: 2011-only, 2023 pritomny, chybejici, neznamy
      6. Volitelne: POST SecureBoot.ResetKeys -> ResetAllKeysToDefault
      7. Export CSV reportu

.PARAMETER OneViewAddress
    IP nebo FQDN OneView Appliance

.PARAMETER OVCredential
    PSCredential pro OneView (Get-Credential)

.PARAMETER ServerFilter
    Volitelny filter nazvu serveru (wildcard, napr. 'DL380*')

.PARAMETER ExportCsv
    Cesta pro export CSV reportu

.PARAMETER ResetKeysOnMissing
    POZOR: Provede ResetAllKeysToDefault kde chybi 2023 certy.
    POUZIVAT POUZE PO UPGRADU BIOSU NA MIN. POZADOVANOU VERZI!

.PARAMETER WhatIf
    Pouze simulace - nic neopravuje.

.NOTES
    Pozadavky:
      - HPEOneView PowerShell modul (Install-Module HPEOneView.1100 nebo aktualni)
      - PS 5.1: SkipCertificateCheck neni podporovan -> pouziva TrustAllCertsPolicy
      - PS 7+:  SkipCertificateCheck parametr Invoke-RestMethod pouzit primo
      - iLO SSO: nevyzaduje separatni iLO credentials

    Zdroj: Broadcom KB423893, HPE OneView API, TAM session 02/2026
#>
param(
    [Parameter(Mandatory)][string]$OneViewAddress,
    [Parameter(Mandatory)][PSCredential]$OVCredential,
    [string]$ServerFilter      = '*',
    [string]$ExportCsv         = '',
    [switch]$ResetKeysOnMissing,
    [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ── PS 5.1 TLS / cert bypass ───────────────────────────────────────────────────
# -SkipCertificateCheck exists only in PS 6+. On PS 5.1 we install a permissive
# ICertificatePolicy that trusts all certs for the duration of the script.
$script:UseSkipCertParam = $PSVersionTable.PSVersion.Major -ge 6

if (-not $script:UseSkipCertParam) {
    if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
        Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) { return true; }
}
"@
    }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [System.Net.ServicePointManager]::SecurityProtocol  =
        [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
    Write-Host "[INFO] PS 5.1 mode — TrustAllCertsPolicy installed (iLO self-signed certs accepted)" -ForegroundColor DarkGray
}

# ── Pomocne funkce ─────────────────────────────────────────────────────────────
function Write-Banner {
    param([string]$Text, [string]$Color = 'Cyan')
    Write-Host "`n$('=' * 60)" -ForegroundColor $Color
    Write-Host "  $Text"        -ForegroundColor $Color
    Write-Host "$('=' * 60)"    -ForegroundColor $Color
}

function Invoke-iLORedfish {
    param(
        [string]$Uri,
        [hashtable]$Headers,
        [string]$Method = 'GET',
        [object]$Body   = $null
    )
    $params = @{
        Uri             = $Uri
        Headers         = $Headers
        Method          = $Method
        ContentType     = 'application/json'
        UseBasicParsing = $true
        ErrorAction     = 'Stop'
    }
    # Only add -SkipCertificateCheck on PS 6+ (parameter does not exist in PS 5.1)
    if ($script:UseSkipCertParam) {
        $params['SkipCertificateCheck'] = $true
    }
    if ($Body -and $Method -ne 'GET') {
        $params['Body'] = ($Body | ConvertTo-Json -Depth 5)
    }
    return (Invoke-RestMethod @params)
}

# ── Kontrola HPEOneView modulu ─────────────────────────────────────────────────
$ovModule = Get-Module -ListAvailable -Name 'HPEOneView.*' |
            Sort-Object Version -Descending | Select-Object -First 1
if (-not $ovModule) {
    Write-Host "[CHYBA] HPEOneView modul neni nainstalovan!" -ForegroundColor Red
    Write-Host "Instalace: Find-Module HPEOneView.* | Sort-Object Version -Desc | Select -First 1 | Install-Module"
    exit 1
}
Import-Module $ovModule.Name -ErrorAction Stop
Write-Host "[OK] HPEOneView modul: $($ovModule.Name) v$($ovModule.Version)" -ForegroundColor Green

# ── Pripojeni k OneView ────────────────────────────────────────────────────────
Write-Banner "Pripojuji se k HPE OneView: $OneViewAddress"
try {
    $ovConn = Connect-OVMgmt -Hostname $OneViewAddress -Credential $OVCredential -ErrorAction Stop
    Write-Host "[OK] Pripojeno: $OneViewAddress" -ForegroundColor Green
} catch {
    Write-Host "[CHYBA] Nelze se pripojit k OneView: $_" -ForegroundColor Red
    exit 1
}

# ── Nacteni serveru ────────────────────────────────────────────────────────────
Write-Host "`n[*] Nacitam seznam serveru (filter: '$ServerFilter')..." -ForegroundColor Cyan
$servers = Get-OVServer -ApplianceConnection $ovConn |
           Where-Object { $_.name -like $ServerFilter }

if ($servers.Count -eq 0) {
    Write-Host "[WARN] Zadne servery nenalezeny pro filter '$ServerFilter'" -ForegroundColor Yellow
    Disconnect-OVMgmt -ApplianceConnection $ovConn
    exit 0
}
Write-Host "[*] Celkem serveru ke zpracovani: $($servers.Count)" -ForegroundColor Cyan

$results  = @()
$i        = 0
$fixCount = 0

foreach ($server in $servers) {
    $i++
    $serverName = $server.name
    $model      = $server.model
    $romVersion = $server.romVersion
    $serialNum  = $server.serialNumber
    $iloModel   = $server.mpModel

    Write-Progress -Activity "Skenuji servery" `
                   -Status   "$serverName  ($i / $($servers.Count))" `
                   -PercentComplete (($i / $servers.Count) * 100)

    Write-Host "`n-- [$i/$($servers.Count)] $serverName | $model | ROM: $romVersion | $iloModel --" -ForegroundColor White

    # iLO IP (skip LinkLocal)
    $iloIP = $null
    try {
        $iloIP = ($server.mpHostInfo.mpIpAddresses |
                  Where-Object { $_.type -ne 'LinkLocal' } |
                  Select-Object -First 1).address
    } catch {}

    if (-not $iloIP) {
        Write-Host "  [SKIP] iLO IP adresa nedostupna" -ForegroundColor DarkGray
        $results += [PSCustomObject]@{
            ServerName = $serverName; Model = $model; Serial = $serialNum
            ROM = $romVersion; iLOIP = 'N/A'; iLOModel = $iloModel
            SecureBoot = 'N/A'; KEK_2023 = 'N/A'; DB_2023 = 'N/A'
            OptionROM_2023 = 'N/A'; Status = 'SKIP - iLO IP nedostupna'
            ResetPerformed = $false
        }
        continue
    }

    Write-Host "  iLO IP: $iloIP" -ForegroundColor DarkCyan

    $biosGuidance = ''
    if    ($romVersion -match 'U30|U32') { $biosGuidance = "Gen10 - min 3.40_01-16-2025 + Reset Keys!" }
    elseif ($romVersion -match 'U46')    { $biosGuidance = "Gen10 Plus - min 2.30_01-16-2025" }
    elseif ($romVersion -match 'U54|U59'){ $biosGuidance = "Gen11 - min 2.42_12-06-2024" }
    if ($biosGuidance) { Write-Host "  [BIOS] $biosGuidance" -ForegroundColor DarkCyan }

    # ── SSO token via OneView ──────────────────────────────────────────────────
    # Get-OVIloSso -IloRestSession returns a hashtable/object with the iLO session.
    # Token key differs between OV module versions; try multiple accessors.
    $ssoToken = $null
    try {
        $iloSession = $server | Get-OVIloSso -IloRestSession -SkipCertificateCheck -ApplianceConnection $ovConn
        # Try common property paths (varies by OV module version)
        if ($iloSession -is [hashtable] -and $iloSession.ContainsKey('X-Auth-Token')) {
            $ssoToken = $iloSession['X-Auth-Token']
        } elseif ($null -ne $iloSession.'X-Auth-Token') {
            $ssoToken = $iloSession.'X-Auth-Token'
        } elseif ($null -ne $iloSession.Headers) {
            $ssoToken = $iloSession.Headers['X-Auth-Token']
        }
        if ($ssoToken) {
            Write-Host "  [OK] SSO token ziskan pres OneView" -ForegroundColor DarkGreen
        } else {
            Write-Host "  [WARN] SSO session ziskana ale token nenalezen v odpovedi" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [WARN] Nelze ziskat SSO token: $_ - preskakuji server" -ForegroundColor Yellow
        $results += [PSCustomObject]@{
            ServerName = $serverName; Model = $model; Serial = $serialNum
            ROM = $romVersion; iLOIP = $iloIP; iLOModel = $iloModel
            SecureBoot = 'N/A'; KEK_2023 = 'N/A'; DB_2023 = 'N/A'
            OptionROM_2023 = 'N/A'; Status = 'SKIP - SSO token selhal'
            ResetPerformed = $false
        }
        continue
    }

    if (-not $ssoToken) {
        $results += [PSCustomObject]@{
            ServerName = $serverName; Model = $model; Serial = $serialNum
            ROM = $romVersion; iLOIP = $iloIP; iLOModel = $iloModel
            SecureBoot = 'N/A'; KEK_2023 = 'N/A'; DB_2023 = 'N/A'
            OptionROM_2023 = 'N/A'; Status = 'SKIP - SSO token prazdny'
            ResetPerformed = $false
        }
        continue
    }

    $hdrs    = @{ 'X-Auth-Token' = $ssoToken; 'OData-Version' = '4.0' }
    $baseUri = "https://$iloIP"

    # === 1. Secure Boot status ================================================
    $sbEnabled = $false
    $sbMode    = 'Unknown'
    try {
        $sb        = Invoke-iLORedfish "$baseUri/redfish/v1/Systems/1/SecureBoot/" $hdrs
        $sbEnabled = $sb.SecureBootEnable
        $sbMode    = $sb.SecureBootMode
        $col       = if ($sbEnabled) { 'Green' } else { 'Yellow' }
        Write-Host "  Secure Boot: $(if ($sbEnabled) {'ENABLED'} else {'DISABLED'})  | Mode: $sbMode" -ForegroundColor $col
    } catch {
        Write-Host "  [WARN] SecureBoot endpoint selhal: $_" -ForegroundColor DarkGray
    }

    # === 2. Certifikaty v db a KEK ===========================================
    $kek2023     = $false
    $db2023      = $false
    $optRom2023  = $false
    $certSummary = @()

    $dbUris = @{
        'KEK' = "/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/KEK/Certificates"
        'db'  = "/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/db/Certificates"
    }

    foreach ($dbName in $dbUris.Keys) {
        $uri = $dbUris[$dbName]
        try {
            # Try $expand first (iLO 6/7); fall back to collection without expand (iLO 5)
            $certs = $null
            try {
                $certs = Invoke-iLORedfish "$baseUri${uri}?`$expand=." $hdrs
            } catch {
                $certs = Invoke-iLORedfish "$baseUri${uri}" $hdrs
            }

            foreach ($certEntry in $certs.Members) {
                $cert = $certEntry
                if (-not $cert.Subject -and $cert.'@odata.id') {
                    try { $cert = Invoke-iLORedfish "$baseUri$($cert.'@odata.id')" $hdrs } catch { continue }
                }

                $cn = ''
                if ($cert.Subject -is [hashtable] -or $cert.Subject -is [PSCustomObject]) {
                    $cn = $cert.Subject.CommonName
                } elseif ($cert.Subject) {
                    $cn = $cert.Subject -replace '.*CN=([^,]+).*','$1'
                }
                if (-not $cn) { $cn = "ID:$($cert.Id)" }

                $exp      = if ($cert.ValidNotAfter) { $cert.ValidNotAfter } else { 'N/A' }
                $certSummary += "${dbName}: $cn (Exp: $exp)"

                if ($cn -like '*KEK 2K CA 2023*' -or $cn -like '*KEK CA 2023*')  { $kek2023    = $true }
                if ($cn -like '*Windows UEFI CA 2023*' -or
                    $cn -like '*Microsoft Corporation UEFI CA 2023*')             { $db2023     = $true }
                if ($cn -like '*Option ROM UEFI CA 2023*')                       { $optRom2023 = $true }

                if ($cn -like '*2023*') {
                    Write-Host "  [2023] $dbName | $cn | $exp" -ForegroundColor Green
                } elseif ($cn -like '*2011*') {
                    Write-Host "  [2011] $dbName | $cn | $exp" -ForegroundColor Yellow
                } else {
                    Write-Host "  [    ] $dbName | $cn | $exp"
                }
            }
        } catch {
            Write-Host "  [WARN] $dbName certifikaty selhal: $($_.Exception.Message)" -ForegroundColor DarkGray
        }
    }

    # === 3. Vyhodnoceni stavu ================================================
    $status = ''
    if (-not $sbEnabled) {
        $status = 'SECURE_BOOT_DISABLED'
        Write-Host "  [WARN] Secure Boot neni povoleno" -ForegroundColor Yellow
    } elseif ($kek2023 -and $db2023) {
        $status = if ($optRom2023) { 'OK_2023' } else { 'OK_MISSING_OPTROM' }
        Write-Host "  [OK] 2023 certifikaty pritomny" -ForegroundColor Green
        if (-not $optRom2023) {
            Write-Host "  [INFO] Option ROM UEFI CA 2023 chybi" -ForegroundColor DarkCyan
        }
    } elseif (-not $kek2023 -and -not $db2023) {
        $status = 'MISSING_ALL_2023'
        Write-Host "  [ACTION REQUIRED] Chybi KEK 2023 i DB 2023 certifikaty!" -ForegroundColor Red
    } elseif (-not $kek2023) {
        $status = 'MISSING_KEK_2023'
        Write-Host "  [ACTION REQUIRED] Chybi KEK 2023 certifikat!" -ForegroundColor Red
    } elseif (-not $db2023) {
        $status = 'MISSING_DB_2023'
        Write-Host "  [ACTION REQUIRED] Chybi DB (Windows UEFI CA) 2023 certifikat!" -ForegroundColor Red
    } else {
        $status = 'UNKNOWN'
    }

    # === 4. ResetAllKeysToDefault (volitelna oprava) ==========================
    $resetDone = $false

    if ($ResetKeysOnMissing -and ($status -like 'MISSING*')) {
        if ($WhatIf) {
            Write-Host "  [WHATIF] POST SecureBoot.ResetKeys (ResetAllKeysToDefault)" -ForegroundColor Magenta
            Write-Host "  [WHATIF] URI: $baseUri/redfish/v1/Systems/1/SecureBoot/Actions/SecureBoot.ResetKeys/" -ForegroundColor Magenta
        } else {
            Write-Host ""
            Write-Host "  [?] Provest ResetAllKeysToDefault na $serverName ($iloIP)?" -ForegroundColor Yellow
            Write-Host "      UPOZORNENI: Resetuje VSECHNY Secure Boot klice na firmware defaults!" -ForegroundColor Red
            Write-Host "      POUZIVAT POUZE pokud BIOS je na min. pozadovane verzi!" -ForegroundColor Red
            $confirm = Read-Host "      Potvrdit (ano/ne)"
            if ($confirm -eq 'ano') {
                try {
                    $resetBody = @{ ResetKeysType = 'ResetAllKeysToDefault' }
                    $resetUri  = "$baseUri/redfish/v1/Systems/1/SecureBoot/Actions/SecureBoot.ResetKeys/"
                    $null = Invoke-iLORedfish -Uri $resetUri -Headers $hdrs -Method 'POST' -Body $resetBody
                    Write-Host "  [OK] ResetAllKeysToDefault odeslan! Server musi byt restartovan (cold reboot)." -ForegroundColor Green
                    $resetDone  = $true
                    $fixCount++
                    $status    += ' -> RESET_SENT (restart required)'
                } catch {
                    Write-Host "  [CHYBA] Reset Keys selhal: $_" -ForegroundColor Red
                }
            } else {
                Write-Host "  [SKIP] Reset preskocen" -ForegroundColor DarkGray
            }
        }
    }

    $results += [PSCustomObject]@{
        ServerName     = $serverName
        Model          = $model
        Serial         = $serialNum
        ROM            = $romVersion
        iLOIP          = $iloIP
        iLOModel       = $iloModel
        SecureBoot     = if ($sbEnabled) { "ENABLED/$sbMode" } else { 'DISABLED' }
        KEK_2023       = $kek2023
        DB_2023        = $db2023
        OptionROM_2023 = $optRom2023
        Status         = $status
        ResetPerformed = $resetDone
        Certs          = ($certSummary -join '; ')
    }
}

Write-Progress -Activity "Skenuji servery" -Completed

# ── Souhrn ─────────────────────────────────────────────────────────────────────
Write-Banner "SOUHRN - UEFI CA 2023 Secure Boot Inventory" 'Cyan'
Write-Host "  OneView: $OneViewAddress" -ForegroundColor White
Write-Host "  Celkem serveru: $($results.Count)" -ForegroundColor White
Write-Host ""

$statusGroups = $results | Group-Object Status | Sort-Object Name
foreach ($grp in $statusGroups) {
    $clr = switch -Wildcard ($grp.Name) {
        'OK*'          { 'Green' }
        'MISSING*'     { 'Red' }
        'SECURE_BOOT*' { 'Yellow' }
        'SKIP*'        { 'DarkGray' }
        default        { 'White' }
    }
    Write-Host "  $($grp.Name): $($grp.Count)x" -ForegroundColor $clr
}

if ($fixCount -gt 0) {
    Write-Host "`n  [INFO] ResetAllKeysToDefault odeslan na $fixCount serveru." -ForegroundColor Cyan
    Write-Host "         Cold reboot povinny pro aplikaci zmen!" -ForegroundColor Yellow
}

Write-Host "`n-- ACTION REQUIRED servery: --" -ForegroundColor Red
$needAction = $results | Where-Object { $_.Status -like 'MISSING*' }
if ($needAction.Count -eq 0) {
    Write-Host "  (zadne)" -ForegroundColor Green
} else {
    $needAction | Format-Table ServerName, Model, ROM, iLOIP, Status -AutoSize -Wrap
}

if ($ExportCsv) {
    $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host "[+] Report exportovan: $ExportCsv" -ForegroundColor Green
}

Write-Host "`nRef: Broadcom KB423893, HPE OneView API, TAM 02/2026, Scott Wiginton/derek.lin2 Slack" -ForegroundColor DarkGray
Write-Host "$('=' * 60)`n" -ForegroundColor Cyan

Disconnect-OVMgmt -ApplianceConnection $ovConn
