#Requires -Version 5.1
<#
.SYNOPSIS
    Přímá kontrola UEFI CA 2023 Secure Boot certifikátů přes iLO Redfish.
    Nevyžaduje HPE OneView — pracuje přímo s iLO IP a credentials.

.DESCRIPTION
    Jednodušší alternativa k Check-SecureBoot-OneView.ps1.
    Vhodné pro servery mimo OneView management nebo pro ad-hoc kontrolu.

    Flow:
      1. Přímé přihlášení na iLO přes Redfish SessionService
      2. GET /SecureBoot — stav Secure Boot
      3. GET /SecureBootDatabases/db + /KEK/Certificates — výpis certifikátů
      4. Vyhodnocení přítomnosti 2023 certifikátů
      5. Volitelný reset + CSV export

.PARAMETER IloHost
    IP nebo hostname iLO. Lze zadat opakovaně nebo načíst ze souboru.

.PARAMETER HostsFile
    Soubor s iLO IP adresami (jedna per řádek, komentáře # ignorovány).
    Volitelný formát: "ServerName|iLO_IP"

.PARAMETER IloCredential
    PSCredential pro iLO (Get-Credential). Stejné credentials použity pro všechny hosty.

.PARAMETER ExportCsv
    Cesta pro CSV export.

.PARAMETER ResetKeysOnMissing
    Provede ResetAllKeysToDefault kde chybí 2023 certy.
    POUŽÍT POUZE PO UPGRADU BIOSU NA MINIMÁLNÍ POŽADOVANOU VERZI!

.PARAMETER WhatIf
    Simulace — ukáže co by bylo resetováno bez provedení akce.

.EXAMPLE
    # Jeden server
    $cred = Get-Credential
    .\Check-SecureBootiLO.ps1 -IloHost 10.3.18.50 -IloCredential $cred

.EXAMPLE
    # Více serverů ze souboru + CSV export
    .\Check-SecureBootiLO.ps1 -HostsFile .\ilo-hosts.txt -IloCredential $cred -ExportCsv report.csv

.EXAMPLE
    # Dry-run reset
    .\Check-SecureBootiLO.ps1 -HostsFile .\ilo-hosts.txt -IloCredential $cred -ResetKeysOnMissing -WhatIf

.NOTES
    Curl ekvivalent pro ruční ověření:
      curl -k -u admin:pass -X GET \
        "https://<ILO_IP>/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/db/Certificates?$expand=." \
        | jq -r '.Members[] | [.Subject.CommonName, .ValidNotAfter] | @csv'

    Zdroj: Broadcom KB423893, HPE iLO5 Redfish API, TAM session 02/2026
#>
param(
    [string[]]$IloHost        = @(),
    [string]$HostsFile        = '',
    [Parameter(Mandatory)][PSCredential]$IloCredential,
    [string]$ExportCsv        = '',
    [switch]$ResetKeysOnMissing,
    [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ── PS 5.1 TLS bypass ─────────────────────────────────────────────────────────
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
}

# ── Helpers ───────────────────────────────────────────────────────────────────
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
    if ($script:UseSkipCertParam) { $params['SkipCertificateCheck'] = $true }
    if ($Body -and $Method -ne 'GET') { $params['Body'] = ($Body | ConvertTo-Json -Depth 5) }
    return (Invoke-RestMethod @params)
}

function New-iLOSession {
    param([string]$BaseUri, [PSCredential]$Cred)
    $body = @{ UserName = $Cred.UserName; Password = $Cred.GetNetworkCredential().Password }
    $params = @{
        Uri             = "$BaseUri/redfish/v1/SessionService/Sessions"
        Method          = 'POST'
        Body            = ($body | ConvertTo-Json)
        ContentType     = 'application/json'
        UseBasicParsing = $true
        ErrorAction     = 'Stop'
    }
    if ($script:UseSkipCertParam) { $params['SkipCertificateCheck'] = $true }

    if ($script:UseSkipCertParam) {
        $resp = Invoke-WebRequest @params
    } else {
        $resp = Invoke-WebRequest @params
    }
    return $resp.Headers['X-Auth-Token']
}

function Remove-iLOSession {
    param([string]$BaseUri, [string]$Token, [string]$SessionUri)
    if (-not $Token) { return }
    try {
        $params = @{
            Uri             = if ($SessionUri) { $SessionUri } else { "$BaseUri/redfish/v1/SessionService/Sessions" }
            Method          = 'DELETE'
            Headers         = @{ 'X-Auth-Token' = $Token }
            UseBasicParsing = $true
            ErrorAction     = 'SilentlyContinue'
        }
        if ($script:UseSkipCertParam) { $params['SkipCertificateCheck'] = $true }
        $null = Invoke-RestMethod @params
    } catch {}
}

# ── Host list sestavení ────────────────────────────────────────────────────────
$hostEntries = @()   # [pscustomobject]@{ Name; IP }

foreach ($h in $IloHost) {
    $hostEntries += [PSCustomObject]@{ Name = $h; IP = $h }
}

if ($HostsFile -and (Test-Path $HostsFile)) {
    foreach ($line in (Get-Content $HostsFile)) {
        $line = $line.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }
        if ($line -like '*|*') {
            $parts = $line -split '\|', 2
            $hostEntries += [PSCustomObject]@{ Name = $parts[0].Trim(); IP = $parts[1].Trim() }
        } else {
            $hostEntries += [PSCustomObject]@{ Name = $line; IP = $line }
        }
    }
}

if ($hostEntries.Count -eq 0) {
    Write-Host "[CHYBA] Žádné hosty — použij -IloHost nebo -HostsFile" -ForegroundColor Red
    exit 1
}

# ── Hlavní smyčka ─────────────────────────────────────────────────────────────
$results  = @()
$i        = 0
$fixCount = 0

foreach ($entry in $hostEntries) {
    $i++
    $serverName = $entry.Name
    $iloIP      = $entry.IP
    $baseUri    = "https://$iloIP"

    Write-Host "`n-- [$i/$($hostEntries.Count)] $serverName ($iloIP) --" -ForegroundColor White

    # Session
    $token = $null
    try {
        $loginBody = @{ UserName = $IloCredential.UserName; Password = $IloCredential.GetNetworkCredential().Password }
        $loginParams = @{
            Uri             = "$baseUri/redfish/v1/SessionService/Sessions"
            Method          = 'POST'
            Body            = ($loginBody | ConvertTo-Json)
            ContentType     = 'application/json'
            UseBasicParsing = $true
            ErrorAction     = 'Stop'
        }
        if ($script:UseSkipCertParam) { $loginParams['SkipCertificateCheck'] = $true }
        $loginResp = Invoke-WebRequest @loginParams
        $token     = $loginResp.Headers['X-Auth-Token']
        $sessionUri = $loginResp.Headers['Location']
    } catch {
        Write-Host "  [SKIP] Login selhal: $_" -ForegroundColor Red
        $results += [PSCustomObject]@{
            ServerName = $serverName; iLOIP = $iloIP
            SecureBoot = 'N/A'; KEK_2023 = 'N/A'; DB_2023 = 'N/A'
            Status = 'SKIP - login selhal'; ResetPerformed = $false; Certs = ''
        }
        continue
    }

    if (-not $token) {
        Write-Host "  [SKIP] Token nezískan" -ForegroundColor Red
        $results += [PSCustomObject]@{
            ServerName = $serverName; iLOIP = $iloIP
            SecureBoot = 'N/A'; KEK_2023 = 'N/A'; DB_2023 = 'N/A'
            Status = 'SKIP - token prazdny'; ResetPerformed = $false; Certs = ''
        }
        continue
    }

    Write-Host "  [OK] Session established" -ForegroundColor DarkGreen
    $hdrs = @{ 'X-Auth-Token' = $token; 'OData-Version' = '4.0' }

    # SecureBoot status
    $sbEnabled = $false; $sbMode = 'Unknown'
    try {
        $sb        = Invoke-iLORedfish "$baseUri/redfish/v1/Systems/1/SecureBoot/" $hdrs
        $sbEnabled = $sb.SecureBootEnable
        $sbMode    = $sb.SecureBootMode
        $col       = if ($sbEnabled) { 'Green' } else { 'Yellow' }
        Write-Host "  Secure Boot: $(if ($sbEnabled) {'ENABLED'} else {'DISABLED'}) | Mode: $sbMode" -ForegroundColor $col
    } catch {
        Write-Host "  [WARN] SecureBoot endpoint selhal: $_" -ForegroundColor DarkGray
    }

    # Certifikáty
    $kek2023 = $false; $db2023 = $false; $certSummary = @()
    $dbUris  = @{
        'KEK' = "/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/KEK/Certificates"
        'db'  = "/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/db/Certificates"
    }

    foreach ($dbName in $dbUris.Keys) {
        try {
            $certs = $null
            try   { $certs = Invoke-iLORedfish "$baseUri$($dbUris[$dbName])?`$expand=." $hdrs }
            catch { $certs = Invoke-iLORedfish "$baseUri$($dbUris[$dbName])"             $hdrs }

            foreach ($certEntry in $certs.Members) {
                $cert = $certEntry
                if (-not $cert.Subject -and $cert.'@odata.id') {
                    try { $cert = Invoke-iLORedfish "$baseUri$($cert.'@odata.id')" $hdrs } catch { continue }
                }
                $cn  = if ($cert.Subject -is [string]) { $cert.Subject -replace '.*CN=([^,]+).*','$1' }
                       elseif ($cert.Subject.CommonName) { $cert.Subject.CommonName }
                       else { "ID:$($cert.Id)" }
                $exp = if ($cert.ValidNotAfter) { $cert.ValidNotAfter } else { 'N/A' }
                $certSummary += "${dbName}: $cn (Exp: $exp)"

                if ($cn -like '*KEK*2023*')                                    { $kek2023 = $true }
                if ($cn -like '*Windows UEFI CA 2023*' -or
                    $cn -like '*Microsoft Corporation UEFI CA 2023*')          { $db2023  = $true }

                $col = if ($cn -like '*2023*') { 'Green' } elseif ($cn -like '*2011*') { 'Yellow' } else { 'White' }
                Write-Host "  [$( if ($cn -like '*2023*') {'2023'} elseif ($cn -like '*2011*') {'2011'} else {'    '} )] $dbName | $cn | $exp" -ForegroundColor $col
            }
        } catch {
            Write-Host "  [WARN] $dbName certs: $($_.Exception.Message)" -ForegroundColor DarkGray
        }
    }

    # Status
    $status = if     (-not $sbEnabled)              { 'SECURE_BOOT_DISABLED' }
              elseif ($kek2023 -and $db2023)         { 'OK_2023' }
              elseif (-not $kek2023 -and -not $db2023) { 'MISSING_ALL_2023' }
              elseif (-not $kek2023)                 { 'MISSING_KEK_2023' }
              elseif (-not $db2023)                  { 'MISSING_DB_2023' }
              else                                   { 'UNKNOWN' }

    $col = if ($status -like 'OK*') { 'Green' } elseif ($status -like 'MISSING*') { 'Red' } else { 'Yellow' }
    Write-Host "  Status: $status" -ForegroundColor $col

    # Optional reset
    $resetDone = $false
    if ($ResetKeysOnMissing -and ($status -like 'MISSING*')) {
        if ($WhatIf) {
            Write-Host "  [WHATIF] POST ResetAllKeysToDefault → $baseUri/redfish/v1/Systems/1/SecureBoot/Actions/SecureBoot.ResetKeys/" -ForegroundColor Magenta
        } else {
            try {
                $null = Invoke-iLORedfish -Uri "$baseUri/redfish/v1/Systems/1/SecureBoot/Actions/SecureBoot.ResetKeys/" `
                    -Headers $hdrs -Method 'POST' -Body @{ ResetKeysType = 'ResetAllKeysToDefault' }
                Write-Host "  [OK] ResetAllKeysToDefault odeslan — cold reboot required!" -ForegroundColor Green
                $resetDone = $true; $fixCount++
                $status   += ' -> RESET_SENT'
            } catch {
                Write-Host "  [CHYBA] Reset selhal: $_" -ForegroundColor Red
            }
        }
    }

    Remove-iLOSession $baseUri $token $sessionUri

    $results += [PSCustomObject]@{
        ServerName     = $serverName
        iLOIP          = $iloIP
        SecureBoot     = if ($sbEnabled) { "ENABLED/$sbMode" } else { 'DISABLED' }
        KEK_2023       = $kek2023
        DB_2023        = $db2023
        Status         = $status
        ResetPerformed = $resetDone
        Certs          = ($certSummary -join '; ')
    }
}

# Souhrn
Write-Banner "SOUHRN" 'Cyan'
$results | Group-Object Status | Sort-Object Name | ForEach-Object {
    $clr = if ($_.Name -like 'OK*') { 'Green' } elseif ($_.Name -like 'MISSING*') { 'Red' } else { 'Yellow' }
    Write-Host "  $($_.Name): $($_.Count)x" -ForegroundColor $clr
}
if ($fixCount -gt 0) {
    Write-Host "`n  ResetAllKeysToDefault odeslan na $fixCount serverech — cold reboot povinný!" -ForegroundColor Yellow
}
Write-Host ""
$results | Where-Object { $_.Status -like 'MISSING*' } |
    Format-Table ServerName, iLOIP, Status -AutoSize

if ($ExportCsv) {
    $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host "[+] Report: $ExportCsv" -ForegroundColor Green
}
