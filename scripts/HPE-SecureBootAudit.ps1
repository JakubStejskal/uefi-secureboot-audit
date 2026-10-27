#Requires -Version 5.1
<#
.SYNOPSIS
    Audits UEFI Secure Boot certificate readiness (Microsoft 2011 -> 2023 CA transition)
    across HPE ProLiant / Synergy Gen11 and Gen12 via iLO Redfish.

.DESCRIPTION
    READ-ONLY. This script never writes to NVRAM, never changes firmware, and never
    reboots anything.

    iLO 6 (Gen11) and iLO 7 (Gen12) expose the full inventory of PK / KEK / db / dbx
    including ValidNotAfter through SecureBootDatabases.

    iLO 5 servers are out of scope: the iLO 5 Redfish API has no certificate
    inventory, so no meaningful remote audit is possible (see docs/runbook.md). If one
    is passed in, it is reported as OUT_OF_SCOPE and nothing else is evaluated.

    Where the certificate inventory is unavailable on an in-scope server, the script
    reports ROM_OK_CERTS_UNKNOWN (Gen11) or UNVERIFIED (Gen12) rather than claiming
    compliance it cannot prove. No verdict of COMPLIANT is ever issued without the
    live KEK and db having been read.

    Every 2023 certificate is checked in the database it belongs to (KEK 2023 in KEK,
    the three CAs in db). A certificate found only in dbx counts as revoked, not present.

    Navigation follows the @odata.id links iLO returns instead of concatenating paths.
    iLO member links end with '/': in v2.0 "$sysUri/SecureBoot" produced
    '.../Systems/1//SecureBoot' (rejected, swallowed as 404/400 -> NOT_REPORTED), and
    splitting '.../SecureBootDatabases/db/' on '/' yielded an empty database ID, so
    every live database would have been skipped even with a correct URI.

.PARAMETER ILOHost
    One or more iLO hostnames / IP addresses. A scheme, path or trailing slash
    ('https://10.0.0.5/') is stripped, so pasted URLs work.

.PARAMETER InputCsv
    CSV file with an 'ILOHost' column (an optional 'Note' column is ignored).
    Alternative to -ILOHost.

.PARAMETER Credential
    iLO credentials. A read-only account is sufficient; no iLO Advanced licence is
    required for Redfish access.

.PARAMETER SkipCertificateCheck
    Accept the self-signed iLO TLS certificate. On Windows PowerShell 5.1 this bypass
    is process-global; the script saves and restores the original callback in a
    finally block so unrelated HTTPS calls in the same session are not left exposed.

.PARAMETER TimeoutSec
    Per-request timeout. Default 30.

.EXAMPLE
    $cred = Get-Credential
    .\HPE-SecureBootAudit.ps1 -ILOHost ilo-esx01,ilo-esx02 -Credential $cred -SkipCertificateCheck |
        Format-Table ILOHost,Model,Generation,BiosVersion,RomStatus,CertInventory,Verdict -AutoSize

.EXAMPLE
    .\HPE-SecureBootAudit.ps1 -InputCsv .\examples\fleet.csv -Credential $cred `
        -SkipCertificateCheck -OutputCsv .\hpe-audit.csv -OutputJson .\hpe-audit.json

.OUTPUTS
    One PSCustomObject per target. Verdict is one of:
        COMPLIANT               KEK 2023 in KEK and all three 2023 CAs in db, read from
                                the live databases, Secure Boot active (UserMode)
        CERTS_OK_SECUREBOOT_OFF certificates complete, but Secure Boot is not enforcing
                                (disabled, or PK missing / SetupMode)
        NEEDS_KEY_RESET         live databases lack 2023 certs; ROM meets baseline
                                (Gen11) or is factory-capable (Gen12)
        NEEDS_ROM_AND_RESET     live databases lack 2023 certs and System ROM is below
                                the advisory baseline
        ROM_OK_CERTS_UNKNOWN    Gen11: ROM meets baseline, live databases not readable
        UNVERIFIED              Gen12: live databases not readable (see CertInventoryNote)
        OUT_OF_SCOPE            iLO 5 server - no remote audit possible, see docs/runbook.md
        NOT_SUPPORTED           Gen9 - no firmware path exists
        UNKNOWN                 generation or ROM version could not be determined
        ERROR                   unreachable / auth failure / unexpected response (see Error)

.LINK
    https://support.hpe.com/hpesc/public/docDisplay?docId=a00156355en_us

.NOTES
    Project : uefi-secureboot-audit
    Version : 2.1
    Licence : MIT. Provided as-is, with no warranty. Not affiliated with, endorsed by,
              or supported by HPE, Broadcom or Microsoft. Validate against the current
              revision of the HPE advisory and test in a lab before fleet use.
#>
[CmdletBinding(DefaultParameterSetName = 'Hosts')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Hosts', Position = 0)]
    [string[]]$ILOHost,

    [Parameter(Mandatory, ParameterSetName = 'File')]
    [ValidateScript({ Test-Path $_ })]
    [string]$InputCsv,

    [Parameter(Mandatory)]
    [System.Management.Automation.PSCredential]$Credential,

    [string]$OutputCsv,
    [string]$OutputJson,
    [switch]$SkipCertificateCheck,
    [ValidateRange(5, 600)][int]$TimeoutSec = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ------------------------------------------------------------ reference data

# Microsoft Secure Boot CAs - state as of 2026-08-04.
# SHA-1 thumbprints computed from the DER files Microsoft distributes via
# go.microsoft.com/fwlink, not transcribed from documentation.
#
# Naming trap: Microsoft KB tables write "Microsoft UEFI CA 2011", but the actual
# X.509 CN is "Microsoft Corporation UEFI CA 2011". Match on CN or thumbprint.
$script:CertCatalog = @(
    [pscustomobject]@{ CN = 'Microsoft Corporation KEK CA 2011';      Db = 'KEK'; Era = 2011; NotAfter = [datetime]'2026-06-24T20:51:29Z'; Thumbprint = '31590BFD89C9D74ED087DFAC66334B3931254B30' }
    [pscustomobject]@{ CN = 'Microsoft Corporation UEFI CA 2011';     Db = 'db';  Era = 2011; NotAfter = [datetime]'2026-06-27T21:32:45Z'; Thumbprint = '46DEF63B5CE61CF8BA0DE2E6639C1019D0ED14F3' }
    [pscustomobject]@{ CN = 'Microsoft Windows Production PCA 2011';  Db = 'db';  Era = 2011; NotAfter = [datetime]'2026-10-19T18:51:42Z'; Thumbprint = '580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D' }
    [pscustomobject]@{ CN = 'Microsoft Corporation KEK 2K CA 2023';   Db = 'KEK'; Era = 2023; NotAfter = [datetime]'2038-03-02T20:31:35Z'; Thumbprint = '459AB6FB5E284D272D5E3E6ABC8ED663829D632B' }
    [pscustomobject]@{ CN = 'Windows UEFI CA 2023';                   Db = 'db';  Era = 2023; NotAfter = [datetime]'2035-06-13T19:08:29Z'; Thumbprint = '45A0FA32604773C82433C3B7D59E7466B3AC0C67' }
    [pscustomobject]@{ CN = 'Microsoft UEFI CA 2023';                 Db = 'db';  Era = 2023; NotAfter = [datetime]'2038-06-13T19:31:47Z'; Thumbprint = 'B5EEB4A6706048073F0ED296E7F580A790B59EAA' }
    [pscustomobject]@{ CN = 'Microsoft Option ROM UEFI CA 2023';      Db = 'db';  Era = 2023; NotAfter = [datetime]'2038-10-26T19:12:20Z'; Thumbprint = '3FB39E2B8BD183BF9E4594E72183CA60AFCD4277' }
)

# All four must be present after successful remediation. The single 2011 third-party
# CA was replaced by TWO 2023 CAs - bootloaders and option ROMs were split apart - so
# checking for three is a common and silent mistake.
$script:Required2023 = @(
    'Microsoft Corporation KEK 2K CA 2023'
    'Windows UEFI CA 2023'
    'Microsoft UEFI CA 2023'
    'Microsoft Option ROM UEFI CA 2023'
)

# Minimum System ROM per HPE Customer Advisory a00156355en_us (rev. 5, 2026-07-02).
# Key: "<Generation>|<Arch>". Exceptions are handled in Get-RequiredRomVersion.
#
# These are the versions in which the LAST of the four certificates (Option ROM UEFI
# CA 2023) landed. Earlier ROMs may already carry the other three.
$script:RomBaseline = @{
    'Gen11|Intel'      = '2.42'
    'Gen11|AMD'        = '2.30'
}

#endregion

#region ------------------------------------------------------------ TLS / transport

$script:OriginalCallback = $null
$script:CallbackModified = $false

function Initialize-TlsBypass {
    if (-not $SkipCertificateCheck) { return }
    if ($PSVersionTable.PSVersion.Major -ge 6) { return }   # PS7 uses per-call -SkipCertificateCheck

    $script:OriginalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    $script:CallbackModified = $true
    [System.Net.ServicePointManager]::SecurityProtocol =
        [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
    Write-Warning 'Windows PowerShell 5.1: TLS validation disabled process-wide for this session. It is restored when the script exits.'
}

function Restore-TlsBypass {
    if ($script:CallbackModified) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $script:OriginalCallback
        $script:CallbackModified = $false
    }
}

function Get-Prop {
    <#
      Safe property read. Set-StrictMode -Version Latest throws on a property the iLO
      simply did not return, which varies by firmware level and platform.
    #>
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object.PSObject.Properties.Name -contains $Name) {
        $v = $Object.$Name
        if ($null -eq $v) { return $Default }
        return $v
    }
    return $Default
}

function ConvertTo-ILOHostName {
    <#
      'https://10.0.0.5/', '10.0.0.5/redfish/v1', ' ilo01 ' -> '10.0.0.5' / 'ilo01'.
      Port and IPv6 literals ('[fe80::1]:443') are preserved.
    #>
    param([Parameter(Mandatory)][string]$Value)
    $h = $Value.Trim() -replace '^[A-Za-z][A-Za-z0-9+.\-]*://', ''
    $h = ($h -split '/')[0]
    if ([string]::IsNullOrWhiteSpace($h)) { throw "Invalid iLO host value '$Value'." }
    return $h
}

function Join-RedfishUri {
    <#
      Joins a base and a path with exactly one '/'. iLO @odata.id values end with '/',
      so naive "$uri/Child" produces '//Child' and iLO answers 404.
    #>
    param([Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)][string]$Path)
    if ($Path -match '^https?://') { return $Path }
    return ($Base.TrimEnd('/') + '/' + $Path.TrimStart('/'))
}

function Resolve-RedfishLink {
    <# Absolute URI of a navigation property { "@odata.id": "..." }, or $null. #>
    param($Conn, $Object, [string]$Name)
    $id = Get-Prop (Get-Prop $Object $Name) '@odata.id'
    if ($id) { return (Join-RedfishUri -Base $Conn.Base -Path $id) }
    return $null
}

function Get-ODataLeaf {
    <# '/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/db/' -> 'db' #>
    param([string]$ODataId)
    return (($ODataId.TrimEnd('/')) -split '/')[-1]
}

function Invoke-Redfish {
    <#
      Thin wrapper over Invoke-RestMethod. Returns $null on HTTP 404/400 when
      -AllowNotFound is set: that is the expected response when asking iLO 5 for
      SecureBootDatabases, and must not be treated as an error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers = @{},
        [string]$Method = 'GET',
        [object]$Body,
        [switch]$AllowNotFound
    )

    $splat = @{
        Uri         = $Uri
        Method      = $Method
        Headers     = $Headers
        TimeoutSec  = $TimeoutSec
        ErrorAction = 'Stop'
    }
    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
        $splat.Body        = ($Body | ConvertTo-Json -Depth 6 -Compress)
        $splat.ContentType = 'application/json'
    }
    if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -ge 6) {
        $splat.SkipCertificateCheck = $true
    }

    try {
        return Invoke-RestMethod @splat
    }
    catch {
        $status = $null
        if ($_.Exception.PSObject.Properties.Name -contains 'Response' -and $_.Exception.Response) {
            try { $status = [int]$_.Exception.Response.StatusCode } catch { $status = $null }
        }
        if ($AllowNotFound -and $status -in 404, 400) { return $null }
        throw
    }
}

function Connect-ILO {
    <#
      Session authentication. iLO has a low simultaneous-session limit, so the caller
      must always Disconnect-ILO in a finally block or the account will lock out
      during a fleet sweep.
    #>
    param([string]$HostName)

    $base = "https://$HostName"
    $body = @{ UserName = $Credential.UserName; Password = $Credential.GetNetworkCredential().Password }

    $splat = @{
        Uri         = "$base/redfish/v1/SessionService/Sessions/"
        Method      = 'POST'
        Body        = ($body | ConvertTo-Json -Compress)
        ContentType = 'application/json'
        TimeoutSec  = $TimeoutSec
        ErrorAction = 'Stop'
    }
    if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -ge 6) { $splat.SkipCertificateCheck = $true }

    # -ResponseHeadersVariable is PS7+; 5.1 must go through Invoke-WebRequest.
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $null = Invoke-RestMethod @splat -ResponseHeadersVariable rh
        $token    = $rh['X-Auth-Token'] | Select-Object -First 1
        $location = $rh['Location']     | Select-Object -First 1
    }
    else {
        $resp     = Invoke-WebRequest @splat -UseBasicParsing
        $token    = $resp.Headers['X-Auth-Token']
        $location = $resp.Headers['Location']
    }

    if (-not $token) { throw "iLO $HostName : session created but no X-Auth-Token returned." }

    # Location may be absolute or relative depending on firmware.
    if ($location -and $location -notmatch '^https?://') { $location = "$base$location" }

    [pscustomobject]@{
        Base    = $base
        Headers = @{ 'X-Auth-Token' = $token; 'OData-Version' = '4.0' }
        Session = $location
    }
}

function Disconnect-ILO {
    param($Conn)
    if (-not $Conn -or -not $Conn.Session) { return }
    try { $null = Invoke-Redfish -Uri $Conn.Session -Headers $Conn.Headers -Method 'DELETE' -AllowNotFound }
    catch { Write-Verbose "Logout failed, session will expire on its own: $($_.Exception.Message)" }
}

#endregion

#region ------------------------------------------------------------ helpers

function Get-SystemUri {
    <# Do not hardcode /Systems/1 - Synergy and Superdome use different member IDs. #>
    param($Conn)
    $col = Invoke-Redfish -Uri "$($Conn.Base)/redfish/v1/Systems/" -Headers $Conn.Headers
    if (-not $col.Members -or $col.Members.Count -eq 0) { throw 'ComputerSystem collection is empty.' }
    return (Join-RedfishUri -Base $Conn.Base -Path $col.Members[0].'@odata.id')
}

function Get-ManagerInfo {
    param($Conn)
    $col = Invoke-Redfish -Uri "$($Conn.Base)/redfish/v1/Managers/" -Headers $Conn.Headers
    $mgr = Invoke-Redfish -Uri (Join-RedfishUri -Base $Conn.Base -Path $col.Members[0].'@odata.id') -Headers $Conn.Headers

    $model = [string](Get-Prop $mgr 'Model' '')
    $fw    = [string](Get-Prop $mgr 'FirmwareVersion' '')

    # 'iLO 5' / 'iLO 6' / 'iLO 7'; older firmware reports 'iLO5' without the space.
    $gen = if ($model -match 'iLO\s*(\d)') { [int]$Matches[1] }
           elseif ($fw -match 'iLO\s*(\d)') { [int]$Matches[1] }
           else { 0 }

    [pscustomobject]@{ Model = $model; FirmwareVersion = $fw; ILOGeneration = $gen }
}

function ConvertTo-RomVersion {
    <# "U30 v3.66 (04/01/2026)" -> Family='U30', Version=[version]'3.66' #>
    param([string]$BiosVersion)

    $family = $null; $ver = $null
    if ($BiosVersion -match '^\s*(?<fam>[A-Za-z]\d{1,3})\s') { $family = $Matches['fam'].ToUpper() }
    if ($BiosVersion -match 'v(?<ver>\d+\.\d+(\.\d+)?)')     { $ver    = [version]$Matches['ver'] }
    elseif ($BiosVersion -match '(?<ver>\d+\.\d+)')          { $ver    = [version]$Matches['ver'] }

    [pscustomobject]@{ Family = $family; Version = $ver; Raw = $BiosVersion }
}

function Get-ServerGeneration {
    param([string]$Model)
    # Order matters: 'Gen10 Plus' must be tested before 'Gen10'.
    switch -Regex ($Model) {
        'Gen12'        { return 'Gen12' }
        'Gen11'        { return 'Gen11' }
        'Gen10\s*Plus' { return 'Gen10 Plus' }
        'Gen10'        { return 'Gen10' }
        'Gen9'         { return 'Gen9' }
        default        { return 'Unknown' }
    }
}

function Get-RequiredRomVersion {
    param([string]$Generation, [string]$Arch, [string]$Model)

    if ($Generation -eq 'Gen12') { return $null }           # 2023 certs active from factory
    if ($Generation -in 'Gen9', 'Unknown') { return $null }  # no firmware path / unknown
    if ($Generation -in 'Gen10', 'Gen10 Plus') { return $null }  # out of scope (iLO 5)

    $key = "$Generation|$Arch"
    if ($script:RomBaseline.ContainsKey($key)) { return [version]$script:RomBaseline[$key] }
    return $null
}

function Get-SecureBootCertificateInventory {
    <#
      Reads the live PK / KEK / db / dbx certificate collections.

      Returns @{ Status; Note; Certs } where Status is:
        OK            every collection and every certificate read
        PARTIAL       some certificate reads failed (see Note); Certs holds what was read
        EMPTY         collections exist but contain no certificates
        NOT_REPORTED  SecureBootDatabases or the live databases are absent (see Note)

      Only live databases are read. The read-only *Default collections hold the OEM
      defaults a key reset would apply, not what the platform is using now.

      dbx mostly holds SHA-256 hashes; those are in .../dbx/Signatures and are not
      read here. Only certificate entries in dbx are reported.
    #>
    param($Conn, $SecureBoot, [string]$SecureBootUri)

    $notes  = New-Object System.Collections.Generic.List[string]
    $result = New-Object System.Collections.Generic.List[object]
    $failed = 0

    $dbColUri = Resolve-RedfishLink -Conn $Conn -Object $SecureBoot -Name 'SecureBootDatabases'
    if (-not $dbColUri) {
        $dbColUri = Join-RedfishUri -Base $SecureBootUri -Path 'SecureBootDatabases/'
        $notes.Add('SecureBoot resource has no SecureBootDatabases link; tried the conventional path.')
    }

    $dbCol = Invoke-Redfish -Uri $dbColUri -Headers $Conn.Headers -AllowNotFound
    if (-not $dbCol -or -not ($dbCol.PSObject.Properties.Name -contains 'Members')) {
        $notes.Add("No SecureBootDatabases collection at $dbColUri.")
        return [pscustomobject]@{ Status = 'NOT_REPORTED'; Note = ($notes -join ' '); Certs = @() }
    }

    $liveSeen = 0
    foreach ($m in $dbCol.Members) {
        $dbUri = Join-RedfishUri -Base $Conn.Base -Path $m.'@odata.id'
        $dbId  = Get-ODataLeaf $m.'@odata.id'

        if ($dbId -match 'Default$') { continue }
        if ($dbId -notin 'PK', 'KEK', 'db', 'dbx') { continue }
        $liveSeen++

        # Prefer the Certificates link from the database resource; fall back to the path.
        $certColUri = $null
        try {
            $db = Invoke-Redfish -Uri $dbUri -Headers $Conn.Headers -AllowNotFound
            if ($db) {
                $certColUri = Resolve-RedfishLink -Conn $Conn -Object $db -Name 'Certificates'
                $idProp = [string](Get-Prop $db 'DatabaseId')
                if ($idProp) { $dbId = $idProp }
            }
        }
        catch { $notes.Add("Read of $dbId failed: $($_.Exception.Message)"); $failed++ }
        if (-not $certColUri) { $certColUri = Join-RedfishUri -Base $dbUri -Path 'Certificates/' }

        $certCol = Invoke-Redfish -Uri $certColUri -Headers $Conn.Headers -AllowNotFound
        if (-not $certCol -or -not ($certCol.PSObject.Properties.Name -contains 'Members')) {
            $notes.Add("$dbId has no Certificates collection.")
            continue
        }

        foreach ($cm in $certCol.Members) {
            try {
                # Some firmware embeds the members ($expand); otherwise fetch each one.
                $cert = if (Get-Prop $cm 'Subject') { $cm }
                        else { Invoke-Redfish -Uri (Join-RedfishUri -Base $Conn.Base -Path $cm.'@odata.id') -Headers $Conn.Headers -AllowNotFound }
                if (-not $cert) { $failed++; continue }

                $subj = Get-Prop $cert 'Subject'
                $cn   = [string](Get-Prop $subj 'CommonName')
                if (-not $cn) { $cn = [string](Get-Prop $subj 'DisplayString') }

                $na  = $null
                $raw = Get-Prop $cert 'ValidNotAfter'
                if ($raw) { try { $na = [datetime]$raw } catch { $na = $null } }

                # Fallback: some iLO firmware omits Subject / ValidNotAfter.
                $pemStr = [string](Get-Prop $cert 'CertificateString')
                if ((-not $cn -or -not $na) -and $pemStr) {
                    try {
                        $pem = $pemStr -replace '-----(BEGIN|END) CERTIFICATE-----', '' -replace '\s', ''
                        $x   = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($pem))
                        if (-not $cn) { $cn = ($x.Subject -split ',' | Where-Object { $_ -match 'CN=' } | Select-Object -First 1) -replace '^\s*CN=', '' }
                        if (-not $na) { $na = $x.NotAfter }
                    }
                    catch { Write-Verbose "Local PEM parse failed: $($_.Exception.Message)" }
                }

                $result.Add([pscustomobject]@{
                    Database   = $dbId
                    CommonName = if ($cn) { $cn.Trim() } else { $null }
                    NotAfter   = $na
                    Serial     = Get-Prop $cert 'SerialNumber'
                })
            }
            catch {
                $failed++
                Write-Verbose "Cannot read $($cm.'@odata.id'): $($_.Exception.Message)"
            }
        }
    }

    if ($liveSeen -eq 0) {
        $notes.Add('SecureBootDatabases lists no live PK/KEK/db/dbx members.')
        return [pscustomobject]@{ Status = 'NOT_REPORTED'; Note = ($notes -join ' '); Certs = @() }
    }
    if ($failed -gt 0) { $notes.Add("$failed certificate read(s) failed.") }

    $status = if ($result.Count -eq 0) { 'EMPTY' } elseif ($failed -gt 0) { 'PARTIAL' } else { 'OK' }
    return [pscustomobject]@{ Status = $status; Note = ($notes -join ' '); Certs = $result.ToArray() }
}

function Test-CertIn {
    <# True when a certificate with this CN is present in the given live database. #>
    param($Certs, [string]$Database, [string]$CommonName)
    return [bool](@($Certs | Where-Object { $_.Database -eq $Database -and $_.CommonName -eq $CommonName }).Count -gt 0)
}

#endregion

#region ------------------------------------------------------------ main

function Get-HPESecureBootStatus {
    param([string]$HostName)

    $row = [ordered]@{
        ILOHost                 = $HostName
        Reachable               = $false
        Model                   = $null
        SerialNumber            = $null
        Generation              = $null
        Arch                    = $null
        ILOModel                = $null
        ILOFirmware             = $null
        BiosVersion             = $null
        RomFamily               = $null
        RomVersion              = $null
        RomRequired             = $null
        RomStatus               = 'Unknown'
        SecureBootEnable        = $null
        SecureBootCurrentBoot   = $null
        SecureBootMode          = $null
        SecureBootActive        = $null
        CertInventory           = 'NotAttempted'
        CertInventoryNote       = $null
        DbCounts                = $null
        Has_PK                  = $null
        Has_KEK2023             = $null
        Has_WindowsUEFICA2023   = $null
        Has_MicrosoftUEFICA2023 = $null
        Has_OptionRomCA2023     = $null
        Has_VMwareDbCert        = $null
        Legacy2011InDb          = $null
        Legacy2011InKEK         = $null
        Revoked2011InDbx        = $null
        Missing2023             = $null
        CertDetail              = $null
        Verdict                 = 'Unknown'
        Action                  = $null
        Error                   = $null
    }

    $conn = $null
    try {
        $conn = Connect-ILO -HostName $HostName
        $row.Reachable = $true

        $mgr = Get-ManagerInfo -Conn $conn
        $row.ILOModel    = $mgr.Model
        $row.ILOFirmware = $mgr.FirmwareVersion

        $sysUri = Get-SystemUri -Conn $conn
        $sys    = Invoke-Redfish -Uri $sysUri -Headers $conn.Headers

        $row.Model        = [string](Get-Prop $sys 'Model' '')
        $row.SerialNumber = [string](Get-Prop $sys 'SerialNumber')
        $row.BiosVersion  = [string](Get-Prop $sys 'BiosVersion')
        $row.Generation   = Get-ServerGeneration -Model $row.Model

        $cpu = [string](Get-Prop (Get-Prop $sys 'ProcessorSummary') 'Model' '')
        $row.Arch = if ($cpu -match 'AMD|EPYC') { 'AMD' } else { 'Intel' }

        # --- System ROM baseline ---
        if ($row.BiosVersion) {
            $rom = ConvertTo-RomVersion -BiosVersion $row.BiosVersion
            $row.RomFamily  = $rom.Family
            $row.RomVersion = if ($rom.Version) { $rom.Version.ToString() } else { $null }

            $req = Get-RequiredRomVersion -Generation $row.Generation -Arch $row.Arch -Model $row.Model
            if ($null -ne $req) {
                $row.RomRequired = $req.ToString()
                $row.RomStatus   = if ($rom.Version -and $rom.Version -ge $req) { 'OK' } else { 'UPDATE_REQUIRED' }
            }
            elseif ($row.Generation -eq 'Gen12') { $row.RomStatus = 'NA_FactoryDefault' }
            elseif ($row.Generation -eq 'Gen9')  { $row.RomStatus = 'NO_FIRMWARE_PATH' }
            elseif ($row.Generation -in 'Gen10', 'Gen10 Plus') { $row.RomStatus = 'OUT_OF_SCOPE' }
            else { $row.RomStatus = 'Unknown' }
        }

        # --- Secure Boot state ---
        # Follow the link from the ComputerSystem; never build '$sysUri/SecureBoot' by
        # string concatenation ($sysUri ends with '/').
        $sbUri = Resolve-RedfishLink -Conn $conn -Object $sys -Name 'SecureBoot'
        if (-not $sbUri) { $sbUri = Join-RedfishUri -Base $sysUri -Path 'SecureBoot/' }
        $sb = Invoke-Redfish -Uri $sbUri -Headers $conn.Headers -AllowNotFound
        if ($sb) {
            foreach ($p in 'SecureBootEnable', 'SecureBootCurrentBoot', 'SecureBootMode') {
                $row[$p] = Get-Prop $sb $p
            }
            # Enforcing = currently booted with Secure Boot AND a PK enrolled (UserMode).
            # Some firmware omits SecureBootMode; then CurrentBoot alone decides.
            $modeOk = (-not $row.SecureBootMode) -or ($row.SecureBootMode -in 'UserMode', 'DeployedMode')
            $row.SecureBootActive = [bool](($row.SecureBootCurrentBoot -eq 'Enabled') -and $modeOk)
        }

        # --- certificate inventory (iLO 6 / iLO 7 only) ---
        if ($mgr.ILOGeneration -le 5) {
            $row.CertInventory = 'UNSUPPORTED_ILO5'
        }
        elseif (-not $sb) {
            $row.CertInventory     = 'NOT_REPORTED'
            $row.CertInventoryNote = "No SecureBoot resource at $sbUri."
        }
        else {
            $inv = Get-SecureBootCertificateInventory -Conn $conn -SecureBoot $sb -SecureBootUri $sbUri
            $row.CertInventory     = $inv.Status
            $row.CertInventoryNote = if ($inv.Note) { $inv.Note } else { $null }
            $certs = @($inv.Certs)

            if ($certs.Count -gt 0) {
                $row.DbCounts = (@('PK', 'KEK', 'db', 'dbx') | ForEach-Object {
                    $d = $_; '{0}={1}' -f $d, @($certs | Where-Object { $_.Database -eq $d }).Count
                }) -join ' '

                $row.Has_PK                  = [bool](@($certs | Where-Object { $_.Database -eq 'PK' }).Count -gt 0)
                $row.Has_KEK2023             = Test-CertIn $certs 'KEK' 'Microsoft Corporation KEK 2K CA 2023'
                $row.Has_WindowsUEFICA2023   = Test-CertIn $certs 'db'  'Windows UEFI CA 2023'
                $row.Has_MicrosoftUEFICA2023 = Test-CertIn $certs 'db'  'Microsoft UEFI CA 2023'
                $row.Has_OptionRomCA2023     = Test-CertIn $certs 'db'  'Microsoft Option ROM UEFI CA 2023'
                # HPE platform defaults carry a VMware signing certificate in db: ESXi boot
                # does not depend on the Microsoft third-party CA on these platforms.
                $row.Has_VMwareDbCert        = [bool](@($certs | Where-Object { $_.Database -eq 'db' -and $_.CommonName -match 'VMware' }).Count -gt 0)

                $ms2011 = @($script:CertCatalog | Where-Object { $_.Era -eq 2011 } | ForEach-Object { $_.CN })
                $row.Legacy2011InDb   = [bool](@($certs | Where-Object { $_.Database -eq 'db'  -and $_.CommonName -in $ms2011 }).Count -gt 0)
                $row.Legacy2011InKEK  = [bool](@($certs | Where-Object { $_.Database -eq 'KEK' -and $_.CommonName -in $ms2011 }).Count -gt 0)
                $row.Revoked2011InDbx = [bool](@($certs | Where-Object { $_.Database -eq 'dbx' -and $_.CommonName -in $ms2011 }).Count -gt 0)

                $missing = @()
                if (-not $row.Has_KEK2023)             { $missing += 'KEK:Microsoft Corporation KEK 2K CA 2023' }
                if (-not $row.Has_WindowsUEFICA2023)   { $missing += 'db:Windows UEFI CA 2023' }
                if (-not $row.Has_MicrosoftUEFICA2023) { $missing += 'db:Microsoft UEFI CA 2023' }
                if (-not $row.Has_OptionRomCA2023)     { $missing += 'db:Microsoft Option ROM UEFI CA 2023' }
                $row.Missing2023 = if ($missing.Count) { $missing -join '; ' } else { '' }

                $row.CertDetail = ($certs |
                    Sort-Object Database, CommonName |
                    ForEach-Object {
                        $d = if ($_.NotAfter) { $_.NotAfter.ToString('yyyy-MM-dd') } else { '?' }
                        "$($_.Database):$($_.CommonName) (exp $d)"
                    }) -join '; '
            }
        }

        $v = @(Get-Verdict -Row $row)
        $row.Verdict = $v[0]
        $row.Action  = $v[1]
    }
    catch {
        $row.Error   = $_.Exception.Message
        $row.Verdict = 'ERROR'
        $row.Action  = 'Check iLO reachability, credentials and TLS (-SkipCertificateCheck). Details in the Error column.'
    }
    finally {
        Disconnect-ILO -Conn $conn
    }

    [pscustomobject]$row
}

function Get-Verdict {
    param($Row)

    if ($Row.Generation -eq 'Gen9') {
        return @('NOT_SUPPORTED', 'Gen9 will not receive a System ROM containing the 2023 certificates. Options: manual enrolment in RBSU, run without Secure Boot, or hardware refresh.')
    }
    if ($Row.Generation -in 'Gen10', 'Gen10 Plus') {
        return @('OUT_OF_SCOPE', 'iLO 5 server: the iLO 5 API cannot report Secure Boot certificates, so a remote audit is not possible. See docs/runbook.md.')
    }

    # --- hard evidence: live databases were read (fully or partially) ---
    if ($Row.CertInventory -in 'OK', 'PARTIAL' -and $null -ne $Row.Missing2023) {
        if ($Row.Missing2023 -eq '') {
            # Presence is proven even from a partial read.
            if ($Row.Has_PK -eq $false -or $Row.SecureBootActive -eq $false) {
                return @('CERTS_OK_SECUREBOOT_OFF', "All four 2023 certificates present, but Secure Boot is not enforcing (CurrentBoot=$($Row.SecureBootCurrentBoot), Mode=$($Row.SecureBootMode), PK present=$($Row.Has_PK)). Re-enable Secure Boot; if PK is missing, reset all keys to platform defaults first.")
            }
            return @('COMPLIANT', 'KEK 2023 in KEK and all three 2023 CAs in db (live databases).')
        }

        if ($Row.CertInventory -eq 'PARTIAL') {
            return @(($(if ($Row.Generation -eq 'Gen12') { 'UNVERIFIED' } else { 'ROM_OK_CERTS_UNKNOWN' })),
                     "Partial read - not found so far: $($Row.Missing2023). $($Row.CertInventoryNote) Re-run with -Verbose.")
        }

        if ($Row.Generation -eq 'Gen12') {
            return @('NEEDS_KEY_RESET', "Gen12 ships with the 2023 certificates enabled, yet the live databases lack: $($Row.Missing2023). Keys were customised or replaced. Check dbDefault / KEKDefault, then 'Reset All Keys to Platform Defaults' and re-enable Secure Boot.")
        }
        switch ($Row.RomStatus) {
            'OK' {
                return @('NEEDS_KEY_RESET', "System ROM meets the baseline but the live databases lack: $($Row.Missing2023). Requires 'Reset All Keys to Platform Defaults', then re-enable Secure Boot.")
            }
            'UPDATE_REQUIRED' {
                return @('NEEDS_ROM_AND_RESET', "Missing: $($Row.Missing2023). Update System ROM to >= $($Row.RomRequired) first, then reset keys.")
            }
            default {
                return @('UNKNOWN', "Missing: $($Row.Missing2023). System ROM status could not be determined - verify manually.")
            }
        }
    }

    # --- no inventory: never claim compliance ---
    $why = if ($Row.CertInventoryNote) { " ($($Row.CertInventoryNote))" } else { '' }
    if ($Row.Generation -eq 'Gen12') {
        return @('UNVERIFIED', "Gen12 is expected to carry the 2023 certificates from the factory, but the live databases could not be read$why. Verify in RBSU (Advanced Secure Boot Options > View entries).")
    }
    switch ($Row.RomStatus) {
        'UPDATE_REQUIRED' {
            return @('NEEDS_ROM_AND_RESET', "System ROM $($Row.RomVersion) is below the required $($Row.RomRequired). Flash the ROM, then reset keys.")
        }
        'OK' {
            return @('ROM_OK_CERTS_UNKNOWN', "System ROM meets the baseline, but the live databases could not be read$why. If the key reset was never performed, the 2023 certificates are NOT active.")
        }
        default {
            return @('UNKNOWN', 'Could not determine System ROM version or server generation - verify manually.')
        }
    }
}

#endregion

#region ------------------------------------------------------------ run

$targets = @(
    $(if ($PSCmdlet.ParameterSetName -eq 'File') {
        Import-Csv -Path $InputCsv | ForEach-Object { $_.ILOHost } | Where-Object { $_ }
    }
    else { $ILOHost }) | ForEach-Object { ConvertTo-ILOHostName -Value $_ } | Select-Object -Unique
)

if ($targets.Count -eq 0) { throw 'No targets to audit.' }

$results = New-Object System.Collections.Generic.List[object]

try {
    Initialize-TlsBypass

    $i = 0
    foreach ($t in $targets) {
        $i++
        Write-Progress -Activity 'HPE Secure Boot audit' -Status "$t ($i/$($targets.Count))" `
                       -PercentComplete (($i / $targets.Count) * 100)
        $results.Add((Get-HPESecureBootStatus -HostName $t))
    }
    Write-Progress -Activity 'HPE Secure Boot audit' -Completed
}
finally {
    Restore-TlsBypass
}

if ($OutputCsv)  { $results | Select-Object * -ExcludeProperty CertDetail | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8 }
if ($OutputJson) { $results | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputJson -Encoding UTF8 }

Write-Host ''
Write-Host '=== Summary ===' -ForegroundColor Cyan
foreach ($g in ($results | Group-Object Verdict | Sort-Object Count -Descending)) {
    $color = switch ($g.Name) {
        'COMPLIANT'           { 'Green' }
        'ERROR'               { 'Red' }
        'NOT_SUPPORTED'       { 'Red' }
        'NEEDS_ROM_AND_RESET' { 'Red' }
        default               { 'Yellow' }
    }
    Write-Host ('{0,-24} {1}' -f $g.Name, $g.Count) -ForegroundColor $color
}

# Reasons are otherwise hidden by a Format-Table column selection.
$attention = @($results | Where-Object { $_.Verdict -ne 'COMPLIANT' })
if ($attention.Count -gt 0) {
    Write-Host ''
    foreach ($r in $attention) {
        $why = if ($r.Error) { $r.Error } elseif ($r.CertInventoryNote) { $r.CertInventoryNote } else { $r.Action }
        Write-Host ('{0,-22} {1,-24} {2}' -f $r.ILOHost, $r.Verdict, $why) -ForegroundColor DarkYellow
    }
}
Write-Host ''

$results

#endregion
