#Requires -Version 5.1
<#
.SYNOPSIS
    Audits UEFI Secure Boot certificate readiness (Microsoft 2011 -> 2023 CA transition)
    across HPE ProLiant / Synergy Gen10, Gen10 Plus, Gen11 and Gen12 via iLO Redfish.

.DESCRIPTION
    READ-ONLY. This script never writes to NVRAM, never changes firmware, and never
    reboots anything.

    It operates in one of two modes, selected automatically from the detected iLO
    generation:

      iLO 5 (Gen10 / Gen10 Plus)
          /redfish/v1/Systems/1/SecureBoot        EXISTS
          /redfish/v1/Systems/1/SecureBoot/SecureBootDatabases   DOES NOT EXIST
          Certificates cannot be enumerated out-of-band at all. The verdict is
          therefore derived indirectly from the System ROM version, compared against
          HPE Customer Advisory a00156355en_us.

      iLO 6 (Gen11) / iLO 7 (Gen12)
          Full inventory of PK / KEK / db / dbx including ValidNotAfter.

    The iLO 5 limitation is a property of iLO 5, not a bug in this script and not a
    firmware-version problem. It is absent from the iLO 5 Redfish resource map for
    every firmware release including the most recent (v3.19). SecureBootDatabases was
    introduced in iLO 6 v1.10.

    Where the certificate inventory is unavailable, the script reports
    ROM_OK_CERTS_UNKNOWN rather than claiming compliance it cannot prove.

.PARAMETER ILOHost
    One or more iLO hostnames / IP addresses.

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
        COMPLIANT             all four 2023 certificates present (or Gen12)
        NEEDS_KEY_RESET       ROM meets baseline, live databases still lack 2023 certs
        NEEDS_ROM_AND_RESET   System ROM below advisory baseline
        ROM_OK_CERTS_UNKNOWN  iLO 5: ROM is fine, certificate state unverifiable here
        NOT_SUPPORTED         Gen9 - no firmware path exists
        ERROR                 unreachable / auth failure / unexpected response

.LINK
    https://support.hpe.com/hpesc/public/docDisplay?docId=a00156355en_us

.NOTES
    Project : uefi-secureboot-audit
    Version : 2.0
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
    'Gen10|Intel'      = '3.62'
    'Gen10|AMD'        = '3.70'
    'Gen10 Plus|Intel' = '2.30'
    'Gen10 Plus|AMD'   = '3.50'
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
    return "$($Conn.Base)$($col.Members[0].'@odata.id')"
}

function Get-ManagerInfo {
    param($Conn)
    $col = Invoke-Redfish -Uri "$($Conn.Base)/redfish/v1/Managers/" -Headers $Conn.Headers
    $mgr = Invoke-Redfish -Uri "$($Conn.Base)$($col.Members[0].'@odata.id')" -Headers $Conn.Headers

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

    # Advisory exception: DL20 Gen10, ML30 Gen10 and m750 baseline at 3.72, not 3.62.
    if ($Generation -eq 'Gen10' -and $Arch -eq 'Intel' -and $Model -match 'DL20|ML30|m750') {
        return [version]'3.72'
    }

    $key = "$Generation|$Arch"
    if ($script:RomBaseline.ContainsKey($key)) { return [version]$script:RomBaseline[$key] }
    return $null
}

function Get-SecureBootCertificateInventory {
    <#
      Returns an array of Database/CommonName/NotAfter/Serial objects, or $null when
      SecureBootDatabases is absent (iLO 5). $null is an expected state, not a fault.

      Only live databases are read. The read-only *Default collections hold the OEM
      defaults that a key reset would apply, not what the platform is using now.
    #>
    param($Conn, [string]$SecureBootUri)

    $dbCol = Invoke-Redfish -Uri "$SecureBootUri/SecureBootDatabases" -Headers $Conn.Headers -AllowNotFound
    if (-not $dbCol) { return $null }
    if (-not ($dbCol.PSObject.Properties.Name -contains 'Members')) { return $null }

    $result = New-Object System.Collections.Generic.List[object]

    foreach ($m in $dbCol.Members) {
        $dbUri = "$($Conn.Base)$($m.'@odata.id')"
        $dbId  = ($m.'@odata.id' -split '/')[-1]

        if ($dbId -match 'Default$') { continue }
        if ($dbId -notin 'PK', 'KEK', 'db', 'dbx') { continue }

        $certCol = Invoke-Redfish -Uri "$dbUri/Certificates" -Headers $Conn.Headers -AllowNotFound
        if (-not $certCol -or -not ($certCol.PSObject.Properties.Name -contains 'Members')) { continue }

        foreach ($cm in $certCol.Members) {
            try {
                $cert = Invoke-Redfish -Uri "$($Conn.Base)$($cm.'@odata.id')" -Headers $Conn.Headers -AllowNotFound
                if (-not $cert) { continue }

                $subj = Get-Prop $cert 'Subject'
                $cn   = [string](Get-Prop $subj 'CommonName')
                if (-not $cn) { $cn = [string](Get-Prop $subj 'DisplayString') }

                $na  = $null
                $raw = Get-Prop $cert 'ValidNotAfter'
                if ($raw) { try { $na = [datetime]$raw } catch { $na = $null } }

                # Fallback: some iLO firmware omits Subject / ValidNotAfter. HPE's
                # Certificate schema also has no Fingerprint property for Secure Boot
                # databases, so any thumbprint work has to start from the PEM anyway.
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
                    CommonName = $cn
                    NotAfter   = $na
                    Serial     = Get-Prop $cert 'SerialNumber'
                })
            }
            catch { Write-Verbose "Cannot read $($cm.'@odata.id'): $($_.Exception.Message)" }
        }
    }

    return $result.ToArray()
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
        CertInventory           = 'NotAttempted'
        Has_KEK2023             = $null
        Has_WindowsUEFICA2023   = $null
        Has_MicrosoftUEFICA2023 = $null
        Has_OptionRomCA2023     = $null
        Legacy2011Present       = $null
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
            else { $row.RomStatus = 'Unknown' }
        }

        # --- Secure Boot state (available on every iLO generation from 5 up) ---
        $sbUri = "$sysUri/SecureBoot"
        $sb    = Invoke-Redfish -Uri $sbUri -Headers $conn.Headers -AllowNotFound
        if ($sb) {
            foreach ($p in 'SecureBootEnable', 'SecureBootCurrentBoot', 'SecureBootMode') {
                $row[$p] = Get-Prop $sb $p
            }
        }

        # --- certificate inventory (iLO 6 / iLO 7 only) ---
        $certs = $null
        if ($mgr.ILOGeneration -ge 6) {
            $certs = Get-SecureBootCertificateInventory -Conn $conn -SecureBootUri $sbUri
        }

        if ($null -eq $certs) {
            $row.CertInventory = if ($mgr.ILOGeneration -le 5) { 'UNSUPPORTED_ILO5' } else { 'NOT_REPORTED' }
        }
        elseif ($certs.Count -eq 0) {
            # Field-reported: some iLO 6 units return empty collections.
            $row.CertInventory = 'EMPTY'
        }
        else {
            $row.CertInventory = 'OK'
            $cnList = @($certs | Where-Object { $_.CommonName } | ForEach-Object { $_.CommonName.Trim() })

            $row.Has_KEK2023             = [bool]($cnList -contains 'Microsoft Corporation KEK 2K CA 2023')
            $row.Has_WindowsUEFICA2023   = [bool]($cnList -contains 'Windows UEFI CA 2023')
            $row.Has_MicrosoftUEFICA2023 = [bool]($cnList -contains 'Microsoft UEFI CA 2023')
            $row.Has_OptionRomCA2023     = [bool]($cnList -contains 'Microsoft Option ROM UEFI CA 2023')
            $row.Legacy2011Present       = [bool](@($cnList | Where-Object { $_ -match '2011' }).Count -gt 0)

            $row.CertDetail = ($certs |
                Sort-Object Database, CommonName |
                ForEach-Object {
                    $d = if ($_.NotAfter) { $_.NotAfter.ToString('yyyy-MM-dd') } else { '?' }
                    "$($_.Database):$($_.CommonName) (exp $d)"
                }) -join '; '
        }

        $v = @(Get-Verdict -Row $row)
        $row.Verdict = $v[0]
        $row.Action  = $v[1]
    }
    catch {
        $row.Error   = $_.Exception.Message
        $row.Verdict = 'ERROR'
        $row.Action  = 'Check iLO reachability, credentials and TLS (-SkipCertificateCheck).'
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
    if ($Row.Generation -eq 'Gen12') {
        return @('COMPLIANT', 'Gen12 ships with the 2023 certificates included AND enabled. A key reset is NOT required - verify only.')
    }

    # Gen11 / Gen12 with a readable inventory: hard evidence.
    if ($Row.CertInventory -eq 'OK') {
        $missing = @()
        if (-not $Row.Has_KEK2023)             { $missing += 'KEK 2K CA 2023' }
        if (-not $Row.Has_WindowsUEFICA2023)   { $missing += 'Windows UEFI CA 2023' }
        if (-not $Row.Has_MicrosoftUEFICA2023) { $missing += 'Microsoft UEFI CA 2023' }
        if (-not $Row.Has_OptionRomCA2023)     { $missing += 'Option ROM UEFI CA 2023' }

        if ($missing.Count -eq 0) { return @('COMPLIANT', 'All four 2023 certificates present in the live databases.') }

        if ($Row.RomStatus -eq 'OK') {
            return @('NEEDS_KEY_RESET', "System ROM meets the baseline but the live databases lack: $($missing -join ', '). Requires 'Reset All Keys to Platform Defaults', then re-enable Secure Boot.")
        }
        return @('NEEDS_ROM_AND_RESET', "Missing: $($missing -join ', '). Update System ROM to >= $($Row.RomRequired) first, then reset keys.")
    }

    # Gen10 / Gen10 Plus: certificates unreadable, ROM version is the only signal.
    # Note it is a necessary but NOT sufficient condition - a compliant ROM whose keys
    # were never reset still runs on 2011-only certificates.
    switch ($Row.RomStatus) {
        'UPDATE_REQUIRED' {
            return @('NEEDS_ROM_AND_RESET', "System ROM $($Row.RomVersion) is below the required $($Row.RomRequired). Flash the ROM, then reset keys.")
        }
        'OK' {
            return @('ROM_OK_CERTS_UNKNOWN', "System ROM meets the baseline, but iLO 5 cannot enumerate Secure Boot certificates. Verify via Embedded UEFI Shell 'secboot -l KEK' / 'secboot -l db', RBSU, or from inside the OS. If the key reset was never performed, the 2023 certificates are NOT active.")
        }
        default {
            return @('UNKNOWN', 'Could not determine System ROM version or server generation - verify manually.')
        }
    }
}

#endregion

#region ------------------------------------------------------------ run

$targets = @(
    if ($PSCmdlet.ParameterSetName -eq 'File') {
        Import-Csv -Path $InputCsv | ForEach-Object { $_.ILOHost } | Where-Object { $_ }
    }
    else { $ILOHost }
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
        'COMPLIANT'            { 'Green' }
        'ROM_OK_CERTS_UNKNOWN' { 'Yellow' }
        'ERROR'                { 'Red' }
        'NOT_SUPPORTED'        { 'Red' }
        default                { 'Yellow' }
    }
    Write-Host ('{0,-24} {1}' -f $g.Name, $g.Count) -ForegroundColor $color
}
Write-Host ''

$results

#endregion
