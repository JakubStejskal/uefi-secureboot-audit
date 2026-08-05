#Requires -Version 5.1
<#
.SYNOPSIS
    Staged remediation of UEFI Secure Boot keys on HPE ProLiant Gen10 / Gen10 Plus /
    Gen11 via iLO Redfish - activating the Microsoft 2023 certificates after a
    System ROM update.

.DESCRIPTION
    *** DESTRUCTIVE. READ THIS ENTIRE BLOCK BEFORE RUNNING. ***

    Implements the official HPE procedure from Customer Advisory a00156355en_us:

        1) POST SecureBoot.ResetKeys  { "ResetKeysType": "ResetAllKeysToDefault" }
        2) reboot
        3) PATCH /SecureBoot          { "SecureBootEnable": true }
        4) reboot

    A System ROM update ALONE IS NOT ENOUGH. Flashing the ROM refreshes only the
    read-only *Default databases (PKDefault, KEKDefault, dbDefault, dbxDefault). The
    live UEFI NVRAM variables are untouched. HPE states it plainly: "Defaults are not
    used at runtime." The new keys reach the live databases only via an explicit
    reset to platform defaults.

    RISKS - deliberately not softened:

    * "Reset All Keys to Platform Defaults" DELETES EVERY customer-enrolled key
      (custom PK, MOK, OS-vendor certificates). It is a replace, not a merge.

    * The reset ALSO TURNS SECURE BOOT OFF. Between stage 1 and stage 3 the server
      runs unprotected. Stage 3 turns it back on.

    * If the System ROM is BELOW the advisory baseline, the reset restores 2011-only
      defaults - a silent REGRESSION. Preflight blocks this. -Force overrides; don't.

    * ESXi with TPM: changing Secure Boot state breaks configuration unsealing and
      the host will PSOD with "Unable to restore the system configuration. A security
      violation was detected". BEFORE running this you MUST have the recovery key:
          esxcli system settings encryption recovery list        # store OFF-host
      Recovery: at boot press SHIFT+O, append after bootUUID=... a space and
          encryptionRecoveryKey=######-######-...
      After a successful boot: /sbin/auto-backup.sh
      Broadcom is explicit that configuration backups alone cannot recover this.

    * Windows with BitLocker: PCR7 changes, triggering a recovery prompt.
          Suspend-BitLocker -MountPoint C: -RebootCount 2
      Escrow recovery keys first regardless.

    * Linux with TPM-sealed LUKS (clevis / systemd-cryptenroll): re-seal required
      after the db change.

    * HPE's own option ROM signing certificate lives in the default db. Do not
      hand-curate the database as an alternative to resetting to defaults - dropping
      the HPE entry means Smart Array / NIC option ROMs will not load and the server
      will not boot with Secure Boot enabled.

    * Gen12 DOES NOT NEED THIS. The 2023 certificates are included and enabled from
      the first factory BIOS. Preflight refuses Gen12.

    * Gen9 CANNOT BE FIXED THIS WAY. No Gen9 System ROM contains the 2023
      certificates. Preflight refuses Gen9.

    Recommended sequence: shut the OS down cleanly, leave the server powered off,
    reset keys, re-enable Secure Boot, and only then boot the OS. Budget three
    reboots per server.

.PARAMETER ILOHost
    iLO hostname / IP.

.PARAMETER Credential
    iLO account with 'Configure iLO Settings' privilege (required for POST/PATCH).

.PARAMETER Stage
    ResetKeys        - stage 1: reset to platform defaults (deletes keys, disables Secure Boot)
    EnableSecureBoot - stage 3: re-enable Secure Boot
    Verify           - read-only verification of the result

.PARAMETER BackupPath
    Directory for the pre-reset key export. Default .\secureboot-backup

.PARAMETER Force
    Override preflight blocks. Use only deliberately.

.EXAMPLE
    # Dry run first - nothing is sent
    .\HPE-SecureBootRemediate.ps1 -ILOHost ilo-esx01 -Credential $c -Stage ResetKeys -SkipCertificateCheck -WhatIf

.EXAMPLE
    # 1. reset keys, then reboot the server
    .\HPE-SecureBootRemediate.ps1 -ILOHost ilo-esx01 -Credential $c -Stage ResetKeys -SkipCertificateCheck
    # 2. re-enable Secure Boot, then reboot again
    .\HPE-SecureBootRemediate.ps1 -ILOHost ilo-esx01 -Credential $c -Stage EnableSecureBoot -SkipCertificateCheck
    # 3. verify
    .\HPE-SecureBootRemediate.ps1 -ILOHost ilo-esx01 -Credential $c -Stage Verify -SkipCertificateCheck

.LINK
    https://support.hpe.com/hpesc/public/docDisplay?docId=a00156355en_us

.NOTES
    Project : uefi-secureboot-audit
    Version : 2.0
    Licence : MIT. Provided as-is, with no warranty. Not affiliated with, endorsed by,
              or supported by HPE, Broadcom or Microsoft. Always validate on a lab
              server before touching production.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory, Position = 0)][string]$ILOHost,
    [Parameter(Mandatory)][System.Management.Automation.PSCredential]$Credential,
    [Parameter(Mandatory)][ValidateSet('ResetKeys', 'EnableSecureBoot', 'Verify')][string]$Stage,
    [string]$BackupPath = '.\secureboot-backup',
    [switch]$SkipCertificateCheck,
    [switch]$Force,
    [ValidateRange(5, 600)][int]$TimeoutSec = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Minimum System ROM per HPE advisory a00156355en_us rev. 5 (2026-07-02).
$script:RomBaseline = @{
    'Gen10|Intel' = '3.62'; 'Gen10|AMD' = '3.70'
    'Gen10 Plus|Intel' = '2.30'; 'Gen10 Plus|AMD' = '3.50'
    'Gen11|Intel' = '2.42'; 'Gen11|AMD' = '2.30'
}
$script:Required2023 = @(
    'Microsoft Corporation KEK 2K CA 2023', 'Windows UEFI CA 2023',
    'Microsoft UEFI CA 2023', 'Microsoft Option ROM UEFI CA 2023'
)

#region ---------------------------------------------- transport (mirrors the audit script)

$script:OriginalCallback = $null; $script:CallbackModified = $false

function Initialize-TlsBypass {
    if (-not $SkipCertificateCheck -or $PSVersionTable.PSVersion.Major -ge 6) { return }
    $script:OriginalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    $script:CallbackModified = $true
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}
function Restore-TlsBypass {
    if ($script:CallbackModified) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $script:OriginalCallback
        $script:CallbackModified = $false
    }
}

function Get-Prop {
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
    param(
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers = @{},
        [string]$Method = 'GET',
        [object]$Body,
        [switch]$AllowNotFound
    )
    $splat = @{ Uri = $Uri; Method = $Method; Headers = $Headers; TimeoutSec = $TimeoutSec; ErrorAction = 'Stop' }
    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
        $splat.Body = ($Body | ConvertTo-Json -Depth 6 -Compress); $splat.ContentType = 'application/json'
    }
    if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -ge 6) { $splat.SkipCertificateCheck = $true }
    try { return Invoke-RestMethod @splat }
    catch {
        $status = $null
        if ($_.Exception.PSObject.Properties.Name -contains 'Response' -and $_.Exception.Response) {
            try { $status = [int]$_.Exception.Response.StatusCode } catch { Write-Verbose "Session cleanup failed; it will expire on its own" }
        }
        if ($AllowNotFound -and $status -in 404, 400) { return $null }
        throw
    }
}

function Connect-ILO {
    param([string]$HostName)
    $base = "https://$HostName"
    $body = @{ UserName = $Credential.UserName; Password = $Credential.GetNetworkCredential().Password }
    $splat = @{
        Uri = "$base/redfish/v1/SessionService/Sessions/"; Method = 'POST'
        Body = ($body | ConvertTo-Json -Compress); ContentType = 'application/json'
        TimeoutSec = $TimeoutSec; ErrorAction = 'Stop'
    }
    if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -ge 6) { $splat.SkipCertificateCheck = $true }
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $null = Invoke-RestMethod @splat -ResponseHeadersVariable rh
        $token = $rh['X-Auth-Token'] | Select-Object -First 1
        $loc   = $rh['Location']     | Select-Object -First 1
    } else {
        $resp  = Invoke-WebRequest @splat -UseBasicParsing
        $token = $resp.Headers['X-Auth-Token']; $loc = $resp.Headers['Location']
    }
    if (-not $token) { throw "iLO $HostName : no X-Auth-Token returned." }
    if ($loc -and $loc -notmatch '^https?://') { $loc = "$base$loc" }
    [pscustomobject]@{ Base = $base; Headers = @{ 'X-Auth-Token' = $token; 'OData-Version' = '4.0' }; Session = $loc }
}
function Disconnect-ILO {
    param($Conn)
    if ($Conn -and $Conn.Session) {
        try { $null = Invoke-Redfish -Uri $Conn.Session -Headers $Conn.Headers -Method DELETE -AllowNotFound } catch { Write-Verbose "Session cleanup failed; it will expire on its own" }
    }
}

#endregion

function Get-Context {
    param($Conn)
    $mgrCol = Invoke-Redfish -Uri "$($Conn.Base)/redfish/v1/Managers/" -Headers $Conn.Headers
    $mgr    = Invoke-Redfish -Uri "$($Conn.Base)$($mgrCol.Members[0].'@odata.id')" -Headers $Conn.Headers
    $iloTag = "$(Get-Prop $mgr 'Model' '')$(Get-Prop $mgr 'FirmwareVersion' '')"
    $iloGen = if ($iloTag -match 'iLO\s*(\d)') { [int]$Matches[1] } else { 0 }

    $sysCol = Invoke-Redfish -Uri "$($Conn.Base)/redfish/v1/Systems/" -Headers $Conn.Headers
    $sysUri = "$($Conn.Base)$($sysCol.Members[0].'@odata.id')"
    $sys    = Invoke-Redfish -Uri $sysUri -Headers $Conn.Headers

    $model = [string](Get-Prop $sys 'Model' '')
    $bios  = [string](Get-Prop $sys 'BiosVersion' '')

    $gen = switch -Regex ($model) {
        'Gen12' { 'Gen12'; break } 'Gen11' { 'Gen11'; break }
        'Gen10\s*Plus' { 'Gen10 Plus'; break } 'Gen10' { 'Gen10'; break }
        'Gen9' { 'Gen9'; break } default { 'Unknown' }
    }
    $cpu  = [string](Get-Prop (Get-Prop $sys 'ProcessorSummary') 'Model' '')
    $arch = if ($cpu -match 'AMD|EPYC') { 'AMD' } else { 'Intel' }

    $romVer = $null
    if ($bios -match 'v(\d+\.\d+(\.\d+)?)') { $romVer = [version]$Matches[1] }

    $req = $null
    if ($gen -eq 'Gen10' -and $arch -eq 'Intel' -and $model -match 'DL20|ML30|m750') { $req = [version]'3.72' }
    elseif ($script:RomBaseline.ContainsKey("$gen|$arch")) { $req = [version]$script:RomBaseline["$gen|$arch"] }

    $sb = Invoke-Redfish -Uri "$sysUri/SecureBoot" -Headers $Conn.Headers -AllowNotFound

    [pscustomobject]@{
        SystemUri     = $sysUri
        SecureBootUri = "$sysUri/SecureBoot"
        Model         = $model
        Serial        = [string](Get-Prop $sys 'SerialNumber' '')
        PowerState    = [string](Get-Prop $sys 'PowerState' '')
        Generation    = $gen
        Arch          = $arch
        BiosVersion   = $bios
        RomVersion    = $romVer
        RomRequired   = $req
        ILOGeneration = $iloGen
        SecureBoot    = $sb
    }
}

function Get-CertInventory {
    param($Conn, [string]$SecureBootUri)
    $dbCol = Invoke-Redfish -Uri "$SecureBootUri/SecureBootDatabases" -Headers $Conn.Headers -AllowNotFound
    if (-not $dbCol -or -not ($dbCol.PSObject.Properties.Name -contains 'Members')) { return $null }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($m in $dbCol.Members) {
        $id = ($m.'@odata.id' -split '/')[-1]
        if ($id -match 'Default$' -or $id -notin 'PK', 'KEK', 'db', 'dbx') { continue }
        $cc = Invoke-Redfish -Uri "$($Conn.Base)$($m.'@odata.id')/Certificates" -Headers $Conn.Headers -AllowNotFound
        if (-not $cc -or -not ($cc.PSObject.Properties.Name -contains 'Members')) { continue }
        foreach ($cm in $cc.Members) {
            $c = Invoke-Redfish -Uri "$($Conn.Base)$($cm.'@odata.id')" -Headers $Conn.Headers -AllowNotFound
            if (-not $c) { continue }
            $out.Add([pscustomobject]@{
                Database   = $id
                CommonName = [string](Get-Prop (Get-Prop $c 'Subject') 'CommonName')
                NotAfter   = Get-Prop $c 'ValidNotAfter'
                Pem        = Get-Prop $c 'CertificateString'
            })
        }
    }
    return $out.ToArray()
}

function Save-KeyBackup {
    param($Certs, [string]$HostName)
    if (-not $Certs -or $Certs.Count -eq 0) {
        Write-Warning @'
No key backup could be taken - this iLO does not expose the certificate inventory.
On Gen10 / Gen10 Plus (iLO 5) export manually before proceeding:
  RBSU -> Server Security -> Secure Boot Settings -> Advanced Secure Boot Options -> Export all keys
'@
        return $null
    }
    $dir = Join-Path $BackupPath ('{0}_{1}' -f $HostName, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $null = New-Item -ItemType Directory -Path $dir -Force
    $Certs | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $dir 'certificates.json') -Encoding UTF8
    $i = 0
    foreach ($c in $Certs) {
        if (-not $c.Pem) { continue }
        $i++
        $safe = ($c.CommonName -replace '[^\w\.\- ]', '_')
        $c.Pem | Set-Content -Path (Join-Path $dir ('{0:D2}_{1}_{2}.pem' -f $i, $c.Database, $safe)) -Encoding ASCII
    }
    Write-Host "Key backup written to: $dir" -ForegroundColor Green
    return $dir
}

function Test-Preflight {
    param($Ctx)
    $blocks = @(); $warns = @()

    if ($Ctx.Generation -eq 'Gen12') {
        $blocks += 'Gen12 already has the 2023 certificates enabled from the factory. A reset gains nothing and discards any custom keys.'
    }
    if ($Ctx.Generation -eq 'Gen9') {
        $blocks += 'Gen9 System ROMs do not contain the 2023 certificates. A reset would restore 2011-only defaults.'
    }
    if ($Ctx.RomRequired -and $Ctx.RomVersion -and $Ctx.RomVersion -lt $Ctx.RomRequired) {
        $blocks += "System ROM $($Ctx.RomVersion) is below the baseline $($Ctx.RomRequired). Resetting now would restore 2011-only defaults (REGRESSION). Flash the ROM first."
    }
    if (-not $Ctx.RomVersion) {
        $warns += 'System ROM version could not be determined - verify manually against advisory a00156355en_us.'
    }
    if ($Ctx.PowerState -eq 'On') {
        $warns += 'Server is powered on. HPE recommends running Secure Boot database operations with the system powered off; the BIOS processes the change at the next POST either way.'
    }
    [pscustomobject]@{ Blocks = $blocks; Warnings = $warns }
}

# ------------------------------------------------------------------ main

$conn = $null
try {
    Initialize-TlsBypass
    $conn = Connect-ILO -HostName $ILOHost
    $ctx  = Get-Context -Conn $conn

    Write-Host ''
    Write-Host "Host        : $ILOHost"
    Write-Host "Model       : $($ctx.Model)  (SN $($ctx.Serial))"
    Write-Host "Generation  : $($ctx.Generation) / $($ctx.Arch)   iLO $($ctx.ILOGeneration)"
    Write-Host "System ROM  : $($ctx.BiosVersion)   baseline: $($ctx.RomRequired)"
    Write-Host "Power state : $($ctx.PowerState)"
    if ($ctx.SecureBoot) {
        Write-Host ('Secure Boot : Enable={0} CurrentBoot={1} Mode={2}' -f `
            (Get-Prop $ctx.SecureBoot 'SecureBootEnable'),
            (Get-Prop $ctx.SecureBoot 'SecureBootCurrentBoot'),
            (Get-Prop $ctx.SecureBoot 'SecureBootMode'))
    }
    Write-Host ''

    $certs = $null
    if ($ctx.ILOGeneration -ge 6) { $certs = Get-CertInventory -Conn $conn -SecureBootUri $ctx.SecureBootUri }

    switch ($Stage) {

        'Verify' {
            if ($null -eq $certs) {
                Write-Warning "iLO $($ctx.ILOGeneration) does not expose the Secure Boot database inventory (iLO 5 = Gen10 / Gen10 Plus). Verify in the Embedded UEFI Shell:  secboot -l KEK   and   secboot -l db"
                $romVerdict = if ($ctx.RomVersion -and $ctx.RomRequired -and $ctx.RomVersion -ge $ctx.RomRequired) { 'ROM OK' } else { 'ROM BELOW BASELINE' }
                Write-Host "Indirect signal only: System ROM $($ctx.BiosVersion) vs baseline $($ctx.RomRequired) -> $romVerdict"
                break
            }
            $certs | Sort-Object Database, CommonName | Format-Table Database, CommonName, NotAfter -AutoSize
            $cns = @($certs | ForEach-Object { $_.CommonName })
            $missing = @($script:Required2023 | Where-Object { $cns -notcontains $_ })
            if ($missing.Count -eq 0) { Write-Host 'All four 2023 certificates are present.' -ForegroundColor Green }
            else { Write-Host "MISSING: $($missing -join ', ')" -ForegroundColor Yellow }
        }

        'ResetKeys' {
            $pf = Test-Preflight -Ctx $ctx
            foreach ($w in $pf.Warnings) { Write-Warning $w }
            if ($pf.Blocks.Count -gt 0) {
                foreach ($b in $pf.Blocks) { Write-Host "BLOCKED: $b" -ForegroundColor Red }
                if (-not $Force) { throw 'Preflight blocked this operation. Fix the cause, or override with -Force if you understand the consequences.' }
                Write-Warning 'Preflight overridden with -Force.'
            }

            Save-KeyBackup -Certs $certs -HostName $ILOHost | Out-Null

            Write-Host ''
            Write-Host 'ABOUT TO RUN: SecureBoot.ResetKeys / ResetAllKeysToDefault' -ForegroundColor Yellow
            Write-Host '  -> deletes ALL enrolled keys and DISABLES Secure Boot' -ForegroundColor Yellow
            Write-Host '  -> ESXi with TPM and no saved recovery key: unrecoverable PSOD' -ForegroundColor Yellow
            Write-Host '  -> Windows with BitLocker not suspended: recovery prompt' -ForegroundColor Yellow
            Write-Host ''

            if ($PSCmdlet.ShouldProcess("$ILOHost ($($ctx.Model))", 'SecureBoot.ResetKeys = ResetAllKeysToDefault')) {
                $uri = "$($ctx.SecureBootUri)/Actions/SecureBoot.ResetKeys"
                $res = Invoke-Redfish -Uri $uri -Headers $conn.Headers -Method POST -Body @{ ResetKeysType = 'ResetAllKeysToDefault' }
                Write-Host 'ResetKeys submitted. The BIOS applies it at the next POST.' -ForegroundColor Green
                Write-Host 'NEXT: reboot the server, then run -Stage EnableSecureBoot.' -ForegroundColor Cyan
                if ($res) { $res | ConvertTo-Json -Depth 4 }
            }
        }

        'EnableSecureBoot' {
            if ((Get-Prop $ctx.SecureBoot 'SecureBootEnable') -eq $true) {
                Write-Host 'SecureBootEnable is already true - nothing to do.' -ForegroundColor Green
                break
            }
            if ($PSCmdlet.ShouldProcess("$ILOHost ($($ctx.Model))", 'PATCH SecureBootEnable = true')) {
                $null = Invoke-Redfish -Uri $ctx.SecureBootUri -Headers $conn.Headers -Method PATCH -Body @{ SecureBootEnable = $true }
                Write-Host 'SecureBootEnable=true set. Applied at the next reboot.' -ForegroundColor Green
                Write-Host 'NEXT: reboot, then run -Stage Verify.' -ForegroundColor Cyan
                Write-Host 'ESXi: run /sbin/auto-backup.sh once the host is up, or the state is not re-sealed.' -ForegroundColor Cyan
            }
        }
    }
}
finally {
    Disconnect-ILO -Conn $conn
    Restore-TlsBypass
}
