#Requires -Version 5.1
<#
.SYNOPSIS
    Audits ESXi hosts and virtual machines for readiness against the Microsoft 2011
    Secure Boot CA expiration.

.DESCRIPTION
    READ-ONLY. Nothing is changed, nothing is rebooted, no snapshots are taken.

    HOSTS
        Checks the ESXi build against the point at which the bootloader became
        multi-signed with both the 2011 and 2023 certificates:

            ESX  9.1.0.0        build 25370933   (2026-05-12)
            ESXi 8.0 U3j (P09)  build 25429389   (2026-05-27)

        vSphere 7.x will never receive a multi-signed bootloader (End of General
        Support 2025-10-02), which makes this a concrete upgrade driver.

        Note that hosts are not the exposure. Broadcom KB 434297: "There is no impact
        on Secure Boot-enabled ESX hosts, and no immediate action is necessary."

    VIRTUAL MACHINES
        This is where the real exposure is. A VM's Secure Boot variables live in its
        <vm>.nvram file, which is seeded ONCE - at NVRAM creation - from the EFI
        firmware image of the host that created it. Patching the host does NOT
        re-seed existing VMs, and neither does a virtual hardware version upgrade.

            ESXi < 8.0 U2, or HW 13   -> 2011 certificates only, PK = VMW.NULLPK
            ESXi 8.0 U2 .. U3i, HW 14+-> 2023 KEK/db present, but PK = VMW.NULLPK,
                                         so KEK/db can never be updated again
            ESXi 8.0 U3j+ / 9.x       -> SilentPK adds the Windows OEM Devices PK
                                         (VMs WITHOUT vTPM, at power cycle)

    COMMON MISCONCEPTION, CORRECTED
        The VMware PK is not "expired". It is VMW.NULLPK - a placeholder with a NULL
        signature: no X.509, therefore no expiry date. The expired "VMware
        Certificate" (Dec 2019) that circulates in blog posts sits in db and is
        inert. What NULL PK actually does is prevent KEK updates from being
        authorised, which surfaces in Windows as Event ID 1803.

    DO NOT DELETE OR RENAME .nvram
        Broadcom withdrew that guidance - KB 423919 replaced KB 421593 explicitly
        "to avoid suggestions of deleting NVRAM, as that behavior can lead to
        unexpected corruptions of the associated VM". On a vTPM VM it destroys the
        vTPM state and with it the BitLocker / LUKS keys, irreversibly.

.PARAMETER Server
    vCenter or standalone ESXi host. Omit if already connected via Connect-VIServer.

.PARAMETER Credential
    vCenter credentials.

.PARAMETER IncludeGuestCheck
    Runs an in-guest check through Invoke-VMScript (requires VMware Tools and guest
    credentials). This is the only reliable verification: the vSphere API cannot read
    NVRAM contents.

.PARAMETER GuestCredential
    Windows guest credentials for -IncludeGuestCheck.

.EXAMPLE
    Connect-VIServer vcsa01
    .\VMware-SecureBootAudit.ps1 |
        Format-Table Name,PowerState,HWVersion,SecureBoot,vTPM,HostBuild,Risk -AutoSize

.EXAMPLE
    .\VMware-SecureBootAudit.ps1 -OutputCsv .\vmware-audit.csv |
        Where-Object Risk -in 'HIGH','MEDIUM' | Format-Table Name,HWVersion,vTPM,Risk,Action -AutoSize

.LINK
    https://knowledge.broadcom.com/external/article/423893/secure-boot-certificate-expirations-and.html

.NOTES
    Project : uefi-secureboot-audit
    Version : 2.0
    Requires: VMware.PowerCLI
    Licence : MIT. Provided as-is, with no warranty. Not affiliated with, endorsed by,
              or supported by Broadcom, VMware, HPE or Microsoft.
#>
[CmdletBinding()]
param(
    [string]$Server,
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$IncludeGuestCheck,
    [System.Management.Automation.PSCredential]$GuestCredential,
    [string]$OutputCsv,
    [string]$OutputJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- reference builds --------------------------------------------------------
$script:SilentPkMinBuild = 25429389   # ESXi 8.0 U3j (P09)
$script:Esx91Build       = 25370933   # ESX 9.1.0.0

function Test-HostMultiSigned {
    <# Build numbers are monotonic across branches, but check the line too so a
       9.0.x build is not accidentally judged against the 8.0 threshold. #>
    param([string]$Version, [int]$Build)
    if ($Version -like '9.*') { return ($Build -ge $script:Esx91Build) }
    if ($Version -like '8.*') { return ($Build -ge $script:SilentPkMinBuild) }
    return $false                       # 7.x and older: never
}

function Get-HostReport {
    Get-VMHost | ForEach-Object {
        $h = $_
        $multi = Test-HostMultiSigned -Version $h.Version -Build ([int]$h.Build)
        $tpm = $null
        try { $tpm = $h.ExtensionData.Capability.TpmSupported } catch { Write-Verbose "Optional property unavailable" }

        $action = if ($h.Version -like '7.*') {
            'vSphere 7 is past End of General Support and will not receive a multi-signed bootloader. Plan an upgrade to 8.0 U3j+ / 9.1.'
        }
        elseif ($multi) { 'OK - bootloader is multi-signed 2011 + 2023. No action.' }
        else { 'Patch to ESXi 8.0 U3j (25429389) / ESX 9.1 (25370933) for the multi-signed bootloader and SilentPK support for VMs.' }

        [pscustomobject]@{
            Type            = 'HOST'
            Name            = $h.Name
            Version         = $h.Version
            Build           = $h.Build
            ConnectionState = $h.ConnectionState
            TpmSupported    = $tpm
            MultiSigned     = $multi
            SilentPkCapable = ([int]$h.Build -ge $script:SilentPkMinBuild)
            Risk            = if ($multi) { 'LOW' } elseif ($h.Version -like '7.*') { 'HIGH' } else { 'MEDIUM' }
            Action          = $action
        }
    }
}

function Get-VmReport {
    $hostCache = @{}
    Get-VMHost | ForEach-Object { $hostCache[$_.Id] = $_ }

    Get-VM | ForEach-Object {
        $vm  = $_
        $cfg = $vm.ExtensionData.Config

        $firmware  = [string]$cfg.Firmware
        $sbEnabled = $false
        try {
            if ($cfg.BootOptions -and $null -ne $cfg.BootOptions.EfiSecureBootEnabled) {
                $sbEnabled = [bool]$cfg.BootOptions.EfiSecureBootEnabled
            }
        } catch { $sbEnabled = $false }

        $hwVer = [string]$cfg.Version                       # e.g. 'vmx-21'
        $hwNum = 0
        if ($hwVer -match 'vmx-(\d+)') { $hwNum = [int]$Matches[1] }

        $hasVtpm = [bool](@($cfg.Hardware.Device | Where-Object { $_ -is [VMware.Vim.VirtualTPM] }).Count -gt 0)

        $vmHost = $null
        try { $vmHost = $hostCache[$vm.VMHostId] } catch { Write-Verbose "Optional property unavailable" }
        if (-not $vmHost) { try { $vmHost = Get-VMHost -VM $vm -ErrorAction SilentlyContinue } catch { Write-Verbose "Host lookup fallback failed for $($vm.Name)" } }
        $hostVer   = if ($vmHost) { [string]$vmHost.Version } else { $null }
        $hostBuild = if ($vmHost) { [int]$vmHost.Build } else { 0 }

        $guestFam = ''
        try { $guestFam = [string]$vm.Guest.GuestFamily } catch { Write-Verbose "Optional property unavailable" }
        if (-not $guestFam) { try { $guestFam = [string]$cfg.GuestFullName } catch { Write-Verbose "GuestFullName unavailable" } }
        $isWindowsGuest = $guestFam -match 'windows'

        # ---- risk classification, per Broadcom KB 423893 scenarios ----
        $risk = 'LOW'; $action = ''

        if ($firmware -ne 'efi') {
            $risk = 'NA'
            $action = 'BIOS firmware - Secure Boot does not apply.'
        }
        elseif (-not $sbEnabled) {
            $risk = 'LOW'
            $action = 'Secure Boot disabled - no immediate impact. NVRAM certificates still age; remediation will be needed before it can be turned on.'
        }
        elseif ($hwNum -lt 14) {
            $risk = 'HIGH'
            $action = "Hardware version $hwVer is below 14, so no PK update is possible by any method. Upgrade VM hardware and apply the manual vUEFI enrolment from KB 423919, or recreate the VM on a U3j+ host."
        }
        elseif ($hostBuild -ge $script:SilentPkMinBuild -and -not $hasVtpm) {
            $risk = 'LOW'
            $action = 'Host is U3j+/9.x and the VM has no vTPM: SilentPK adds the PK at the next power cycle. Then run the in-guest servicing (Windows AvailableUpdates=0x5944).'
        }
        elseif ($hostBuild -ge $script:SilentPkMinBuild -and $hasVtpm -and $isWindowsGuest) {
            $risk = 'MEDIUM'
            $action = 'Windows + vTPM on U3j+: Broadcom recommends WAITING for the capsule-based solution. Manual intervention risks BitLocker recovery. For now, escrow recovery keys.'
        }
        elseif ($hostBuild -ge $script:SilentPkMinBuild -and $hasVtpm) {
            $risk = 'MEDIUM'
            $action = 'Non-Windows + vTPM on U3j+: use the VMX parameter uefi.secureBoot.PK.resetOnce = "TRUE" on the powered-off VM. Plan the TPM-bound LUKS re-seal first - PCR7 changes.'
        }
        else {
            $risk = 'HIGH'
            $action = "Host $hostVer build $hostBuild is below U3j. This VM has VMW.NULLPK, so KEK/db can no longer be updated - it will never receive future DBX revocations. Patch the host to 8.0 U3j+, or apply the manual vUEFI enrolment from KB 423919."
        }

        [pscustomobject]@{
            Type              = 'VM'
            Name              = $vm.Name
            PowerState        = [string]$vm.PowerState
            Firmware          = $firmware
            SecureBoot        = $sbEnabled
            HWVersion         = $hwVer
            vTPM              = $hasVtpm
            GuestFamily       = $guestFam
            VMHost            = if ($vmHost) { $vmHost.Name } else { $null }
            HostVersion       = $hostVer
            HostBuild         = $hostBuild
            SilentPkCapable   = ($hostBuild -ge $script:SilentPkMinBuild)
            LegacySeedSuspect = ($hwNum -lt 14)
            Risk              = $risk
            Action            = $action
            GuestKEK2023      = $null
            GuestDb2023       = $null
            GuestPK           = $null
            GuestServicing    = $null
        }
    }
}

# In-guest verification: the only way to actually see NVRAM contents.
# Note: Get-SecureBootUEFI -Name PK throwing "Cannot index into a null array" is the
# in-guest fingerprint of VMW.NULLPK.
$script:GuestScript = @'
$out = [ordered]@{}
try { $out.SecureBoot = [string](Confirm-SecureBootUEFI) } catch { $out.SecureBoot = 'N/A' }
function Get-VarText($n) {
  try { [Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI -Name $n).Bytes) } catch { '' }
}
$db  = Get-VarText 'db'
$kek = Get-VarText 'KEK'
try { $pk = (Get-SecureBootUEFI -Name PK).Bytes.Length } catch { $pk = 0 }
$out.PKBytes             = $pk
$out.KEK2023             = [bool]($kek -match 'Microsoft Corporation KEK 2K CA 2023')
$out.WindowsUEFICA2023   = [bool]($db  -match 'Windows UEFI CA 2023')
$out.MicrosoftUEFICA2023 = [bool]($db  -match 'Microsoft UEFI CA 2023')
$out.OptionRomCA2023     = [bool]($db  -match 'Microsoft Option ROM UEFI CA 2023')
try {
  $s = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -ErrorAction Stop
  $out.UEFICA2023Status = [string]$s.UEFICA2023Status
  $out.UEFICA2023Error  = [string]$s.UEFICA2023Error
} catch { $out.UEFICA2023Status = 'n/a' }
try {
  $a = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -ErrorAction Stop
  $out.AvailableUpdates = ('0x{0:X}' -f [int]$a.AvailableUpdates)
} catch { $out.AvailableUpdates = 'n/a' }
($out.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '|'
'@

function Invoke-GuestCheck {
    param($Rows)
    if (-not $GuestCredential) { throw '-IncludeGuestCheck requires -GuestCredential.' }

    foreach ($r in $Rows) {
        if ($r.Type -ne 'VM' -or $r.PowerState -ne 'PoweredOn' -or $r.GuestFamily -notmatch 'windows') { continue }
        try {
            $res = Invoke-VMScript -VM $r.Name -ScriptText $script:GuestScript -ScriptType Powershell `
                                   -GuestCredential $GuestCredential -ErrorAction Stop
            $kv = @{}
            foreach ($pair in ($res.ScriptOutput.Trim() -split '\|')) {
                $k, $v = $pair -split '=', 2
                if ($k) { $kv[$k.Trim()] = $v }
            }
            $r.GuestKEK2023   = $kv['KEK2023']
            $r.GuestDb2023    = "$($kv['WindowsUEFICA2023'])/$($kv['MicrosoftUEFICA2023'])/$($kv['OptionRomCA2023'])"
            $r.GuestPK        = if ([int]($kv['PKBytes']) -gt 0) { "$($kv['PKBytes'])B" } else { 'NULL/absent' }
            $r.GuestServicing = "$($kv['UEFICA2023Status']) AU=$($kv['AvailableUpdates'])"
        }
        catch { $r.GuestServicing = "guest check failed: $($_.Exception.Message)" }
    }
}

# ------------------------------------------------------------------ run

if ($Server) {
    $connParams = @{ Server = $Server; ErrorAction = 'Stop' }
    if ($Credential) { $connParams.Credential = $Credential }
    $null = Connect-VIServer @connParams
}
$connected = @(Get-Variable -Name 'DefaultVIServers' -Scope Global -ValueOnly -ErrorAction SilentlyContinue)
if ($connected.Count -eq 0) {
    throw 'Not connected to vCenter. Use -Server or Connect-VIServer first.'
}

$rows = New-Object System.Collections.Generic.List[object]
Get-HostReport | ForEach-Object { $rows.Add($_) }
Get-VmReport   | ForEach-Object { $rows.Add($_) }

if ($IncludeGuestCheck) { Invoke-GuestCheck -Rows $rows }

if ($OutputCsv)  { $rows | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8 }
if ($OutputJson) { $rows | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputJson -Encoding UTF8 }

Write-Host ''
Write-Host '=== Risk summary ===' -ForegroundColor Cyan
$rows | Group-Object Type, Risk | Sort-Object Name | ForEach-Object {
    Write-Host ('{0,-16} {1}' -f $_.Name, $_.Count)
}
Write-Host ''

$rows
