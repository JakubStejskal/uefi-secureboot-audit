#Requires -Version 5.1
<#
.SYNOPSIS
    Inventura Secure Boot nastavení na virtuálních strojích v VMware vSphere.
    Vyžaduje VMware PowerCLI.

.DESCRIPTION
    Připojí se na vCenter, projde všechny VM (nebo filtrované) a zkontroluje:
      - Zda je Secure Boot povoleno (EFI firmware + SecureBootEnabled)
      - Typ firmware (BIOS/EFI)
      - Guest OS
      - Stav VM (PoweredOn/Off)

    Výstup: konzole + volitelný CSV export.

.PARAMETER VCenterAddress
    FQDN nebo IP vCenter Serveru.

.PARAMETER VCenterCredential
    PSCredential pro vCenter.

.PARAMETER VMFilter
    Wildcard filter názvu VM (default: '*' = všechny).

.PARAMETER Datacenter
    Volitelný filter datacentra.

.PARAMETER Cluster
    Volitelný filter clusteru.

.PARAMETER ExportCsv
    Cesta pro CSV export.

.PARAMETER ShowOnlyNoSecureBoot
    Zobrazí pouze VM bez Secure Boot (pro rychlý přehled co je potřeba opravit).

.EXAMPLE
    $cred = Get-Credential
    .\Inventory-SecureBootVMs.ps1 -VCenterAddress vc.lab.local -VCenterCredential $cred

.EXAMPLE
    .\Inventory-SecureBootVMs.ps1 -VCenterAddress vc.lab.local -VCenterCredential $cred `
        -Cluster 'Prod-Cluster-01' -ExportCsv vm-secureboot.csv

.EXAMPLE
    # Pouze VM bez Secure Boot
    .\Inventory-SecureBootVMs.ps1 -VCenterAddress vc.lab.local -VCenterCredential $cred `
        -ShowOnlyNoSecureBoot

.NOTES
    Požadavky:
      Install-Module VMware.PowerCLI -Scope CurrentUser

    Secure Boot na VM vyžaduje:
      - EFI firmware (ne BIOS)
      - Hardware version 13+ (vSphere 6.5+)
      - Guest OS podporující Secure Boot (Windows 2016+, RHEL 7+, Ubuntu 18.04+)

    Zdroj: VMware KB 2142235, HPE TAM session 02/2026
#>
param(
    [Parameter(Mandatory)][string]$VCenterAddress,
    [Parameter(Mandatory)][PSCredential]$VCenterCredential,
    [string]$VMFilter            = '*',
    [string]$Datacenter          = '',
    [string]$Cluster             = '',
    [string]$ExportCsv           = '',
    [switch]$ShowOnlyNoSecureBoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

function Write-Banner {
    param([string]$Text, [string]$Color = 'Cyan')
    Write-Host "`n$('=' * 60)" -ForegroundColor $Color
    Write-Host "  $Text"        -ForegroundColor $Color
    Write-Host "$('=' * 60)"    -ForegroundColor $Color
}

# ── Kontrola PowerCLI ──────────────────────────────────────────────────────────
if (-not (Get-Module -ListAvailable -Name 'VMware.PowerCLI' -ErrorAction SilentlyContinue)) {
    Write-Host "[CHYBA] VMware.PowerCLI modul není nainstalován!" -ForegroundColor Red
    Write-Host "Instalace: Install-Module VMware.PowerCLI -Scope CurrentUser"
    exit 1
}

# Suppress CEIP prompt
$null = Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session 2>$null
$null = Set-PowerCLIConfiguration -ParticipateInCeip $false -Confirm:$false -Scope Session 2>$null

# ── Připojení na vCenter ───────────────────────────────────────────────────────
Write-Banner "Připojuji se na vCenter: $VCenterAddress"
try {
    $null = Connect-VIServer -Server $VCenterAddress -Credential $VCenterCredential -ErrorAction Stop
    Write-Host "[OK] Připojeno: $VCenterAddress" -ForegroundColor Green
} catch {
    Write-Host "[CHYBA] Nelze se připojit na vCenter: $_" -ForegroundColor Red
    exit 1
}

# ── Načtení VM ─────────────────────────────────────────────────────────────────
Write-Banner "Načítám VM (filter: '$VMFilter')"

$getVmParams = @{ Name = $VMFilter; ErrorAction = 'SilentlyContinue' }
if ($Datacenter) { $getVmParams['Location'] = Get-Datacenter -Name $Datacenter -ErrorAction Stop }
if ($Cluster)    { $getVmParams['Location'] = Get-Cluster    -Name $Cluster    -ErrorAction Stop }

$vms = Get-VM @getVmParams
Write-Host "[*] Nalezeno VM: $($vms.Count)" -ForegroundColor Cyan

$results = @()
$i = 0

foreach ($vm in $vms) {
    $i++
    Write-Progress -Activity "Kontroluji VM" -Status "$($vm.Name) ($i/$($vms.Count))" `
                   -PercentComplete (($i / $vms.Count) * 100)

    $firmware      = 'Unknown'
    $secureBootOn  = $false
    $hwVersion     = $vm.HardwareVersion
    $guestOs       = $vm.Guest.OSFullName
    if (-not $guestOs) { $guestOs = $vm.GuestId }

    try {
        # EFI firmware check
        $firmware = $vm.ExtensionData.Config.Firmware
        if ($firmware -eq 'efi') {
            # Secure Boot flag
            $bootOpts = $vm.ExtensionData.Config.BootOptions
            if ($null -ne $bootOpts.EfiSecureBootEnabled) {
                $secureBootOn = $bootOpts.EfiSecureBootEnabled
            }
        }
    } catch {
        Write-Host "  [WARN] $($vm.Name): chyba při čtení boot config: $_" -ForegroundColor DarkGray
    }

    $status = if ($firmware -ne 'efi')     { 'BIOS_FIRMWARE - Secure Boot nepodporován' }
              elseif ($secureBootOn)        { 'OK - Secure Boot ENABLED' }
              else                          { 'EFI - Secure Boot DISABLED' }

    $col = if ($status -like 'OK*') { 'Green' }
           elseif ($status -like 'BIOS*') { 'DarkGray' }
           else { 'Yellow' }

    if (-not $ShowOnlyNoSecureBoot -or $status -notlike 'OK*') {
        Write-Host ("  [{0,-3}] {1,-40} | FW: {2,-4} | SB: {3,-5} | {4}" -f
            $i, $vm.Name, $firmware.ToUpper(), $(if ($secureBootOn) {'ON'} else {'OFF'}), $guestOs) `
            -ForegroundColor $col
    }

    $results += [PSCustomObject]@{
        VMName         = $vm.Name
        PowerState     = $vm.PowerState
        HWVersion      = $hwVersion
        Firmware       = $firmware.ToUpper()
        SecureBootEnabled = $secureBootOn
        GuestOS        = $guestOs
        Datacenter     = ($vm | Get-Datacenter -ErrorAction SilentlyContinue).Name
        Cluster        = ($vm | Get-Cluster    -ErrorAction SilentlyContinue).Name
        Status         = $status
    }
}

Write-Progress -Activity "Kontroluji VM" -Completed

# ── Souhrn ─────────────────────────────────────────────────────────────────────
Write-Banner "SOUHRN - VM Secure Boot Inventory" 'Cyan'
Write-Host "  vCenter: $VCenterAddress" -ForegroundColor White
Write-Host "  Celkem VM: $($results.Count)" -ForegroundColor White
Write-Host ""

$sbOn    = ($results | Where-Object { $_.SecureBootEnabled }).Count
$sbOff   = ($results | Where-Object { $_.Firmware -eq 'EFI' -and -not $_.SecureBootEnabled }).Count
$bios    = ($results | Where-Object { $_.Firmware -ne 'EFI' }).Count

Write-Host "  EFI + Secure Boot ON  : $sbOn" -ForegroundColor Green
Write-Host "  EFI + Secure Boot OFF : $sbOff" -ForegroundColor Yellow
Write-Host "  BIOS firmware (no SB) : $bios" -ForegroundColor DarkGray

if ($sbOff -gt 0) {
    Write-Host "`n-- EFI VM bez Secure Boot: --" -ForegroundColor Yellow
    $results | Where-Object { $_.Firmware -eq 'EFI' -and -not $_.SecureBootEnabled } |
        Format-Table VMName, PowerState, HWVersion, GuestOS -AutoSize
}

if ($ExportCsv) {
    $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host "[+] Report exportován: $ExportCsv" -ForegroundColor Green
}

Disconnect-VIServer -Server $VCenterAddress -Confirm:$false
