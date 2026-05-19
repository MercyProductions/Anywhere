param(
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-AuditPol {
    param(
        [Parameter(Mandatory = $true)][string]$Subcategory,
        [string]$Success = 'enable',
        [string]$Failure = 'disable'
    )

    $arguments = @('/set', "/subcategory:$Subcategory", "/success:$Success", "/failure:$Failure")
    Write-Host "auditpol $($arguments -join ' ')"
    if ($Apply) {
        & auditpol.exe @arguments | Out-Host
    }
}

function Set-Dword {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$Value
    )

    Write-Host "Set $Path\$Name = $Value"
    if ($Apply) {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }

        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    }
}

Write-Host 'Aegis telemetry setup'
Write-Host ('Mode: ' + $(if ($Apply) { 'APPLY' } else { 'DRY RUN' }))
Write-Host ''

if ($Apply -and -not (Test-Administrator)) {
    throw 'Run this script from an elevated PowerShell session when using -Apply.'
}

Write-Host 'Recommended audit policy changes:'
Invoke-AuditPol -Subcategory 'Process Creation' -Success enable -Failure disable
Invoke-AuditPol -Subcategory 'Process Termination' -Success enable -Failure disable
Invoke-AuditPol -Subcategory 'Registry' -Success enable -Failure enable
Invoke-AuditPol -Subcategory 'File System' -Success enable -Failure enable
Invoke-AuditPol -Subcategory 'Handle Manipulation' -Success enable -Failure disable
Invoke-AuditPol -Subcategory 'Security System Extension' -Success enable -Failure enable

Write-Host ''
Write-Host 'Recommended registry-backed logging changes:'
Set-Dword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1
Set-Dword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1
Set-Dword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Value 1

if ($Apply) {
    $moduleNamesPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
    if (-not (Test-Path $moduleNamesPath)) {
        New-Item -Path $moduleNamesPath -Force | Out-Null
    }

    New-ItemProperty -Path $moduleNamesPath -Name '*' -Value '*' -PropertyType String -Force | Out-Null
}
else {
    Write-Host "Set HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames\* = *"
}

Write-Host ''
Write-Host 'Current audit policy summary:'
if (Test-Administrator) {
    & auditpol.exe /get /category:* | Select-String -Pattern 'Process Creation|Process Termination|Registry|File System|Handle Manipulation|Security System Extension' | ForEach-Object {
        Write-Host $_.Line
    }
}
else {
    Write-Host 'Current audit policy status requires an elevated PowerShell session.'
}

Write-Host ''
Write-Host 'Provider availability:'
$sysmon = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
$powershell = Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' -ErrorAction SilentlyContinue
Write-Host ('Sysmon Operational log: ' + $(if ($sysmon) { 'available' } else { 'not found' }))
Write-Host ('PowerShell Operational log: ' + $(if ($powershell) { 'available' } else { 'not found' }))

Write-Host ''
if ($Apply) {
    Write-Host 'Aegis telemetry policy has been applied.'
}
else {
    Write-Host 'Dry run complete. Re-run with -Apply from an elevated PowerShell session to enable these settings.'
}
