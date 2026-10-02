<#
.SYNOPSIS
Install SniffCraft as a Wireshark capture interface (extcap) and the Minecraft dissectors, for the current user.

.PARAMETER SniffcraftExe
The sniffcraft executable to install, defaults to sniffcraft.exe next to this script or in ..\bin

.PARAMETER VersionsDir
Folder with the SniffCraft builds for other Minecraft versions (sniffcraft-<version>.exe), defaults to
sniffcraft_versions next to this script or ..\dist\sniffcraft_versions (see tools/build_versions.py)

.PARAMETER WiresharkDir
Personal Wireshark configuration folder, defaults to %APPDATA%\Wireshark
#>
param(
    [string]$SniffcraftExe = "",
    [string]$VersionsDir = "",
    [string]$WiresharkDir = (Join-Path $env:APPDATA "Wireshark")
)

$ErrorActionPreference = "Stop"

if ($SniffcraftExe -eq "") {
    $candidates = @((Join-Path $PSScriptRoot "sniffcraft.exe"), (Join-Path $PSScriptRoot "..\bin\sniffcraft.exe"))
    $SniffcraftExe = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if ($VersionsDir -eq "") {
    $candidates = @((Join-Path $PSScriptRoot "sniffcraft_versions"), (Join-Path $PSScriptRoot "..\dist\sniffcraft_versions"))
    $VersionsDir = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}

$extcapDir = Join-Path $WiresharkDir "extcap"
$pluginsDir = Join-Path $WiresharkDir "plugins"
New-Item -ItemType Directory -Force -Path $extcapDir, $pluginsDir | Out-Null

if ($SniffcraftExe -and (Test-Path $SniffcraftExe)) {
    Copy-Item $SniffcraftExe (Join-Path $extcapDir "sniffcraft.exe") -Force
    Write-Host "Capture interface: $extcapDir\sniffcraft.exe"
}
else {
    Write-Warning "sniffcraft.exe not found, only the dissectors are installed (use -SniffcraftExe <path>)"
}

if ($VersionsDir -and (Test-Path $VersionsDir)) {
    # Replaced as a whole so removed versions don't stay in the version list
    $target = Join-Path $extcapDir "sniffcraft_versions"
    if (Test-Path $target) {
        Remove-Item $target -Recurse -Force
    }
    New-Item -ItemType Directory -Path $target | Out-Null
    Copy-Item (Join-Path $VersionsDir "sniffcraft-*.exe") $target
    $count = (Get-ChildItem $target -Filter "sniffcraft-*.exe").Count
    Write-Host "Other Minecraft versions: $count builds in $target"
}

foreach ($script in @("sniffcraft.lua", "minecraft.lua")) {
    Copy-Item (Join-Path $PSScriptRoot $script) $pluginsDir -Force
    Write-Host "Dissector: $pluginsDir\$script"
}

$mcdata = Join-Path $PSScriptRoot "minecraft_mcdata"
if (Test-Path $mcdata) {
    $target = Join-Path $pluginsDir "minecraft_mcdata"
    if (Test-Path $target) {
        Remove-Item $target -Recurse -Force
    }
    Copy-Item $mcdata $target -Recurse
    Write-Host "Protocol definitions: $target"
}

Write-Host "Done, restart Wireshark to load the changes."
