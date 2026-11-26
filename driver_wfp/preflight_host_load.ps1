# Read-only preflight: can this machine load a test-signed kernel driver, and what
# would we have to weaken to get there? Nothing here changes any state.
$ErrorActionPreference = 'SilentlyContinue'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
"admin (needed to query these)      : $isAdmin"

try {
    $sb = Get-SecureBootUEFI
    if ($sb) { 'Secure Boot                            : ON  → test-signed driver will be REFUSED' }
    else     { 'Secure Boot                            : off → loading test-signed is allowed' }
} catch { "Secure Boot                            : unknown — $($_.Exception.Message)" }

try {
    $g = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard'
    $running = $g.SecurityServicesRunning -join ','
    $hvci = if ($g.VirtualizationBasedSecurityStatus -eq 0) { 'VBS off' } else { "VBS status $($g.VirtualizationBasedSecurityStatus)" }
    "Device Guard services running              : $running  ($hvci)"
    if ($running -match '2') { 'HVCI (Memory integrity)                : ON → blocks test-signed drivers' }
    else                     { 'HVCI (Memory integrity)                : off' }
} catch { "Device Guard                           : unknown — $($_.Exception.Message)" }

$ts = (bcdedit /enum '{current}' | Select-String 'testsigning') -join ''
if ($ts) { "testsigning                            : $ts" } else { 'testsigning                            : not set (default off)' }

$bl = Get-BitLockerVolume
if (-not $bl) { 'BitLocker                              : no volumes reported (needs admin, or not enabled)' }
else {
    foreach ($v in $bl) {
        'BitLocker {0,-6} protection={1} status={2}' -f $v.MountPoint, $v.ProtectionStatus, $v.VolumeStatus
    }
}

$cs = Get-CimInstance Win32_ComputerSystem
"Hyper-V firmware support                    : $($cs.HyperVPresent)"
$feat = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
"Hyper-V feature state                       : $($feat.State)"
"OS                                            : $((Get-CimInstance Win32_OperatingSystem).Caption) $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"
$ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
"RAM                                           : $ram GB"
