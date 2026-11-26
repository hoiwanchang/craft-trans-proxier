# install.ps1 / uninstall.ps1 — load and remove the WFP callout (VM ONLY).
#
# Neither has ever been run. They are here so the operator does not have to invent
# the plumbing, and they refuse to act unless -IDeclareIAmInAVM is passed: a
# callout that redirects wrongly takes the host's network with it, and removing it
# cleanly matters more than installing it.
#
# Prerequisites: test signing enabled (`bcdedit /set testsigning on` + reboot) and
# the certificate from build.ps1 in LocalMachine\Trusted Root + Trusted Publishers.
#
# Rollback, in order of preference:
#   .\uninstall.ps1 -IDeclareIAmInAVM          # stops + removes the service
#   netsh wfp reset filters                    # ONLY if you know this clears ALL
#                                              # custom filters, not just ours: the
#                                              # control plane also lives in a
#                                              # dynamic session that dies with the
#                                              # service process, which is the
#                                              # cheaper escape hatch.

[CmdletBinding()]
param(
    [switch]$IDeclareIAmInAVM,
    [switch]$Uninstall,
    [string]$Path = "$PSScriptRoot\out"
)

$ErrorActionPreference = 'Stop'
$svc = 'TpDrvWfp'

if (-not $IDeclareIAmInAVM) {
    throw "refusing to touch the kernel without -IDeclareIAmInAVM; run this in a VM."
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "needs an elevated prompt"
}

if ($Uninstall) {
    Write-Host "== stopping and removing $svc (our WFP filters live in the service process's dynamic session, so they go with it)" -ForegroundColor Cyan
    & sc.exe stop $svc | Out-Host
    & sc.exe delete $svc | Out-Host
    Get-WindowsDriver -Online -All 2>$null |
        Where-Object { $_.OriginalFileName -like "*$svc*" } |
        ForEach-Object { & pnputil.exe /delete-driver $_.InfPath /uninstall | Out-Host }
    Write-Host "done. confirm with: driverquery /v | findstr /i tpdrv  (expect no output)" -ForegroundColor Green
    return
}

$sys = Join-Path $Path "$svc.sys"
if (-not (Test-Path $sys)) { throw "not built: $sys (run build.ps1 first)" }

Write-Host "== importing certificate from $Path if present" -ForegroundColor DarkGray
$cer = Join-Path $Path 'TPDrvTestCert.cer'
if (Test-Path $cer) {
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
    Write-Host "   imported; a reboot may still be needed for test signing to accept it" -ForegroundColor Yellow
}

Write-Host "== staging the driver package, then creating the service" -ForegroundColor Cyan
# /add-driver WITHOUT /install, deliberately: /install needs a PnP device whose hardware
# ID matches, and a callout driver has none (Root\TpDrvWfp only exists if someone created
# it by hand). What loads this driver is the SERVICE, so sc create is the real step — and
# running /install first would race it for the same service name.
& pnputil.exe /add-driver (Join-Path $Path "$svc.inf") | Out-Host
if ((& sc.exe qc $svc 2>$null | Out-String) -match 'SERVICE_NAME') {
    Write-Host "   service $svc already exists — not re-creating it (check binPath with: sc qc $svc)" -ForegroundColor Yellow
}
else {
    & sc.exe create $svc type= kernel start= demand binPath= $sys DisplayName= "trans-proxier WFP callout" | Out-Host
}
& sc.exe start $svc | Out-Host

Write-Host @"

Now arm the route from the service side — one command does all of it:

  set TPROXIER_WFP_INGRESS=1
  trans-proxier wfp --apply --i-consent-to-install-wfp-filters

  That starts the token listeners, pushes this process's pid + both token pools to the
  driver (IOCTL_TPDRV_SET_CONFIG), installs one filter per whitelisted app, and then
  SUPERVISES: every 2 s it re-reads the driver and re-pushes if the two disagree — a
  callout driver that is stopped and started again comes back inert, which otherwise
  looks exactly like "proxification is off". Ctrl+C (or --once) disarms it on the way
  out, because the token ports die with this process and an armed driver would redirect
  the next whitelisted connect to a closed port.
  1. check the device:  driverquery /v | findstr /i tpdrv
  2. confirm the policy: netsh wfp show state file=wfp-state.xml
  3. and the replica's own gate: trans-proxier wfp --verify   (read-only)
              look for callout d7a1f002-2222-4333-9999-999999999999 and the
              ALE_CONNECT_REDIRECT filters in sublayer d7a1f001-1111-4222-8888-...
"@ -ForegroundColor Green
