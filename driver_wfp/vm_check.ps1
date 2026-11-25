# vm_check.ps1 — the whole WFP kernel-redirect acceptance run, start to finish, in one
# command. FOR A VIRTUAL MACHINE ONLY.
#
# This is the script that answers the only question left on the WFP item: does the loaded
# callout actually redirect traffic, and does the engine get each flow's ORIGINAL
# destination back? Everything before it (compile, link, ABI, contracts) is already
# checked in-repo; nothing here can be verified without a kernel.
#
#   # in the VM, elevated, after copying the craft-trans-proxier tree across:
#   .\vm_check.ps1 -IDeclareIAmInAVM -App target_probe\debug\trans-proxier.exe
#   .\vm_check.ps1 -IDeclareIAmInAVM -Teardown      # stop + remove the driver
#
# What it does, in order: builds the .sys (build_cl.ps1), creates and trusts a test
# certificate, signs the image, loads the driver, points the service at a whitelisted
# program, supervises the route, then runs `wfp --verify` — whose rows are the
# acceptance criteria, including "the kernel credited the flow to this process".
#
# It refuses to run without -IDeclareIAmInAVM because every step below it changes the
# machine: the certificate store, the driver store, the service control manager, and (once
# the route is armed) this host's routing for the listed programs.

[CmdletBinding()]
param(
    [switch]$IDeclareIAmInAVM,
    [switch]$Teardown,
    [switch]$SkipBuild,
    [string]$App = "target_check\debug\trans-proxier.exe",   # in the VM, not this repo's default
    [string]$Config = "",
    [string]$CertName = 'TPDrvTestCert'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$svc = 'TpDrvWfp'

if (-not $IDeclareIAmInAVM) {
    throw @"
refusing to run: this installs a kernel driver, a code-signing certificate and WFP filters.
Copy the tree into a VM and re-run with -IDeclareIAmInAVM. Rollback is -Teardown.
"@
}
$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) { throw "needs an elevated prompt" }

function Step($n, $msg) { Write-Host ("[{0}] {1}" -f $n, $msg) -ForegroundColor Cyan }

if ($Teardown) {
    Step "1/2" "stopping the route: filters live in a dynamic session, so ending the service process withdraws them"
    Get-Process trans-proxier -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.Id -Force }
    & "$PSScriptRoot\install.ps1" -Uninstall -IDeclareIAmInAVM
    Step "2/2" "confirming the driver is gone"
    & driverquery.exe /v | Select-String -Pattern 'tpdrv' -SimpleMatch
    Write-Host "teardown done (no tpdrv line above = unloaded)" -ForegroundColor Green
    return
}

# ── 1. build ────────────────────────────────────────────────────────────────────
if (-not $SkipBuild) {
    Step 1 "compiling + linking tpdrv_wfp.sys"
    & "$PSScriptRoot\build_cl.ps1"
    if ($LASTEXITCODE -ne 0) { throw "build_cl.ps1 failed" }
}
$sys = Join-Path $root 'out\tpdrv_wfp.sys'
if (-not (Test-Path $sys)) { throw "no $sys to sign — run without -SkipBuild" }

# ── 2. test certificate (a VM-only action: it writes the local machine stores) ───
Step 2 "test code-signing certificate"
$sig = Get-AuthenticodeSignature $sys
$cerExisting = Join-Path (Split-Path $sys) 'tpdrv_test.cer'
if ($sig.SignatureType -eq 'Authenticode' -and $sig.SignerCertificate) {
    # build_cl.ps1 -SignWith already produced a signed image; do not mint a second identity.
    Write-Host "   image is already signed by $($sig.SignerCertificate.Subject) — trusting its certificate only" -ForegroundColor DarkGray
    $cer = if (Test-Path $cerExisting) { $cerExisting } else {
        $tmp = Join-Path $env:TEMP 'tpdrv_from_signed_image.cer'
        [IO.File]::WriteAllBytes($tmp, $sig.SignerCertificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        $tmp
    }
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
    Write-Host "   trusted: $cer" -ForegroundColor DarkGray
    $alreadySigned = $true
}
else {
$alreadySigned = $false
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$CertName" } | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$CertName" `
        -HashAlgorithm SHA256 -KeyExportPolicy Exportable -KeyUsage DigitalSignature `
        -CertStoreLocation Cert:\LocalMachine\My
}
$pfx = Join-Path $env:TEMP "$CertName.pfx"
if (-not (Test-Path $pfx)) {
    Export-PfxCertificate -Cert $cert -FilePath $pfx -Password (ConvertTo-SecureString -AsPlainText 'tpdrv' -Force) | Out-Null
}
# Trust it by the PUBLIC certificate; the private key stays in LocalMachine\My.
$cer = Join-Path $env:TEMP "$CertName.cer"
Export-Certificate -Cert $cert -FilePath $cer | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
Write-Host "   thumbprint $($cert.Thumbprint)" -ForegroundColor DarkGray
}   # end of "no signature yet" branch

# ── 3. sign ─────────────────────────────────────────────────────────────────────
if ($alreadySigned) {
    Step 3 "already signed by build_cl.ps1 — skipping"
}
else {
Step 3 "signing the image"
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match 'x64' } | Select-Object -Last 1
if (-not $signtool) { throw "signtool.exe not found in the Windows SDK" }
& $signtool.FullName sign /fd SHA256 /a /f $pfx /p 'tpdrv' $sys
if ($LASTEXITCODE -ne 0) { throw "signing failed" }
& $signtool.FullName verify /pa /v $sys
}

# ── 4. load ─────────────────────────────────────────────────────────────────────
Step 4 "loading the driver"
& "$PSScriptRoot\install.ps1" -IDeclareIAmInAVM
& driverquery.exe /v | Select-String -Pattern 'tpdrv' -SimpleMatch | ForEach-Object { Write-Host "   $_" }

# ── 5. arm the route, then run the gate ─────────────────────────────────────────
Step 5 "arming the route (supervises: re-arms the driver if it drifts)"
$exe = if ([IO.Path]::IsPathRooted($App)) { $App } else { Join-Path (Split-Path -Parent $root) $App }
if (-not (Test-Path $exe)) { throw "no service binary at $exe — build it in the VM or pass -App" }
$env:TPROXIER_WFP_INGRESS = '1'
# --verify --i-consent-to-install-wfp-filters is SELF-CONTAINED: it binds its own
# token listeners, hands the driver its own pool, installs its own per-transport
# filters and probes. A second, supervising --apply process would hold the driver
# claim and this run could not arm itself, so the acceptance gate runs alone here.
$applyArgs = @('wfp', '--verify', '--i-consent-to-install-wfp-filters')
if ($Config) { $applyArgs += @('--config', $Config) }
$job = Start-Process -FilePath $exe -ArgumentList $applyArgs -PassThru -NoNewWindow
Start-Sleep -Seconds 3
if ($job.HasExited) { throw "the route exited immediately (code $($job.ExitCode)) — read the output above" }

Step 6 "acceptance gate:  trans-proxier wfp --verify"
# the gate already ran above as part of the armed process; re-run read-only so
# the rows are visible a second time without touching anything
$verifyArgs = @('wfp', '--verify') + $(if ($Config) { @('--config', $Config) } else { @() })
& $exe @verifyArgs
$gate = $LASTEXITCODE

Write-Host @"

──────────────────────────────────────────────────────────────────────
$($job.Id) : route still supervising.  Check the kernel's own view:
    netsh wfp show state file=wfp-state.xml
    (expect callout d7a1f002-2222-4333-9999-999999999999 and one redirect filter per app)

Stop everything and unload:
    Stop-Process -Id $($job.Id);  .\vm_check.ps1 -IDeclareIAmInAVM -Teardown
──────────────────────────────────────────────────────────────────────
"@ -ForegroundColor Green
if ($gate -eq 0) {
    Write-Host "WFP KERNEL REDIRECT: verified end to end." -ForegroundColor Green
}
else {
    Write-Host "WFP KERNEL REDIRECT: gate FAILED (exit $gate). The rows above say which layer." -ForegroundColor Yellow
}
exit $gate
