# build.ps1 — compile + package tpdrv_wfp.sys with the installed WDK.
#
# Operator-run by design: this workspace has no WDK, so nothing here has ever
# executed. Read driver_wfp/README.md before running it, run it in a VM, and expect
# to have to fix small compile errors — that is the point of writing the callout in
# C: the WDK headers, not a hand-copied layout, decide what is correct.
#
#   prerequisites: Windows Driver Kit (WDK) matching the SDK, plus the VS C/C++
#   tools. Easiest is an EWDK iso: `./Execute` then run this script from that prompt.
#
#   .\build.ps1                      # build → .\out\tpdrv_wfp.sys
#   .\build.ps1 -Sign -CertName TPDrvTest   # self-signed test cert (test-signing hosts)
#   .\install.ps1 / .\uninstall.ps1  # load / remove (VM only)

[CmdletBinding()]
param(
    [string]$Arch = 'x64',
    [switch]$Sign,
    [string]$CertName = 'TPDrvTestCert',
    [string]$WdkVersion = '10.0.26100.0',
    [switch]$Test
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$out = Join-Path $root 'out'
New-Item -ItemType Directory -Force -Path $out | Out-Null

if ($Test) {
    # The encoders in record.c are host-compilable on purpose: this is the part of a
    # redirect driver whose mistakes are silent (byte order, sockaddr layout), so it is
    # checked with an ordinary compiler and compared against the Rust spec.
    $gcc = Get-Command gcc.exe -ErrorAction SilentlyContinue
    if (-not $gcc) { throw "-Test needs gcc (or run: gcc -I. record.c test_record.c -lws2_32 -o test_record)" }
    Write-Host "== host tests: driver encoders vs the Rust spec" -ForegroundColor Cyan
    Push-Location $root
    try {
        & gcc.exe -I. record.c test_record.c -lws2_32 -o "$out\test_record.exe"
        if ($LASTEXITCODE -ne 0) { throw "host test build failed" }
        & "$out\test_record.exe"
        if ($LASTEXITCODE -ne 0) { throw "host tests failed" }
        & gcc.exe (Join-Path $root 'abi_check.c') -o "$out\abi_check.exe" 2>$null
        if ($LASTEXITCODE -eq 0) { & "$out\abi_check.exe" | Select-Object -Last 1 }
        else { Write-Warning "abi_check did not build with this toolchain (it needs fwpmu.h)" }

        # The classify decision, executed (not merely type-checked): tpdrv_wfp.c compiled
        # with TPDRV_HOST_TEST against recorded fakes for the Fwps* DDIs. This is the only
        # place the C that will run at DISPATCH_LEVEL is actually run.
        Write-Host '== host tests: the driver classify path itself' -ForegroundColor Cyan
        $log = & gcc.exe -I. -DTPDRV_HOST_TEST -Wno-multichar -Wno-deprecated-declarations `
            tpdrv_wfp.c record.c test_classify.c -lws2_32 -o "$out\test_classify.exe" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host ($log | Out-String)
            throw 'test_classify did not build'
        }
        & "$out\test_classify.exe"
        if ($LASTEXITCODE -ne 0) { throw 'classify path tests failed' }

        # The kernel TU cannot be BUILT without the WDK, but it can be type-checked
        # without it: wdk_shim.h carries the fwpsk.h declarations transcribed from the
        # DDI pages, and MinGW ships Microsoft's own ddk/ntddk.h for the IRP/device half.
        # This is what catches a wrong argument count, an identifier that does not exist,
        # or a callout callback with the wrong shape. The last of those is only a warning
        # by default and a runtime bad-pointer at DISPATCH_LEVEL, so that one class of
        # warning is escalated. Verified to fail on purpose (red test): deleting an
        # argument from FwpsCalloutRegister1, and reverting notifyFn to its old
        # (UINT32, FWPS_FILTER1*, UINT64)->VOID shape, each stop this build.
        $ddk = Join-Path (Split-Path (Split-Path $gcc.Source -Parent) -Parent) `
                         'x86_64-w64-mingw32/include/ddk'
        if (Test-Path $ddk) {
            Write-Host '== kernel TU syntax check (against wdk_shim.h, no WDK)' -ForegroundColor Cyan
            # gcc sends notes to stderr, which $ErrorActionPreference='Stop' would
            # promote into a terminating error; the exit code is the real verdict.
            $prevEap = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                # the second entry also compiles the older-WDK spelling of the pool
                # allocation, so that branch is never shipped unread by a compiler
                foreach ($tu in 'tpdrv_wfp.c', 'record.c') {
                  foreach ($extra in @(@(), @('-DTPDRV_TEST_LEGACY_POOL'))) {
                    if ($tu -ne 'tpdrv_wfp.c' -and $extra.Count -gt 0) { continue }
                    $cArgs = @(
                        '-fsyntax-only', '-Wall', '-Wextra', '-Werror=incompatible-pointer-types',
                        '-DTPDRV_SYNTAX_CHECK', '-include', 'wdk_shim.h',
                        '-I.', ('-I' + $ddk)
                    ) + $extra + @($tu)
                    $log = & gcc.exe @cArgs 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        Write-Host ('   gcc ' + ($cArgs -join ' ')) -ForegroundColor DarkGray
                        ($log | Out-String) -split "`n" |
                            Where-Object { $_ -match 'error' } | ForEach-Object { Write-Host $_.Trim() }
                        throw "$tu does not type-check against wdk_shim.h"
                    }
                    if ($extra.Count -gt 0) { Write-Host "   $tu - legacy-WDK pool spelling type-checks clean" -ForegroundColor DarkGreen }
                    else { Write-Host "   $tu - type-checks clean" -ForegroundColor DarkGreen }
                  }
                }
            }
            finally { $ErrorActionPreference = $prevEap }
        }
        else {
            Write-Warning "no ddk/ntddk.h beside this gcc; skipped the kernel-TU syntax check"
        }
    }
    finally { Pop-Location }
}

# Everything above runs with nothing but gcc; everything below needs the WDK. With
# -Test alone on a dev box, that is the whole run — the checks are the point.
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    if ($Test) {
        Write-Host '== checks complete; no cl.exe here so nothing was built (that half needs the WDK)' -ForegroundColor Yellow
        exit 0
    }
    throw "cl.exe not found — run this from a 'Developer Command Prompt' or an EWDK environment."
}

$kitsRoot = ${env:ProgramFiles(x86)} + '\Windows Kits\10'
$inc = @(
    "$kitsRoot\Include\$WdkVersion\km",
    "$kitsRoot\Include\$WdkVersion\shared",
    "$kitsRoot\Include\$WdkVersion\km\crt"
)
$lib = "$kitsRoot\Lib\$WdkVersion\km\$Arch"

foreach ($p in ($inc + @($lib))) {
    if (-not (Test-Path $p)) {
        throw "Missing WDK path: $p  (install the WDK, or pass -WdkVersion matching your kit)"
    }
}

$clArgs = @(
    '/c', '/W3', '/O2', '/Zi', '/kernel', '/GS', '/Gz', '/GR-', '/std:c17',
    '/D_NTDRIVER_', "/D_AMD64_"
    "/I$root"
) + ($inc | ForEach-Object { "/I$_" }) + @(
    (Join-Path $root 'tpdrv_wfp.c')
    (Join-Path $root 'record.c')
    "/Fo$(Join-Path $out '\')"
)

Write-Host "== compiling (tpdrv_wfp.c + record.c)" -ForegroundColor Cyan
& cl.exe @clArgs
if ($LASTEXITCODE -ne 0) { throw "compile failed" }

# The three libraries a WFP callout needs; fwpkclnt is the engine, netio the ALE
# helpers, ntoskrnl the kernel itself.
$linkArgs = @(
    '/DRIVER', '/SUBSYSTEM:NATIVE', '/MANIFEST:NO', '/INCREMENTAL:NO',
    '/ENTRY:DriverEntry',
    "/LIBPATH:$lib",
    'ntoskrnl.lib', 'hal.lib', 'bufferoverflowfastfailk.lib',
    'fwpkclnt.lib', 'netio.lib', 'ndis.lib', 'wmilib.lib',
    "/OUT:$(Join-Path $out 'tpdrv_wfp.sys')",
    "/PDB:$(Join-Path $out 'tpdrv_wfp.pdb')",
    (Join-Path $out 'tpdrv_wfp.obj'),
    (Join-Path $out 'record.obj')
)

Write-Host "== linking" -ForegroundColor Cyan
& link.exe @linkArgs
if ($LASTEXITCODE -ne 0) { throw "link failed" }

Copy-Item (Join-Path $root 'tpdrv_wfp.inf') $out -Force


if ($Sign) {
    Write-Host "== signing with test certificate '$CertName'" -ForegroundColor Cyan
    if (-not (Get-Command makecert.exe -ErrorAction SilentlyContinue)) {
        Write-Warning "makecert.exe missing; create the cert once with New-SelfSignedCertificate -Type CodeSigningCert and adjust this block."
    }
    $pfx = Join-Path $out "$CertName.pfx"
    if (-not (Test-Path $pfx)) {
        New-SelfSignedCertificate -Type CodeSign -Subject "CN=$CertName" -CertStoreLocation Cert:\CurrentUser\My `
            -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3') | Out-Null
        $c = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq "CN=$CertName" } | Select-Object -First 1
        Export-PfxCertificate -Cert $c -FilePath $pfx -Password (Read-Host -AsSecureString 'pfx password') | Out-Null
        Export-Certificate -Cert $c -FilePath (Join-Path $out "$CertName.cer") | Out-Null
        Write-Host "Import $CertName.cer into LocalMachine\Trusted Root + Trusted Publishers, then reboot with:"
        Write-Host "    bcdedit /set testsigning on" -ForegroundColor Yellow
    }
    & signtool.exe sign /fd SHA256 /a /f $pfx (Join-Path $out 'tpdrv_wfp.sys')
    if ($LASTEXITCODE -ne 0) { throw "signing failed" }
}

Write-Host "== done: $(Join-Path $out 'tpdrv_wfp.sys')" -ForegroundColor Green
Write-Host "Verify the driver is honest about what it did with:"
Write-Host '    netsh wfp show state file=wfp-state.xml   # look for the tpdrv callout + filters'
