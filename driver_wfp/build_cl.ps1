# build_cl.ps1 — compile AND link tpdrv_wfp.sys with plain MSVC + the WDK's km headers,
# no Visual Studio solution and no WDK *installation* required.
#
# Why this exists alongside build.ps1: build.ps1 drives the .vcxproj, which needs the WDK
# VS extension. The km headers are also distributable as the `Microsoft.Windows.WDK.x64`
# NuGet package, and that is enough for cl.exe/link.exe — which is how this driver got
# compiled for the first time (2026-11-25): the header package, MSVC from an ordinary VS
# 2022 Community install, and the six kernel import libraries.
#
#   .\build_cl.ps1 -WdkDir "$env:LOCALAPPDATA\trans-proxier-wdk\wdk"
#
# -WdkDir must contain  include\fwpsk.h (+ include\crt)  and  lib\fwpkclnt.lib & co.
# Extract them from the nupkg (it is a zip) with driver_wfp/README.md's recipe, or point
# -WdkDir at a real WDK's "10.0.x/km" tree by adjusting $inc below.
#
# NOTHING here signs or loads anything. The output is out\tpdrv_wfp.sys; signing is
# build.ps1 -Sign (or signtool), loading is install.ps1 -IDeclareIAmInAVM, and both remain
# operator actions on a test-signing host.

[CmdletBinding()]
param(
    [string]$WdkDir = "$env:LOCALAPPDATA\trans-proxier-wdk\wdk",
    # Deliberately empty and resolved below: a default built from $PSScriptRoot silently
    # became "\build_cl" when this script was invoked as `-File ./build_cl.ps1`, and a
    # path with a leading backslash is DRIVE-relative — the images were landing in
    # D:\build_cl instead of the project, while every existence check inside the script
    # agreed with itself. Absolute paths only, derived from the script's own full path.
    [string]$OutDir = "",
    [string]$SignWith = "",
    [string]$PfxPassword = ""
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $root) { $root = (Get-Location).Path }
if (-not $OutDir) { $OutDir = Join-Path $root 'out' }
$OutDir = (New-Item -ItemType Directory -Force -Path $OutDir).FullName
if (-not [IO.Path]::IsPathRooted($OutDir)) { throw "-OutDir must be absolute, got '$OutDir'" }

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { $vswhere = "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe" }
if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found — this needs an MSVC toolchain (any VS 2022 edition)" }
$vcvars = & $vswhere -latest -property installationPath | ForEach-Object { Join-Path $_ 'VC\Auxiliary\Build\vcvars64.bat' } |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $vcvars) { throw "no VC\Auxiliary\Build\vcvars64.bat under any VS 2022 install" }

foreach ($probe in @('include\fwpsk.h', 'lib\fwpkclnt.lib', 'lib\ntoskrnl.lib')) {
    if (-not (Test-Path (Join-Path $WdkDir $probe))) {
        throw "missing $WdkDir\$probe — see driver_wfp/README.md (WDK NuGet package extraction)"
    }
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# One batch file because cl/link only behave under the environment vcvars defines, and
# PowerShell cannot import it reliably. Everything is quoted; no path interpolation.
$bat = Join-Path $env:TEMP ("tpdrv_build_{0}.bat" -f $PID)
@"
@echo off
call "$vcvars" >nul 2>&1
set "INCLUDE=$WdkDir\include;$WdkDir\include\crt;%INCLUDE%"
set "LIB=$WdkDir\lib;%LIB%"
cd /d "$root"
cl /c /W3 /O1 /kernel /GS- /Gy /utf-8 /std:c17 /D_AMD64_ /D_WIN64 /D_NTDRIVER_ /D_NTKERNEL /DNDIS_SUPPORT_NDIS6 /DNTDDI_VERSION=0x0A00000B /D_WIN32_WINNT=0x0A00 /Fo"$OutDir\\" tpdrv_wfp.c record.c
if errorlevel 1 exit /b 10

rem layout_probe.c is NOT part of the driver: it pins the fwpsk.h shapes that this
rem directory documents, so a reordered struct fails the build instead of the network.
cl /c /W3 /kernel /GS- /utf-8 /std:c17 /D_AMD64_ /D_WIN64 /D_NTDRIVER_ /D_NTKERNEL /DNDIS_SUPPORT_NDIS6 /DNTDDI_VERSION=0x0A00000B /D_WIN32_WINNT=0x0A00 /Fo"$OutDir\\" layout_probe.c
if errorlevel 1 exit /b 12
link /DRIVER /SUBSYSTEM:NATIVE,10.0 /OSVERSION:10.0 /ENTRY:DriverEntry /NODEFAULTLIB /OUT:"$OutDir\tpdrv_wfp.sys" /PDB:"$OutDir\tpdrv_wfp.pdb" "$OutDir\tpdrv_wfp.obj" "$OutDir\record.obj" fwpkclnt.lib ntoskrnl.lib hal.lib bufferoverflowfastfailk.lib displib.lib ndis.lib
if errorlevel 1 exit /b 11
dumpbin /headers "$OutDir\tpdrv_wfp.sys" | findstr /C:"subsystem" /C:"machine ("
dumpbin /imports "$OutDir\tpdrv_wfp.sys" | findstr /C:"fwpkclnt.sys" /C:"Fwps"
exit /b 0
"@ | Set-Content -Encoding ascii $bat

Push-Location $root
try {
    Write-Host "== compiling (tpdrv_wfp.c + record.c) with MSVC + $WdkDir" -ForegroundColor Cyan
    & cmd.exe /c "`"$bat`""
    $code = $LASTEXITCODE
}
finally {
    Remove-Item $bat -Force -ErrorAction SilentlyContinue
    Pop-Location
}
if ($code -eq 12) { throw "layout_probe.c failed: the platform's struct layout no longer matches what driver_wfp documents — update layout_probe.c and the Rust mirror it guards" }
if ($code -ne 0) { throw "build failed with $code" }
Write-Host "   layout_probe.c: fwpsk.h layout assumptions hold (sockaddr sizes, connect-request offsets, metadata bits, 72-byte record)" -ForegroundColor DarkGreen

# install.ps1 installs the service from the driver store using this INF; without it in
# the output directory, `vm_check.ps1 -SkipBuild` has a .sys and nothing to install it
# with — the same trap as a signed binary with no package.
Copy-Item (Join-Path $root 'tpdrv_wfp.inf') $OutDir -Force

$sys = Join-Path $OutDir 'tpdrv_wfp.sys'
if (-not (Test-Path $sys)) {
    # This used to be the symptom of the drive-relative path bug above: the script's own
    # checks agreed with the linker, and only a listing of the intended directory showed
    # the image had never been there. Hence the absolute-path assertion, and this message
    # naming the two things worth checking first.
    Write-Warning "$sys is missing although link reported success. Check that -OutDir is the directory the linker was told to write to, and whether something on this host (antivirus is the usual suspect for an unsigned .sys) removed it."
    throw "tpdrv_wfp.sys not found in $OutDir"
}
$i = Get-Item $sys
Write-Host "`ntpdrv_wfp.sys : $($i.Length) bytes, built $($i.LastWriteTime)" -ForegroundColor Green

if ($SignWith) {
    if (-not (Test-Path $SignWith)) { throw "no pfx at $SignWith" }
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match 'x64' } | Select-Object -Last 1
    if (-not $signtool) { throw "signtool.exe not found in the Windows SDK" }
    & $signtool.FullName sign /fd SHA256 /f $SignWith /p $PfxPassword /d "trans-proxier WFP callout (test)" $sys | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "signtool failed with $LASTEXITCODE" }
    # The certificate is in no trust store on a build machine, so "NotTrusted/UnknownError"
    # here is the EXPECTED answer and proves only that the signature is embedded. The VM
    # that imports the .cer is where trust is established.
    $st = Get-AuthenticodeSignature $sys
    Write-Host "   signed: $($st.SignerCertificate.Subject)  thumbprint=$($st.SignerCertificate.Thumbprint)  (chain status $($st.Status) — expected until the .cer is trusted)" -ForegroundColor DarkGreen
    $cer = Join-Path $OutDir 'tpdrv_test.cer'
    # X509Certificate2.Export takes an X509ContentType, not the "X509CertificateType::
    # Encoded" spelling — the wrong one throws here and the operator is left without the
    # certificate the VM needs in order to trust this image.
    [IO.File]::WriteAllBytes($cer, $st.SignerCertificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    if (-not (Test-Path $cer)) { throw "could not write $cer" }
    Write-Host "   public certificate for the VM: $cer ($((Get-Item $cer).Length) bytes) — import it into LocalMachine\Root + TrustedPublisher there" -ForegroundColor DarkGray
}
else {
    Write-Host "Not signed. To sign with a test certificate:  .\build_cl.ps1 -SignWith <pfx> -PfxPassword <pw>  (the private key belongs OUTSIDE this repository)" -ForegroundColor Yellow
}
Write-Host "Load + verify on a test-signing VM:  .\vm_check.ps1 -IDeclareIAmInAVM   (or install.ps1 + trans-proxier wfp --verify)"
