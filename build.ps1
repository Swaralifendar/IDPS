<#
.SYNOPSIS
    Builds the IDSIPS MSI on a developer/build machine.

.DESCRIPTION
    1. Reads the product version from version.py
    2. Cleans build\stage
    3. Stages the Python runtime (fresh via the Python Install
       Manager, or copied with -RuntimeSource), installs
       requirements.txt into it and prepares pywin32 for running
       as a service (pythonservice.exe and pywintypes next to
       python314.dll)
    4. Stages the application files (code, default rules/config,
       install actions) - nothing from the development data folder
    5. Writes the "installed" marker (data goes to
       %ProgramData%\IDSIPS) and precompiles all .py files
    6. Builds build\IDSIPS-<version>-x64.msi with WiX Toolset v5

    The client machine needs no Python and no internet access.

.PARAMETER PythonVersion
    Python version for a fresh runtime (py install).

.PARAMETER RuntimeSource
    Existing runtime folder to copy instead (e.g. .\runtime).

.PARAMETER OutputDir
    Build output folder (default: .\build).

.PARAMETER WixPath
    Path to wix.exe if it is not on PATH.

.PARAMETER SkipMsi
    Stage and compile only; do not build the MSI.

.EXAMPLE
    .\build.ps1
    .\build.ps1 -RuntimeSource .\runtime
#>

param(
    [string]$PythonVersion = "3.14.7",
    [string]$RuntimeSource,
    [string]$OutputDir = (Join-Path $PSScriptRoot "build"),
    [string]$WixPath,
    [switch]$SkipMsi
)

$ErrorActionPreference = "Stop"

$ProjectRoot = $PSScriptRoot
$Stage = Join-Path $OutputDir "stage"
$StageRuntime = Join-Path $Stage "runtime"
$StagePython = Join-Path $StageRuntime "python.exe"


function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host $Message -ForegroundColor Yellow
}


function Invoke-Native([string]$Description, [scriptblock]$Command) {
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed (exit code $LASTEXITCODE)"
    }
}


Write-Host "========================================" -ForegroundColor Cyan
Write-Host "       IDSIPS Build" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# ------------------------------------------------------------
# 1. Version
# ------------------------------------------------------------
Write-Step "[1/6] Reading version"

$versionMatch = Select-String -Path (Join-Path $ProjectRoot "version.py") -Pattern '__version__\s*=\s*"(\d+\.\d+\.\d+)"'

if (-not $versionMatch) {
    throw "version.py must contain __version__ = ""X.Y.Z"""
}

$Version = $versionMatch.Matches[0].Groups[1].Value
Write-Host "Version: $Version"

# ------------------------------------------------------------
# 2. Clean stage
# ------------------------------------------------------------
Write-Step "[2/6] Cleaning $Stage"

if (Test-Path $Stage) {
    Remove-Item -Recurse -Force $Stage
}

New-Item -ItemType Directory -Force -Path $Stage | Out-Null

# ------------------------------------------------------------
# 3. Runtime
# ------------------------------------------------------------
Write-Step "[3/6] Staging the Python runtime"

if ($RuntimeSource) {
    $source = (Resolve-Path $RuntimeSource).Path
    Write-Host "Copying $source"

    # robocopy exit codes 0-7 mean success
    robocopy $source $StageRuntime /E /NFL /NDL /NJH /NJS /NP /XD __pycache__ | Out-Null
    if ($LASTEXITCODE -ge 8) {
        throw "Copying the runtime failed (robocopy exit code $LASTEXITCODE)"
    }
}
else {
    if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
        throw "Python Install Manager (py) not found. Install it, or use -RuntimeSource."
    }

    Write-Host "Creating Python $PythonVersion runtime"
    Invoke-Native "py install" { py install --target="$StageRuntime" $PythonVersion }
}

if (-not (Test-Path $StagePython)) {
    throw "Runtime has no python.exe: $StagePython"
}

$detected = & $StagePython --version
if ($detected -notlike "*$PythonVersion*") {
    Write-Warning "Runtime is $detected (expected Python $PythonVersion)"
}

Write-Host "Installing requirements.txt"
Invoke-Native "pip install" {
    & $StagePython -m pip install --disable-pip-version-check --no-warn-script-location `
        -r (Join-Path $ProjectRoot "requirements.txt")
}

# pywin32 runs services through pythonservice.exe, which must sit
# next to python314.dll together with pywintypes/pythoncom. Done
# here so the MSI owns these files (pywin32 would otherwise move
# them during service registration).
$sitePackages = Join-Path $StageRuntime "Lib\site-packages"
$serviceHost = Join-Path $sitePackages "win32\pythonservice.exe"

if (Test-Path $serviceHost) {
    Move-Item -Force $serviceHost (Join-Path $StageRuntime "pythonservice.exe")
}

if (-not (Test-Path (Join-Path $StageRuntime "pythonservice.exe"))) {
    throw "pythonservice.exe not found (pywin32 not installed?)"
}

Get-ChildItem (Join-Path $sitePackages "pywin32_system32") -Filter *.dll | ForEach-Object {
    Copy-Item -Force $_.FullName $StageRuntime
}

Write-Host "Verifying dependencies"
Invoke-Native "Dependency check" {
    & $StagePython -c "import win32service, win32serviceutil, win32evtlog, servicemanager, yaml, pydivert; print('All dependencies OK')"
}

# ------------------------------------------------------------
# 4. Application files
# ------------------------------------------------------------
Write-Step "[4/6] Staging application files"

$appFiles = @(
    # folder,          file patterns,                         recurse
    @(".",             @("service.py", "logger.py", "paths.py", "rotation.py", "stop_signal.py", "version.py"), $false),
    @("hids",          @("*.py", "hids.rules"),               $false),
    @("NIDS",          @("*.py", "config.yml"),               $false),
    @("NIDS\rules",    @("nids.rules"),                       $false),
    @("IPS",           @("*.py", "ips.rules"),                $false),
    @("alert_manager", @("*.py"),                             $true),
    @("installer",     @("install_actions.ps1", "configure.py"), $false)
)

$copied = 0

foreach ($entry in $appFiles) {
    $folder, $patterns, $recurse = $entry
    $sourceDir = Join-Path $ProjectRoot $folder

    foreach ($pattern in $patterns) {
        $files = Get-ChildItem -Path $sourceDir -Filter $pattern -File -Recurse:$recurse |
            Where-Object { $_.FullName -notmatch '\\(__pycache__|\.venv)\\' }

        foreach ($file in $files) {
            $relative = $file.FullName.Substring($ProjectRoot.Length).TrimStart("\")
            $target = Join-Path $Stage $relative

            New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
            Copy-Item -Force $file.FullName $target
            $copied++
        }
    }
}

Write-Host "$copied application files staged"

# ------------------------------------------------------------
# 5. Installed marker + precompile
# ------------------------------------------------------------
Write-Step "[5/6] Marking as installed and precompiling"

# paths.py: with this marker, data goes to %ProgramData%\IDSIPS
Set-Content -Path (Join-Path $Stage "idsips_installed") -Value "IDSIPS $Version" -Encoding ASCII

# unchecked-hash: .pyc stay valid regardless of file timestamps
# after installation, and nothing needs to be written under
# Program Files at run time.
Invoke-Native "compileall" {
    & $StagePython -m compileall -q -f --invalidation-mode unchecked-hash `
        -x "[\\/]Lib[\\/]test[\\/]" $Stage
}

$fileCount = (Get-ChildItem $Stage -Recurse -File).Count
$sizeMb = [math]::Round((Get-ChildItem $Stage -Recurse -File | Measure-Object Length -Sum).Sum / 1MB)
Write-Host "Stage: $fileCount files, $sizeMb MB"

# ------------------------------------------------------------
# 6. MSI
# ------------------------------------------------------------
if ($SkipMsi) {
    Write-Step "[6/6] Skipping MSI (-SkipMsi)"
    Write-Host "Staged files: $Stage"
    exit 0
}

Write-Step "[6/6] Building the MSI"

$wix = if ($WixPath) { $WixPath } else { (Get-Command wix -ErrorAction SilentlyContinue).Source }

if (-not $wix -or -not (Test-Path $wix)) {
    throw "WiX Toolset v5 not found. Install it with 'dotnet tool install --global wix --version 5.0.2' or pass -WixPath."
}

$wixVersion = ((& $wix --version) -split "\+")[0].Trim()
Write-Host "WiX $wixVersion"

$msi = Join-Path $OutputDir "IDSIPS-$Version-x64.msi"

Push-Location $OutputDir
try {
    # WixQuietExec custom action (cached under build\.wix)
    $extensions = & $wix extension list 2>$null | Out-String
    if ($extensions -notmatch "WixToolset.Util.wixext") {
        Invoke-Native "wix extension add" { & $wix extension add "WixToolset.Util.wixext/$wixVersion" }
    }

    Invoke-Native "wix build" {
        & $wix build (Join-Path $ProjectRoot "installer\IDSIPS.wxs") `
            -arch x64 `
            -ext WixToolset.Util.wixext `
            -d "StageDir=$Stage" `
            -d "ProductVersion=$Version" `
            -o $msi
    }
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "       IDSIPS BUILD COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "MSI : $msi"
Write-Host ""
Write-Host "Install (elevated):"
Write-Host "  msiexec /i `"$msi`" /l*v install.log"
Write-Host "  msiexec /i `"$msi`" /qn HOME_NET=10.0.0.0/8 INTERFACES=Ethernet"
