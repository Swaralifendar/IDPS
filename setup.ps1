# ============================================================
# IDSIPS - Complete Development + Deployment Setup
# ============================================================
#
# Architecture:
#
#   .venv   -> Development / Testing
#   runtime -> Deployment / Windows Service
#
# Required Python:
#   3.14.7
#
# The script:
#   1. Checks administrator privileges
#   2. Detects Python 3.14.7
#   3. Installs Python 3.14.7 if missing
#   4. Creates/verifies .venv
#   5. Installs development dependencies
#   6. Creates/verifies standalone runtime
#   7. Installs deployment dependencies
#   8. Configures pywin32
#   9. Installs/configures IDSIPS Windows Service
#  10. Starts and verifies the service
#
# IMPORTANT:
#   .venv/ and runtime/ are generated locally.
#   They must NOT be committed to Git.
#
# ============================================================

$ErrorActionPreference = "Stop"

# ============================================================
# CONFIGURATION
# ============================================================

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

$PythonVersion = "3.14.7"

$PythonInstallerName = "python-3.14.7-amd64.exe"

$PythonInstallerUrl = `
    "https://www.python.org/ftp/python/3.14.7/python-3.14.7-amd64.exe"

$VenvPath = Join-Path $ProjectRoot ".venv"
$RuntimePath = Join-Path $ProjectRoot "runtime"
$LogsPath = Join-Path $ProjectRoot "logs"

$VenvPython = Join-Path $VenvPath "Scripts\python.exe"

$RuntimePython = Join-Path $RuntimePath "python.exe"
$RuntimeServiceHost = Join-Path $RuntimePath "pythonservice.exe"

$RequirementsFile = Join-Path $ProjectRoot "requirements.txt"

$ServiceName = "IDSIPS"

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Write-Step {

    param(
        [string]$Message
    )

    Write-Host ""
    Write-Host "============================================================"
    Write-Host $Message
    Write-Host "============================================================"
}

function Write-Info {

    param(
        [string]$Message
    )

    Write-Host "[INFO] $Message"
}

function Write-Success {

    param(
        [string]$Message
    )

    Write-Host "[OK]   $Message"
}

function Write-WarningMessage {

    param(
        [string]$Message
    )

    Write-Host "[WARN] $Message"
}

function Test-IsAdministrator {

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $principal = New-Object `
        Security.Principal.WindowsPrincipal($identity)

    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Get-PythonVersion {

    param(
        [string]$PythonExecutable
    )

    try {

        if (-not (Test-Path $PythonExecutable)) {
            return $null
        }

        $output = & $PythonExecutable --version 2>&1

        if ($output -match "Python\s+([0-9]+\.[0-9]+\.[0-9]+)") {

            return $Matches[1]
        }
    }
    catch {
        return $null
    }

    return $null
}

function Test-PythonVersion {

    param(
        [string]$PythonExecutable,
        [string]$ExpectedVersion
    )

    if (-not (Test-Path $PythonExecutable)) {
        return $false
    }

    $version = Get-PythonVersion $PythonExecutable

    return ($version -eq $ExpectedVersion)
}

function Find-Python3147 {

    $candidates = @()

    # --------------------------------------------------------
    # python command
    # --------------------------------------------------------

    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue

    if ($pythonCommand) {

        if ($pythonCommand.Source) {
            $candidates += $pythonCommand.Source
        }

        if ($pythonCommand.Path) {
            $candidates += $pythonCommand.Path
        }
    }

    # --------------------------------------------------------
    # py launcher
    # --------------------------------------------------------

    $pyCommand = Get-Command py -ErrorAction SilentlyContinue

    if ($pyCommand) {

        try {

            $pyPython = & py -3.14 -c `
                "import sys; print(sys.executable)" 2>$null

            if ($pyPython) {
                $candidates += $pyPython.Trim()
            }
        }
        catch {
        }
    }

    # --------------------------------------------------------
    # Common Python 3.14 locations
    # --------------------------------------------------------

    $commonPaths = @(

        "$env:LocalAppData\Programs\Python\Python314\python.exe",

        "$env:LocalAppData\Programs\Python\Python314-64\python.exe",

        "$env:ProgramFiles\Python314\python.exe",

        "$env:ProgramFiles\Python314-64\python.exe",

        "$env:LocalAppData\Python\pythoncore-3.14-64\python.exe",

        "$env:LocalAppData\Python\pythoncore-3.14-amd64\python.exe"

    )

    $candidates += $commonPaths

    # --------------------------------------------------------
    # Remove duplicates
    # --------------------------------------------------------

    $candidates = $candidates |
        Where-Object { $_ } |
        Select-Object -Unique

    # --------------------------------------------------------
    # Validate candidates
    # --------------------------------------------------------

    foreach ($candidate in $candidates) {

        if (-not (Test-Path $candidate)) {
            continue
        }

        $version = Get-PythonVersion $candidate

        if ($version -eq $PythonVersion) {

            try {
                return (Resolve-Path $candidate).Path
            }
            catch {
                return $candidate
            }
        }
    }

    return $null
}

function Download-PythonInstaller {

    param(
        [string]$InstallerPath
    )

    if (Test-Path $InstallerPath) {

        Write-Info "Python installer already downloaded."

        return
    }

    Write-Info "Downloading Python $PythonVersion..."

    try {

        Invoke-WebRequest `
            -Uri $PythonInstallerUrl `
            -OutFile $InstallerPath `
            -UseBasicParsing

    }
    catch {

        throw "Unable to download Python $PythonVersion installer. Error: $($_.Exception.Message)"
    }

    if (-not (Test-Path $InstallerPath)) {

        throw "Python installer download failed."
    }

    Write-Success "Python installer downloaded."
}

function Find-Pywin32PostInstall {

    param(
        [string]$RuntimeRoot
    )

    $possiblePaths = @(

        (Join-Path `
            $RuntimeRoot `
            "Scripts\pywin32_postinstall.py"),

        (Join-Path `
            $RuntimeRoot `
            "Lib\site-packages\win32\scripts\pywin32_postinstall.py")

    )

    foreach ($path in $possiblePaths) {

        if (Test-Path $path) {
            return $path
        }
    }

    return $null
}

# ============================================================
# START
# ============================================================

Write-Host ""
Write-Host "========================================"
Write-Host "       IDSIPS COMPLETE SETUP"
Write-Host "========================================"
Write-Host ""

Write-Info "Project root:"
Write-Host "  $ProjectRoot"

# ============================================================
# ADMINISTRATOR CHECK
# ============================================================

Write-Step "[1/8] Checking Administrator privileges"

if (-not (Test-IsAdministrator)) {

    Write-Host ""
    Write-Host "ERROR: Administrator privileges are required."
    Write-Host ""
    Write-Host "Please:"
    Write-Host "1. Close this PowerShell window."
    Write-Host "2. Open PowerShell as Administrator."
    Write-Host "3. Navigate to the project directory."
    Write-Host "4. Run .\setup.ps1"
    Write-Host ""

    exit 1
}

Write-Success "Administrator privileges verified."

# ============================================================
# REQUIREMENTS FILE
# ============================================================

Write-Step "[2/8] Checking project dependencies"

if (-not (Test-Path $RequirementsFile)) {

    throw "requirements.txt was not found at: $RequirementsFile"
}

Write-Success "requirements.txt found."

# ============================================================
# PYTHON 3.14.7
# ============================================================

Write-Step "[3/8] Checking Python $PythonVersion"

$Python3147 = Find-Python3147

if ($Python3147) {

    Write-Success "Python $PythonVersion already installed."

    Write-Host ""
    Write-Host "Using Python:"
    Write-Host "  $Python3147"

}
else {

    Write-WarningMessage `
        "Python $PythonVersion was not found."

    Write-Info `
        "Installing Python $PythonVersion without removing existing Python versions."

    $InstallerPath = Join-Path `
        $env:TEMP `
        $PythonInstallerName

    Download-PythonInstaller $InstallerPath

    # --------------------------------------------------------
    # Install Python 3.14.7 separately
    #
    # This does NOT uninstall older Python versions.
    # --------------------------------------------------------

    $PrimaryPythonTarget = `
        Join-Path `
        $env:ProgramFiles `
        "Python314"

    Write-Info `
        "Installing Python $PythonVersion into:"
    Write-Host "  $PrimaryPythonTarget"

    $PythonInstallArguments = @(
        "/quiet",
        "InstallAllUsers=1",
        "TargetDir=$PrimaryPythonTarget",
        "PrependPath=0",
        "Include_test=0",
        "Include_pip=1",
        "Include_launcher=1"
    )

    $pythonProcess = Start-Process `
        -FilePath $InstallerPath `
        -ArgumentList $PythonInstallArguments `
        -Wait `
        -PassThru

    if ($pythonProcess.ExitCode -ne 0) {

        throw `
            "Python $PythonVersion installation failed. Exit code: $($pythonProcess.ExitCode)"
    }

    # --------------------------------------------------------
    # Search again
    # --------------------------------------------------------

    $Python3147 = Find-Python3147

    if (-not $Python3147) {

        if (Test-Path "$PrimaryPythonTarget\python.exe") {

            $Python3147 = `
                (Resolve-Path "$PrimaryPythonTarget\python.exe").Path
        }
    }

    if (-not $Python3147) {

        throw `
            "Python $PythonVersion was installed but could not be located."
    }

    Write-Success `
        "Python $PythonVersion installed successfully."
}

# ------------------------------------------------------------
# Verify exact version
# ------------------------------------------------------------

$DetectedPythonVersion = Get-PythonVersion $Python3147

if ($DetectedPythonVersion -ne $PythonVersion) {

    throw `
        "Incorrect Python version detected: $DetectedPythonVersion. Required: $PythonVersion"
}

Write-Success `
    "Python version verified: $DetectedPythonVersion"

# ============================================================
# DEVELOPMENT VENV
# ============================================================

Write-Step "[4/8] Checking development .venv"

if (Test-Path $VenvPython) {

    $ExistingVenvVersion = `
        Get-PythonVersion $VenvPython

    if ($ExistingVenvVersion -eq $PythonVersion) {

        Write-Success ".venv already exists."
        Write-Success "Development Python $ExistingVenvVersion verified."

    }
    else {

        Write-WarningMessage `
            ".venv uses Python $ExistingVenvVersion instead of $PythonVersion."

        Write-Info "Recreating .venv with Python $PythonVersion..."

        Remove-Item `
            -Recurse `
            -Force `
            $VenvPath

        & $Python3147 -m venv $VenvPath

        if ($LASTEXITCODE -ne 0) {

            throw "Failed to recreate .venv."
        }

        Write-Success ".venv recreated."
    }

}
else {

    Write-Info ".venv does not exist."

    Write-Info `
        "Creating development environment using Python $PythonVersion..."

    & $Python3147 -m venv $VenvPath

    if ($LASTEXITCODE -ne 0) {

        throw "Failed to create .venv."
    }

    Write-Success ".venv created."
}

# ------------------------------------------------------------
# Verify .venv
# ------------------------------------------------------------

if (-not (Test-Path $VenvPython)) {

    throw `
        ".venv was created but .venv\Scripts\python.exe was not found."
}

$VenvVersion = Get-PythonVersion $VenvPython

if ($VenvVersion -ne $PythonVersion) {

    throw `
        ".venv Python version is $VenvVersion. Required: $PythonVersion"
}

Write-Success "Development environment verified."

# ------------------------------------------------------------
# Install development dependencies
# ------------------------------------------------------------

Write-Info "Installing development dependencies..."

& $VenvPython -m pip install --upgrade pip

if ($LASTEXITCODE -ne 0) {

    throw "Failed to update pip in .venv."
}

& $VenvPython -m pip install -r $RequirementsFile

if ($LASTEXITCODE -ne 0) {

    throw "Failed to install development dependencies."
}

Write-Success "Development dependencies installed."

# ============================================================
# DEPLOYMENT RUNTIME
# ============================================================

Write-Step "[5/8] Checking deployment runtime"

if (Test-Path $RuntimePython) {

    $ExistingRuntimeVersion = `
        Get-PythonVersion $RuntimePython

    if ($ExistingRuntimeVersion -eq $PythonVersion) {

        Write-Success "Deployment runtime already exists."
        Write-Success `
            "Runtime Python $ExistingRuntimeVersion verified."

    }
    else {

        throw `
            "Existing runtime uses Python $ExistingRuntimeVersion. Required: $PythonVersion. Existing runtime was NOT modified."
    }

}
else {

    Write-Info "Deployment runtime does not exist."

    Write-Info `
        "Creating standalone Python $PythonVersion deployment runtime."

    # --------------------------------------------------------
    # IMPORTANT
    #
    # DO NOT use:
    #
    #     python -m venv runtime
    #
    # runtime must be a standalone Python installation.
    # --------------------------------------------------------

    if (Test-Path $RuntimePath) {

        Write-WarningMessage `
            "runtime directory exists but runtime\python.exe is missing."

        Write-Info `
            "The incomplete runtime directory will be removed."

        Remove-Item `
            -Recurse `
            -Force `
            $RuntimePath
    }

    New-Item `
        -ItemType Directory `
        -Force `
        -Path $RuntimePath |
        Out-Null

    $RuntimeInstallerPath = Join-Path `
        $env:TEMP `
        $PythonInstallerName

    Download-PythonInstaller $RuntimeInstallerPath

    Write-Info "Installing standalone Python runtime..."

    $RuntimeInstallArguments = @(
        "/quiet",
        "InstallAllUsers=0",
        "TargetDir=$RuntimePath",
        "PrependPath=0",
        "Include_test=0",
        "Include_pip=1",
        "Include_launcher=0"
    )

    $runtimeProcess = Start-Process `
        -FilePath $RuntimeInstallerPath `
        -ArgumentList $RuntimeInstallArguments `
        -Wait `
        -PassThru

    if ($runtimeProcess.ExitCode -ne 0) {

        throw `
            "Deployment runtime installation failed. Exit code: $($runtimeProcess.ExitCode)"
    }

    if (-not (Test-Path $RuntimePython)) {

        throw `
            "Deployment runtime was installed but runtime\python.exe was not found."
    }

    Write-Success "Standalone deployment runtime created."
}

# ------------------------------------------------------------
# Verify runtime version
# ------------------------------------------------------------

$RuntimeVersion = Get-PythonVersion $RuntimePython

if ($RuntimeVersion -ne $PythonVersion) {

    throw `
        "Deployment runtime version is $RuntimeVersion. Required: $PythonVersion"
}

Write-Success `
    "Deployment runtime Python $RuntimeVersion verified."

# ============================================================
# RUNTIME DEPENDENCIES
# ============================================================

Write-Step "[6/8] Installing deployment dependencies"

Write-Info "Installing runtime dependencies from requirements.txt..."

& $RuntimePython -m pip install --upgrade pip

if ($LASTEXITCODE -ne 0) {

    throw "Failed to update runtime pip."
}

& $RuntimePython -m pip install -r $RequirementsFile

if ($LASTEXITCODE -ne 0) {

    throw "Failed to install runtime dependencies."
}

Write-Success "Runtime dependencies installed."

# ------------------------------------------------------------
# Verify pywin32 import
# ------------------------------------------------------------

Write-Info "Checking pywin32..."

$pywin32Test = @'
import win32service
import win32serviceutil
import win32event
print("pywin32 OK")
'@

$pywin32Result = `
    & $RuntimePython -c $pywin32Test 2>&1

if ($LASTEXITCODE -ne 0) {

    Write-WarningMessage `
        "pywin32 import test failed."

    Write-Host $pywin32Result

    throw "pywin32 is not functioning correctly in runtime."
}

Write-Success "pywin32 verified."

# ============================================================
# PYWIN32 SERVICE HOST
# ============================================================

Write-Step "[7/8] Configuring pywin32 service host"

$PostInstallScript = `
    Find-Pywin32PostInstall $RuntimePath

if ($PostInstallScript) {

    # --------------------------------------------------------
    # Only run post-install if pythonservice.exe is not already
    # correctly available.
    #
    # This avoids repeatedly modifying DLLs on every setup run.
    # --------------------------------------------------------

    if (-not (Test-Path $RuntimeServiceHost)) {

        Write-Info `
            "runtime\pythonservice.exe not found."

        Write-Info `
            "Running pywin32 post-installation..."

        & $RuntimePython `
            $PostInstallScript `
            -install

        if ($LASTEXITCODE -ne 0) {

            throw `
                "pywin32 post-install failed."
        }

        Write-Success "pywin32 post-install completed."
    }
    else {

        Write-Success `
            "runtime\pythonservice.exe already exists."

        Write-Info `
            "Skipping pywin32 post-install."
    }

}
else {

    Write-WarningMessage `
        "pywin32 post-install script was not found."

    Write-Info `
        "Continuing with existing pywin32 installation."
}

# ------------------------------------------------------------
# Verify pythonservice.exe
#
# pip installs pywin32's pythonservice.exe directly into
# sys.prefix (i.e. the runtime root, $RuntimeServiceHost).
# pywin32_postinstall.py above only handles DLL registration
# and the .pth file -- it does not place pythonservice.exe
# anywhere. If it's missing here, the pywin32 install itself
# is broken/incomplete, and that should fail loudly rather
# than being silently patched over by copying a file from an
# unexpected location (which could be a stale or architecture-
# mismatched binary from a prior partial install).
# ------------------------------------------------------------

if (-not (Test-Path $RuntimeServiceHost)) {

    throw `
        "runtime\pythonservice.exe was not found after pywin32 installation. " +
        "Expected it at: $RuntimeServiceHost. " +
        "This indicates the pywin32 package install into the runtime is broken " +
        "or incomplete -- reinstall pywin32 into the runtime and re-run setup."
}

Write-Success `
    "runtime\pythonservice.exe verified."

# ============================================================
# LOGS
# ============================================================

Write-Info "Checking logs directory..."

if (-not (Test-Path $LogsPath)) {

    New-Item `
        -ItemType Directory `
        -Force `
        -Path $LogsPath |
        Out-Null

    Write-Success "logs directory created."
}
else {

    Write-Success "logs directory already exists."
}

# ============================================================
# WINDOWS SERVICE
# ============================================================

Write-Step "[8/8] Configuring IDSIPS Windows Service"

$ExistingService = `
    Get-Service `
        -Name $ServiceName `
        -ErrorAction SilentlyContinue

# ------------------------------------------------------------
# Determine expected service executable
# ------------------------------------------------------------

$ExpectedServicePath = $RuntimeServiceHost

# ------------------------------------------------------------
# Check existing service
# ------------------------------------------------------------

if ($ExistingService) {

    Write-Info "IDSIPS service already exists."

    # --------------------------------------------------------
    # Read service configuration
    # --------------------------------------------------------

    $ServiceInfo = `
        Get-CimInstance `
            Win32_Service `
            -Filter "Name='$ServiceName'"

    $CurrentServicePath = $ServiceInfo.PathName

    Write-Info "Current service path:"
    Write-Host "  $CurrentServicePath"

    Write-Info "Expected service path:"
    Write-Host "  `"$ExpectedServicePath`""

    # --------------------------------------------------------
    # Stop service before changing configuration
    # --------------------------------------------------------

    if ($ExistingService.Status -eq "Running") {

        Write-Info "Stopping IDSIPS service..."

        Stop-Service `
            -Name $ServiceName `
            -Force `
            -ErrorAction SilentlyContinue

        Start-Sleep -Seconds 3
    }

    # --------------------------------------------------------
    # If the service points to the wrong runtime, remove it.
    # --------------------------------------------------------

    if (
        $CurrentServicePath -and
        (
            $CurrentServicePath -notlike "*$ExpectedServicePath*"
        )
    ) {

        Write-WarningMessage `
            "Existing IDSIPS service points to a different executable."

        Write-Info `
            "Removing stale IDSIPS service registration..."

        try {

            & $RuntimePython `
                "$ProjectRoot\service.py" `
                remove

        }
        catch {

            Write-WarningMessage `
                "Service removal returned an error. Continuing cleanup."
        }

        Start-Sleep -Seconds 5

        $ExistingService = `
            Get-Service `
                -Name $ServiceName `
                -ErrorAction SilentlyContinue

        # ----------------------------------------------------
        # Verify removal actually succeeded.
        #
        # Without this check, a failed/incomplete removal would
        # silently fall through to "Existing IDSIPS service
        # registration retained" below -- leaving the stale,
        # wrong-executable service in place while the script
        # reports success.
        # ----------------------------------------------------

        if ($ExistingService) {

            throw `
                "Failed to remove the stale IDSIPS service registration. " +
                "It still points to a different executable than expected " +
                "($ExpectedServicePath). Stop and delete the 'IDSIPS' service " +
                "manually (sc.exe delete IDSIPS) and re-run setup."
        }

        Write-Success `
            "Stale IDSIPS service registration removed."
    }

}
else {

    Write-Info "IDSIPS service does not exist."
}

# ============================================================
# INSTALL SERVICE IF NEEDED
# ============================================================

$ExistingService = `
    Get-Service `
        -Name $ServiceName `
        -ErrorAction SilentlyContinue

if (-not $ExistingService) {

    Write-Info `
        "Installing IDSIPS service using deployment runtime..."

    & $RuntimePython `
        "$ProjectRoot\service.py" `
        install

    if ($LASTEXITCODE -ne 0) {

        throw `
            "IDSIPS service installation failed."
    }

    Start-Sleep -Seconds 3

    Write-Success "IDSIPS service installed."

}
else {

    Write-Success "Existing IDSIPS service registration retained."
}

# ============================================================
# SERVICE STARTUP TYPE
# ============================================================

Write-Info "Configuring automatic startup..."

Set-Service `
    -Name $ServiceName `
    -StartupType Automatic

Write-Success "IDSIPS service startup set to Automatic."

# ============================================================
# VERIFY SERVICE PATH
# ============================================================

$FinalServiceInfo = `
    Get-CimInstance `
        Win32_Service `
        -Filter "Name='$ServiceName'"

if (-not $FinalServiceInfo) {

    throw `
        "IDSIPS service could not be found after installation."
}

Write-Host ""
Write-Host "Final service configuration:"
Write-Host ""

Write-Host "Name:"
Write-Host "  $($FinalServiceInfo.Name)"

Write-Host "State:"
Write-Host "  $($FinalServiceInfo.State)"

Write-Host "Start Mode:"
Write-Host "  $($FinalServiceInfo.StartMode)"

Write-Host "Executable:"
Write-Host "  $($FinalServiceInfo.PathName)"

# ============================================================
# START SERVICE
# ============================================================

if ($FinalServiceInfo.State -ne "Running") {

    Write-Info "Starting IDSIPS service..."

    Start-Service `
        -Name $ServiceName

    Start-Sleep -Seconds 5
}

# ============================================================
# FINAL SERVICE VERIFICATION
# ============================================================

$FinalService = `
    Get-Service `
        -Name $ServiceName `
        -ErrorAction Stop

if ($FinalService.Status -ne "Running") {

    throw `
        "IDSIPS service failed to start. Current status: $($FinalService.Status)"
}

# ------------------------------------------------------------
# Verify final service executable
# ------------------------------------------------------------

$FinalServiceInfo = `
    Get-CimInstance `
        Win32_Service `
        -Filter "Name='$ServiceName'"

$FinalPath = $FinalServiceInfo.PathName

if ($FinalPath -notlike "*$ExpectedServicePath*") {

    throw `
        "IDSIPS service is not using the expected deployment runtime.`nExpected: $ExpectedServicePath`nActual: $FinalPath"
}

# ============================================================
# FINAL OUTPUT
# ============================================================

Write-Host ""
Write-Host ""
Write-Host "============================================================"
Write-Host "       IDSIPS SETUP COMPLETED SUCCESSFULLY"
Write-Host "============================================================"
Write-Host ""

Write-Host "Project Root:"
Write-Host "  $ProjectRoot"

Write-Host ""

Write-Host "Python Version:"
Write-Host "  $PythonVersion"

Write-Host ""

Write-Host "Development Environment:"
Write-Host "  $VenvPath"

Write-Host ""

Write-Host "Development Python:"
Write-Host "  $VenvPython"

Write-Host ""

Write-Host "Deployment Runtime:"
Write-Host "  $RuntimePath"

Write-Host ""

Write-Host "Deployment Python:"
Write-Host "  $RuntimePython"

Write-Host ""

Write-Host "Service Host:"
Write-Host "  $RuntimeServiceHost"

Write-Host ""

Write-Host "Windows Service:"
Write-Host "  $ServiceName"

Write-Host ""

Write-Host "Service Status:"
Get-Service `
    -Name $ServiceName |
    Format-Table Name, Status, StartType -AutoSize

Write-Host ""

Write-Host "Final Service Executable:"
Write-Host "  $($FinalServiceInfo.PathName)"

Write-Host ""

Write-Host "Logs:"
Write-Host "  $LogsPath"

Write-Host ""

Write-Success "IDSIPS is ready."

Write-Host ""
Write-Host "Development commands:"
Write-Host "  .\.venv\Scripts\Activate.ps1"
Write-Host "  python --version"
Write-Host "  pytest"

Write-Host ""
Write-Host "Service verification:"
Write-Host "  Get-Service IDSIPS"

Write-Host ""












# # ============================================================
# # IDSIPS - Development Environment Setup
# # ============================================================

# $ErrorActionPreference = "Stop"

# $ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
# $RuntimePath = Join-Path $ProjectRoot "runtime"
# $ServiceName = "IDSIPS"
# $PythonVersion = "3.14.7"

# Write-Host ""
# Write-Host "========================================" -ForegroundColor Cyan
# Write-Host "       IDSIPS Setup" -ForegroundColor Cyan
# Write-Host "========================================" -ForegroundColor Cyan
# Write-Host ""

# # ------------------------------------------------------------
# # 1. Check Python Install Manager
# # ------------------------------------------------------------

# Write-Host "[1/6] Checking Python Install Manager..." -ForegroundColor Yellow

# $PyCommand = Get-Command py -ErrorAction SilentlyContinue

# if (-not $PyCommand) {
#     Write-Host ""
#     Write-Host "Python Install Manager was not found." -ForegroundColor Red
#     Write-Host "Please install Python from https://www.python.org/downloads/windows/"
#     exit 1
# }

# Write-Host "Python Install Manager found." -ForegroundColor Green


# # ------------------------------------------------------------
# # 2. Create project runtime
# # ------------------------------------------------------------

# Write-Host ""
# Write-Host "[2/6] Checking IDSIPS runtime..." -ForegroundColor Yellow

# $RuntimePython = Join-Path $RuntimePath "python.exe"

# if (-not (Test-Path $RuntimePython)) {

#     Write-Host "Runtime not found. Creating Python $PythonVersion runtime..."

#     & py install --target="$RuntimePath" $PythonVersion

#     if (-not (Test-Path $RuntimePython)) {
#         throw "Python runtime creation failed."
#     }

#     Write-Host "Runtime created successfully." -ForegroundColor Green
# }
# else {
#     Write-Host "Runtime already exists." -ForegroundColor Green
# }


# # ------------------------------------------------------------
# # 3. Check Python runtime
# # ------------------------------------------------------------

# Write-Host ""
# Write-Host "[3/6] Verifying Python runtime..." -ForegroundColor Yellow

# $InstalledVersion = & $RuntimePython --version

# Write-Host "Detected: $InstalledVersion"

# if ($InstalledVersion -notlike "*$PythonVersion*") {
#     throw "Incorrect Python version detected. Expected Python $PythonVersion."
# }

# Write-Host "Python runtime verified." -ForegroundColor Green


# # ------------------------------------------------------------
# # 4. Install / verify pywin32
# # ------------------------------------------------------------

# Write-Host ""
# Write-Host "[4/6] Checking Python dependencies..." -ForegroundColor Yellow

# $PyWin32Check = & $RuntimePython -c "import win32service, win32serviceutil; print('OK')" 2>$null

# if ($PyWin32Check -ne "OK") {

#     Write-Host "pywin32 not found. Installing..."

#     & $RuntimePython -m pip install pywin32

#     $PyWin32Check = & $RuntimePython -c "import win32service, win32serviceutil; print('OK')" 2>$null

#     if ($PyWin32Check -ne "OK") {
#         throw "pywin32 installation failed."
#     }

#     Write-Host "pywin32 installed successfully." -ForegroundColor Green
# }
# else {
#     Write-Host "pywin32 already installed." -ForegroundColor Green
# }

# $RuntimeServicePython = Join-Path $RuntimePath "pythonservice.exe"

# if (-not (Test-Path $RuntimeServicePython)) {
#     throw "pythonservice.exe was not found in the IDSIPS runtime after pywin32 installation."
# }

# Write-Host "pythonservice.exe verified." -ForegroundColor Green

# # ------------------------------------------------------------
# # Check PyYAML
# # ------------------------------------------------------------

# $PyYAMLCheck = & $RuntimePython -c "import yaml; print('OK')" 2>$null

# if ($PyYAMLCheck -ne "OK") {

#     Write-Host "PyYAML not found. Installing..."

#     & $RuntimePython -m pip install PyYAML

#     $PyYAMLCheck = & $RuntimePython -c "import yaml; print('OK')" 2>$null

#     if ($PyYAMLCheck -ne "OK") {
#         throw "PyYAML installation failed."
#     }

#     Write-Host "PyYAML installed successfully." -ForegroundColor Green
# }
# else {
#     Write-Host "PyYAML already installed." -ForegroundColor Green
# }

# # ------------------------------------------------------------
# # Create runtime log directory
# # ------------------------------------------------------------

# $LogsPath = Join-Path $ProjectRoot "logs"

# if (-not (Test-Path $LogsPath)) {
#     Write-Host "Creating logs directory..."
#     New-Item -ItemType Directory -Path $LogsPath -Force | Out-Null
# }

# Write-Host "Logs directory verified." -ForegroundColor Green

# # ------------------------------------------------------------
# # 5. Install / update Windows Service
# # ------------------------------------------------------------

# Write-Host ""
# Write-Host "[5/6] Checking Windows Service..." -ForegroundColor Yellow

# $ExistingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

# $ServiceNeedsInstall = $false

# if (-not $ExistingService) {

#     Write-Host "IDSIPS service not found. Installing..."
#     $ServiceNeedsInstall = $true

# }
# #     & $RuntimePython "$ProjectRoot\service.py" install

# #     if ($LASTEXITCODE -ne 0) {
# #         throw "IDSIPS service installation failed."
# #     }

# #     Write-Host "IDSIPS service installed." -ForegroundColor Green
# # }
# else {
#     Write-Host "IDSIPS service already exists." -ForegroundColor Green
#      # Check the executable registered with Windows
#     $ServiceConfig = sc.exe qc $ServiceName 2>&1

#     $BinaryPathLine = $ServiceConfig |
#         Select-String "BINARY_PATH_NAME"

#     $ExpectedServicePath = Join-Path $RuntimePath "pythonservice.exe"

#     if (-not $BinaryPathLine -or
#         $BinaryPathLine.ToString() -notlike "*$ExpectedServicePath*") {

#         Write-Host "Existing service configuration is incorrect." -ForegroundColor Yellow
#         Write-Host "Updating IDSIPS service configuration..." -ForegroundColor Yellow

#         $ServiceNeedsInstall = $true
#     }
# }


# if ($ServiceNeedsInstall) {

#     # Stop the existing service if necessary
#     if ($ExistingService -and $ExistingService.Status -eq "Running") {

#         Write-Host "Stopping existing IDSIPS service..."

#         Stop-Service -Name $ServiceName -Force

#         Start-Sleep -Seconds 2
#     }

#     # Remove old service registration
#     if ($ExistingService) {

#         Write-Host "Removing old IDSIPS service registration..."

#         & $RuntimePython "$ProjectRoot\service.py" remove
#         if ($LASTEXITCODE -ne 0) {
#             throw "Failed to remove existing IDSIPS service."
#         }

#         Start-Sleep -Seconds 2
#     }

#     # Install service using the project runtime
#     Write-Host "Installing IDSIPS service..."

#     & $RuntimePython "$ProjectRoot\service.py" install

#     if ($LASTEXITCODE -ne 0) {
#         throw "IDSIPS service installation failed."
#     }

#     Write-Host "IDSIPS service installed successfully." -ForegroundColor Green
# }


# # ------------------------------------------------------------
# # 6. Start and verify service
# # ------------------------------------------------------------

# Write-Host ""
# Write-Host "[6/6] Starting IDSIPS service..." -ForegroundColor Yellow

# $Service = Get-Service -Name $ServiceName -ErrorAction Stop

# if ($Service.Status -ne "Running") {
#     Start-Service -Name $ServiceName
# }

# Start-Sleep -Seconds 2

# $Service = Get-Service -Name $ServiceName

# if ($Service.Status -ne "Running") {
#     throw "IDSIPS service failed to start."
# }

# Write-Host ""
# Write-Host "========================================" -ForegroundColor Green
# Write-Host "       IDSIPS SETUP COMPLETE" -ForegroundColor Green
# Write-Host "========================================" -ForegroundColor Green
# Write-Host ""
# Write-Host "Service : $($Service.DisplayName)"
# Write-Host "Status  : $($Service.Status)"
# Write-Host "Runtime : $RuntimePython"
# Write-Host ""












# # ============================================================
# # IDSIPS - Development Environment Setup
# # ============================================================

# $ErrorActionPreference = "Stop"

# $ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
# $RuntimePath = Join-Path $ProjectRoot "runtime"
# $ServiceName = "IDSIPS"
# $PythonVersion = "3.14.7"

# Write-Host ""
# Write-Host "========================================" -ForegroundColor Cyan
# Write-Host "       IDSIPS Setup" -ForegroundColor Cyan
# Write-Host "========================================" -ForegroundColor Cyan
# Write-Host ""

# # ------------------------------------------------------------
# # 1. Check Python Install Manager
# # ------------------------------------------------------------

# Write-Host "[1/6] Checking Python Install Manager..." -ForegroundColor Yellow

# $PyCommand = Get-Command py -ErrorAction SilentlyContinue

# if (-not $PyCommand) {
#     Write-Host ""
#     Write-Host "Python Install Manager was not found." -ForegroundColor Red
#     Write-Host "Please install Python from https://www.python.org/downloads/windows/"
#     exit 1
# }

# Write-Host "Python Install Manager found." -ForegroundColor Green


# # ------------------------------------------------------------
# # 2. Create project runtime
# # ------------------------------------------------------------

# Write-Host ""
# Write-Host "[2/6] Checking IDSIPS runtime..." -ForegroundColor Yellow

# $RuntimePython = Join-Path $RuntimePath "python.exe"

# if (-not (Test-Path $RuntimePython)) {

#     Write-Host "Runtime not found. Creating Python $PythonVersion runtime..."

#     & py install --target="$RuntimePath" $PythonVersion

#     if (-not (Test-Path $RuntimePython)) {
#         throw "Python runtime creation failed."
#     }

#     Write-Host "Runtime created successfully." -ForegroundColor Green
# }
# else {
#     Write-Host "Runtime already exists." -ForegroundColor Green
# }


# # ------------------------------------------------------------
# # 3. Check Python runtime
# # ------------------------------------------------------------

# Write-Host ""
# Write-Host "[3/6] Verifying Python runtime..." -ForegroundColor Yellow

# $InstalledVersion = & $RuntimePython --version

# Write-Host "Detected: $InstalledVersion"

# if ($InstalledVersion -notlike "*$PythonVersion*") {
#     throw "Incorrect Python version detected. Expected Python $PythonVersion."
# }

# Write-Host "Python runtime verified." -ForegroundColor Green


# # ------------------------------------------------------------
# # 4. Install / verify pywin32
# # ------------------------------------------------------------

# Write-Host ""
# Write-Host "[4/6] Checking Python dependencies..." -ForegroundColor Yellow

# $PyWin32Check = & $RuntimePython -c "import win32service, win32serviceutil; print('OK')" 2>$null

# if ($PyWin32Check -ne "OK") {

#     Write-Host "pywin32 not found. Installing..."

#     & $RuntimePython -m pip install pywin32

#     $PyWin32Check = & $RuntimePython -c "import win32service, win32serviceutil; print('OK')" 2>$null

#     if ($PyWin32Check -ne "OK") {
#         throw "pywin32 installation failed."
#     }

#     Write-Host "pywin32 installed successfully." -ForegroundColor Green
# }
# else {
#     Write-Host "pywin32 already installed." -ForegroundColor Green
# }

# $RuntimeServicePython = Join-Path $RuntimePath "pythonservice.exe"

# if (-not (Test-Path $RuntimeServicePython)) {
#     throw "pythonservice.exe was not found in the IDSIPS runtime after pywin32 installation."
# }

# Write-Host "pythonservice.exe verified." -ForegroundColor Green

# # ------------------------------------------------------------
# # Check PyYAML
# # ------------------------------------------------------------

# $PyYAMLCheck = & $RuntimePython -c "import yaml; print('OK')" 2>$null

# if ($PyYAMLCheck -ne "OK") {

#     Write-Host "PyYAML not found. Installing..."

#     & $RuntimePython -m pip install PyYAML

#     $PyYAMLCheck = & $RuntimePython -c "import yaml; print('OK')" 2>$null

#     if ($PyYAMLCheck -ne "OK") {
#         throw "PyYAML installation failed."
#     }

#     Write-Host "PyYAML installed successfully." -ForegroundColor Green
# }
# else {
#     Write-Host "PyYAML already installed." -ForegroundColor Green
# }

# # ------------------------------------------------------------
# # Create runtime log directory
# # ------------------------------------------------------------

# $LogsPath = Join-Path $ProjectRoot "logs"

# if (-not (Test-Path $LogsPath)) {
#     Write-Host "Creating logs directory..."
#     New-Item -ItemType Directory -Path $LogsPath -Force | Out-Null
# }

# Write-Host "Logs directory verified." -ForegroundColor Green

# # ------------------------------------------------------------
# # 5. Install / update Windows Service
# # ------------------------------------------------------------

# Write-Host ""
# Write-Host "[5/6] Checking Windows Service..." -ForegroundColor Yellow

# $ExistingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

# $ServiceNeedsInstall = $false

# if (-not $ExistingService) {

#     Write-Host "IDSIPS service not found. Installing..."
#     $ServiceNeedsInstall = $true

# }
# #     & $RuntimePython "$ProjectRoot\service.py" install

# #     if ($LASTEXITCODE -ne 0) {
# #         throw "IDSIPS service installation failed."
# #     }

# #     Write-Host "IDSIPS service installed." -ForegroundColor Green
# # }
# else {
#     Write-Host "IDSIPS service already exists." -ForegroundColor Green
#      # Check the executable registered with Windows
#     $ServiceConfig = sc.exe qc $ServiceName 2>&1

#     $BinaryPathLine = $ServiceConfig |
#         Select-String "BINARY_PATH_NAME"

#     $ExpectedServicePath = Join-Path $RuntimePath "pythonservice.exe"

#     if (-not $BinaryPathLine -or
#         $BinaryPathLine.ToString() -notlike "*$ExpectedServicePath*") {

#         Write-Host "Existing service configuration is incorrect." -ForegroundColor Yellow
#         Write-Host "Updating IDSIPS service configuration..." -ForegroundColor Yellow

#         $ServiceNeedsInstall = $true
#     }
# }


# if ($ServiceNeedsInstall) {

#     # Stop the existing service if necessary
#     if ($ExistingService -and $ExistingService.Status -eq "Running") {

#         Write-Host "Stopping existing IDSIPS service..."

#         Stop-Service -Name $ServiceName -Force

#         Start-Sleep -Seconds 2
#     }

#     # Remove old service registration
#     if ($ExistingService) {

#         Write-Host "Removing old IDSIPS service registration..."

#         & $RuntimePython "$ProjectRoot\service.py" remove
#         if ($LASTEXITCODE -ne 0) {
#             throw "Failed to remove existing IDSIPS service."
#         }

#         Start-Sleep -Seconds 2
#     }

#     # Install service using the project runtime
#     Write-Host "Installing IDSIPS service..."

#     & $RuntimePython "$ProjectRoot\service.py" install

#     if ($LASTEXITCODE -ne 0) {
#         throw "IDSIPS service installation failed."
#     }

#     Write-Host "IDSIPS service installed successfully." -ForegroundColor Green
# }


# # ------------------------------------------------------------
# # 6. Start and verify service
# # ------------------------------------------------------------

# Write-Host ""
# Write-Host "[6/6] Starting IDSIPS service..." -ForegroundColor Yellow

# $Service = Get-Service -Name $ServiceName -ErrorAction Stop

# if ($Service.Status -ne "Running") {
#     Start-Service -Name $ServiceName
# }

# Start-Sleep -Seconds 2

# $Service = Get-Service -Name $ServiceName

# if ($Service.Status -ne "Running") {
#     throw "IDSIPS service failed to start."
# }

# Write-Host ""
# Write-Host "========================================" -ForegroundColor Green
# Write-Host "       IDSIPS SETUP COMPLETE" -ForegroundColor Green
# Write-Host "========================================" -ForegroundColor Green
# Write-Host ""
# Write-Host "Service : $($Service.DisplayName)"
# Write-Host "Status  : $($Service.Status)"
# Write-Host "Runtime : $RuntimePython"
# Write-Host ""