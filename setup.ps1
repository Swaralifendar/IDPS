# ============================================================
# IDSIPS - Development Environment Setup
# ============================================================

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RuntimePath = Join-Path $ProjectRoot "runtime"
$ServiceName = "IDSIPS"
$PythonVersion = "3.14.7"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "       IDSIPS Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------------------------
# 1. Check Python Install Manager
# ------------------------------------------------------------

Write-Host "[1/6] Checking Python Install Manager..." -ForegroundColor Yellow

$PyCommand = Get-Command py -ErrorAction SilentlyContinue

if (-not $PyCommand) {
    Write-Host ""
    Write-Host "Python Install Manager was not found." -ForegroundColor Red
    Write-Host "Please install Python from https://www.python.org/downloads/windows/"
    exit 1
}

Write-Host "Python Install Manager found." -ForegroundColor Green


# ------------------------------------------------------------
# 2. Create project runtime
# ------------------------------------------------------------

Write-Host ""
Write-Host "[2/6] Checking IDSIPS runtime..." -ForegroundColor Yellow

$RuntimePython = Join-Path $RuntimePath "python.exe"

if (-not (Test-Path $RuntimePython)) {

    Write-Host "Runtime not found. Creating Python $PythonVersion runtime..."

    & py install --target="$RuntimePath" $PythonVersion

    if (-not (Test-Path $RuntimePython)) {
        throw "Python runtime creation failed."
    }

    Write-Host "Runtime created successfully." -ForegroundColor Green
}
else {
    Write-Host "Runtime already exists." -ForegroundColor Green
}


# ------------------------------------------------------------
# 3. Check Python runtime
# ------------------------------------------------------------

Write-Host ""
Write-Host "[3/6] Verifying Python runtime..." -ForegroundColor Yellow

$InstalledVersion = & $RuntimePython --version

Write-Host "Detected: $InstalledVersion"

if ($InstalledVersion -notlike "*$PythonVersion*") {
    throw "Incorrect Python version detected. Expected Python $PythonVersion."
}

Write-Host "Python runtime verified." -ForegroundColor Green


# ------------------------------------------------------------
# 4. Install / verify pywin32
# ------------------------------------------------------------

Write-Host ""
Write-Host "[4/6] Checking Python dependencies..." -ForegroundColor Yellow

$PyWin32Check = & $RuntimePython -c "import win32service, win32serviceutil; print('OK')" 2>$null

if ($PyWin32Check -ne "OK") {

    Write-Host "pywin32 not found. Installing..."

    & $RuntimePython -m pip install pywin32

    $PyWin32Check = & $RuntimePython -c "import win32service, win32serviceutil; print('OK')" 2>$null

    if ($PyWin32Check -ne "OK") {
        throw "pywin32 installation failed."
    }

    Write-Host "pywin32 installed successfully." -ForegroundColor Green
}
else {
    Write-Host "pywin32 already installed." -ForegroundColor Green
}

# ------------------------------------------------------------
# Check PyYAML
# ------------------------------------------------------------

$PyYAMLCheck = & $RuntimePython -c "import yaml; print('OK')" 2>$null

if ($PyYAMLCheck -ne "OK") {

    Write-Host "PyYAML not found. Installing..."

    & $RuntimePython -m pip install PyYAML

    $PyYAMLCheck = & $RuntimePython -c "import yaml; print('OK')" 2>$null

    if ($PyYAMLCheck -ne "OK") {
        throw "PyYAML installation failed."
    }

    Write-Host "PyYAML installed successfully." -ForegroundColor Green
}
else {
    Write-Host "PyYAML already installed." -ForegroundColor Green
}


# ------------------------------------------------------------
# 5. Install / update Windows Service
# ------------------------------------------------------------

Write-Host ""
Write-Host "[5/6] Checking Windows Service..." -ForegroundColor Yellow

$ExistingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if (-not $ExistingService) {

    Write-Host "IDSIPS service not found. Installing..."

    & $RuntimePython "$ProjectRoot\service.py" install

    if ($LASTEXITCODE -ne 0) {
        throw "IDSIPS service installation failed."
    }

    Write-Host "IDSIPS service installed." -ForegroundColor Green
}
else {
    Write-Host "IDSIPS service already exists." -ForegroundColor Green
}


# ------------------------------------------------------------
# 6. Start and verify service
# ------------------------------------------------------------

Write-Host ""
Write-Host "[6/6] Starting IDSIPS service..." -ForegroundColor Yellow

$Service = Get-Service -Name $ServiceName -ErrorAction Stop

if ($Service.Status -ne "Running") {
    Start-Service -Name $ServiceName
}

Start-Sleep -Seconds 2

$Service = Get-Service -Name $ServiceName

if ($Service.Status -ne "Running") {
    throw "IDSIPS service failed to start."
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "       IDSIPS SETUP COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Service : $($Service.DisplayName)"
Write-Host "Status  : $($Service.Status)"
Write-Host "Runtime : $RuntimePython"
Write-Host ""