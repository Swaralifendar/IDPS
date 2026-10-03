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
# 4. Install / verify project dependencies
# ------------------------------------------------------------

Write-Host ""
Write-Host "[4/6] Checking project dependencies..." -ForegroundColor Yellow

$RequirementsFile = Join-Path $ProjectRoot "requirements.txt"

if (-not (Test-Path $RequirementsFile)) {
    throw "requirements.txt not found."
}

Write-Host "Installing project dependencies..."

& $RuntimePython -m pip install -r $RequirementsFile

if ($LASTEXITCODE -ne 0) {
    throw "Dependency installation failed."
}

# Verify critical dependencies
& $RuntimePython -c "import win32service, win32serviceutil, win32evtlog, yaml, pydivert; print('All dependencies OK')"

if ($LASTEXITCODE -ne 0) {
    throw "Dependency verification failed."
}

Write-Host "All project dependencies verified." -ForegroundColor Green

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

    Write-Host "IDSIPS service already exists. Updating service..."

    & $RuntimePython "$ProjectRoot\service.py" update

    if ($LASTEXITCODE -ne 0) {
        throw "IDSIPS service update failed."
    }

    Write-Host "IDSIPS service updated." -ForegroundColor Green
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