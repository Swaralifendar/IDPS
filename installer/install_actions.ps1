<#
.SYNOPSIS
    IDSIPS install actions. Run by the MSI (deferred, as SYSTEM)
    after the files are copied. Can also be run by hand from an
    elevated PowerShell.

.DESCRIPTION
    1. Creates %ProgramData%\IDSIPS (config, rules, logs, state),
       seeds missing config/rules and applies HOME_NET/INTERFACES.
    2. Locks down folder permissions:
         SYSTEM, Administrators : full control (everything)
         Users                  : read (config, rules only)
         logs, state            : no access for Users
    3. Registers the IDSIPS service (or updates an existing one):
         start type      Automatic (Delayed Start)
         recovery        restart after 5 s, 5 s, 30 s; reset after 1 day
    4. Starts the service. A start failure is reported in the log
       but does not fail the installation.

    Log: %ProgramData%\IDSIPS\logs\install.log

.PARAMETER InstallDir
    Application folder (e.g. C:\Program Files\IDSIPS).

.PARAMETER HomeNet
    "auto" or comma-separated networks, e.g. "10.0.0.0/8,192.168.1.0/24".

.PARAMETER Interfaces
    "auto" or comma-separated adapter names, e.g. "Ethernet,Wi-Fi".

.PARAMETER DataDir
    Data folder. Only for testing: the installed service always
    uses %ProgramData%\IDSIPS.

.PARAMETER SkipService
    Only for testing: do steps 1-2, do not touch the service.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,

    [string]$HomeNet = "auto",

    [string]$Interfaces = "auto",

    [string]$DataDir = (Join-Path $env:ProgramData "IDSIPS"),

    [switch]$SkipService
)

$ErrorActionPreference = "Stop"

$ServiceName = "IDSIPS"

# Well-known SIDs (independent of the Windows display language)
$SidSystem = "*S-1-5-18"
$SidAdmins = "*S-1-5-32-544"
$SidUsers  = "*S-1-5-32-545"

# "C:\Program Files\IDSIPS\." -> "C:\Program Files\IDSIPS"
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir).TrimEnd("\", ".")
$DataDir = [System.IO.Path]::GetFullPath($DataDir).TrimEnd("\")

$Python = Join-Path $InstallDir "runtime\python.exe"
$ServiceScript = Join-Path $InstallDir "service.py"
$ConfigureScript = Join-Path $InstallDir "installer\configure.py"

# Python resolves the same data folder (paths.py)
$env:IDSIPS_DATA = $DataDir

New-Item -ItemType Directory -Force -Path (Join-Path $DataDir "logs") | Out-Null
$LogFile = Join-Path $DataDir "logs\install.log"


function Write-Log([string]$Message) {
    $line = "{0} | {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Write-Output $line
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}


function Invoke-Checked([string]$Description, [scriptblock]$Command) {
    $output = & $Command 2>&1 | Out-String
    $code = $LASTEXITCODE

    if ($output.Trim()) {
        Write-Log ("  " + $output.Trim().Replace("`n", "`n  "))
    }

    if ($code -ne 0) {
        throw "$Description failed (exit code $code)"
    }
}


function Wait-ServiceStatus([string]$Status, [int]$TimeoutSeconds) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $deadline) {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

        if ($service -and $service.Status -eq $Status) {
            return $true
        }

        Start-Sleep -Milliseconds 500
    }

    return $false
}


try {
    Write-Log "===== IDSIPS install actions ====="
    Write-Log "InstallDir=$InstallDir DataDir=$DataDir HomeNet=$HomeNet Interfaces=$Interfaces"

    if (-not (Test-Path $Python)) {
        throw "Bundled Python runtime not found: $Python"
    }

    # ---------------------------------------------------------
    # 1. Data folder, default config/rules, network settings
    # ---------------------------------------------------------
    Write-Log "[1/4] Preparing data folder and network configuration"

    Push-Location $InstallDir
    try {
        Invoke-Checked "Configuration" {
            & $Python $ConfigureScript --home-net $HomeNet --interfaces $Interfaces
        }
    }
    finally {
        Pop-Location
    }

    # ---------------------------------------------------------
    # 2. Folder permissions
    # ---------------------------------------------------------
    Write-Log "[2/4] Setting folder permissions"

    # Owner Administrators, so the creator of an older folder keeps
    # no implicit right to change permissions.
    Invoke-Checked "Set owner" { icacls $DataDir /setowner $SidAdmins /T /C /Q }

    # Root: only SYSTEM and Administrators, no inherited entries
    Invoke-Checked "Root permissions" {
        icacls $DataDir /inheritance:r /grant:r "${SidSystem}:(OI)(CI)F" "${SidAdmins}:(OI)(CI)F" /Q
    }

    # Everything below just inherits from the root
    Invoke-Checked "Reset child permissions" { icacls "$DataDir\*" /reset /T /C /Q }

    # Users may read (not change) the configuration and rules
    foreach ($folder in "config", "rules") {
        Invoke-Checked "Read access to $folder" {
            icacls (Join-Path $DataDir $folder) /grant "${SidUsers}:(OI)(CI)RX" /Q
        }
    }

    if ($SkipService) {
        Write-Log "SkipService: service not changed"
        Write-Log "===== Install actions completed ====="
        exit 0
    }

    # ---------------------------------------------------------
    # 3. Register / update the service
    # ---------------------------------------------------------
    Write-Log "[3/4] Registering the $ServiceName service"

    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($existing -and $existing.Status -ne "Stopped") {
        Write-Log "  Stopping the existing service"
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue

        if (-not (Wait-ServiceStatus "Stopped" 60)) {
            throw "The existing $ServiceName service did not stop"
        }
    }

    # pywin32 records the service class and points the service at
    # runtime\pythonservice.exe. "update" re-points an existing
    # service (e.g. a development install) at this folder.
    $verb = if ($existing) { "update" } else { "install" }

    Push-Location $InstallDir
    try {
        Invoke-Checked "Service $verb" {
            & $Python $ServiceScript --startup delayed $verb
        }
    }
    finally {
        Pop-Location
    }

    if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        throw "Service $ServiceName is not registered"
    }

    # Start type: Automatic (Delayed Start), so network adapters are up
    Invoke-Checked "Delayed auto start" { sc.exe config $ServiceName start= delayed-auto }

    # Restart on failure: 5 s, 5 s, then every 30 s; counter reset after 1 day
    Invoke-Checked "Recovery actions" {
        sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/30000
    }

    # Also apply recovery when the service stops with an error code
    Invoke-Checked "Recovery on error exit" { sc.exe failureflag $ServiceName 1 }

    # ---------------------------------------------------------
    # 4. Start
    # ---------------------------------------------------------
    Write-Log "[4/4] Starting the service"

    try {
        Start-Service -Name $ServiceName

        if (Wait-ServiceStatus "Running" 30) {
            Write-Log "  Service is running"
        }
        else {
            Write-Log "  WARNING: service did not reach Running within 30 s; see $DataDir\logs\idsips.log"
        }
    }
    catch {
        Write-Log "  WARNING: service could not be started: $($_.Exception.Message)"
    }

    Write-Log "===== Install actions completed ====="
    exit 0
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Log "===== Install actions FAILED ====="
    exit 1
}
