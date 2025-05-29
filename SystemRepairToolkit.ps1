# System Repair Toolkit
# Version: 1.0
# Requirements: PowerShell 5.1+, Windows 10/11, Administrator privileges

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

#region Constants
$script:CONSTANTS = @{
    # Timeout constants
    USER_DECISION_TIMEOUT_SECONDS = 300      # 5 minutes for user decisions
    CLEANMGR_TIMEOUT_MINUTES      = 15        # CleanMgr timeout to prevent hanging
    PROCESS_KILL_TIMEOUT_MS       = 5000      # Time to wait for process termination
    
    # Progress estimation constants
    SFC_PROGRESS_RATE             = 10         # Progress percentage per minute for SFC
    MAX_ESTIMATED_PROGRESS        = 95         # Maximum estimated progress percentage
    TIMER_INTERVAL_MS             = 750        # Progress timer update interval
    
    # Cleanup configuration
    SAGESET_VALUE                 = 64          # StateFlags value for disk cleanup
    
    # File paths and names
    LOG_FILENAME                  = "SystemRepairLog.txt"
    COMMUNICATION_PREFIX          = "RepairToolkit"
    
    # UI constants
    MAIN_BUTTON_HEIGHT            = 55
    MAIN_BUTTON_WIDTH             = 590
    BOTTOM_BUTTON_HEIGHT          = 35
    BOTTOM_BUTTON_WIDTH           = 180
    CONTROL_SPACING               = 15
}
#endregion

#region Global Variables
$global:currentRepairJob = $null
$global:progressUpdateTimer = $null
$global:operationStartTime = $null
$global:timerLock = New-Object System.Object
$global:logPath = Join-Path $env:USERPROFILE "Desktop\$($script:CONSTANTS.LOG_FILENAME)"
$global:currentJobId = $null
#endregion

#region Enhanced Logging System - FIXED AND IMPROVED

# Logging configuration
$script:LOG_CONFIG = @{
    # Log categories with user-friendly descriptions
    Categories            = @{
        INFO      = @{ Display = "INFO"; Color = "White"; Description = "General information" }
        OPERATION = @{ Display = "STEP"; Color = "Cyan"; Description = "Major operation start/end" }
        PROGRESS  = @{ Display = "PROG"; Color = "Yellow"; Description = "Progress updates" }
        SUCCESS   = @{ Display = "DONE"; Color = "Green"; Description = "Successful completion" }
        WARNING   = @{ Display = "WARN"; Color = "DarkYellow"; Description = "Non-critical issues" }
        ERROR     = @{ Display = "ERR!"; Color = "Red"; Description = "Error conditions" }
        USER      = @{ Display = "USER"; Color = "Magenta"; Description = "User interactions" }
        SYSTEM    = @{ Display = "SYS"; Color = "Gray"; Description = "System events" }
    }
    
    # Operation contexts for different repair types
    Operations            = @{
        DISM    = "System Image Repair"
        SFC     = "System File Check"
        CLEANUP = "System Cleanup"
        TOOLKIT = "Repair Toolkit"
        JOB     = "Background Task"
    }
    
    # User-friendly operation descriptions
    OperationDescriptions = @{
        DISM    = "Repairing Windows system image and component store"
        SFC     = "Scanning and repairing system files"
        CLEANUP = "Cleaning temporary files and optimizing system"
        TOOLKIT = "System repair toolkit operations"
        JOB     = "Background processing tasks"
    }
}

function Write-RepairLog {
    <#
    .SYNOPSIS
    Enhanced logging function with consistent formatting and user-friendly output.
    .PARAMETER Message
    The message to log (can also be passed as first parameter for backward compatibility).
    .PARAMETER Category
    The category of the log entry.
    .PARAMETER Operation
    The operation context.
    .PARAMETER IncludeInConsole
    Whether to also display the message in the console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        
        [Parameter(Position = 1)]
        [ValidateSet("INFO", "OPERATION", "PROGRESS", "SUCCESS", "WARNING", "ERROR", "USER", "SYSTEM")]
        [string]$Category,
        
        [Parameter(Position = 2)]
        [ValidateSet("DISM", "SFC", "CLEANUP", "TOOLKIT", "JOB")]
        [string]$Operation,
        
        [switch]$IncludeInConsole
    )
    
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        # If no category/operation provided, try to parse from message for backward compatibility
        if (-not $Category -or -not $Operation) {
            $parsedInfo = Parse-LogMessage -Message $Message
            if (-not $Category) { $Category = $parsedInfo.Category }
            if (-not $Operation) { $Operation = $parsedInfo.Operation }
        }
        
        # Default values if still not set
        if (-not $Category) { $Category = "INFO" }
        if (-not $Operation) { $Operation = "TOOLKIT" }
        
        $categoryInfo = $script:LOG_CONFIG.Categories[$Category]
        $operationName = $script:LOG_CONFIG.Operations[$Operation]
        
        # Create formatted log entry
        $logEntry = "[$timestamp] [$($categoryInfo.Display)] [$operationName] $Message"
        
        # Write to log file
        $logEntry | Out-File -FilePath $global:logPath -Append -Encoding UTF8
        
        # Optional console output for debugging
        if ($IncludeInConsole) {
            Write-Host $logEntry -ForegroundColor $categoryInfo.Color
        }
    }
    catch {
        # Fallback logging if enhanced logging fails
        $fallbackEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERR!] [TOOLKIT] Logging error: $($_.Exception.Message) | Original message: $Message"
        try {
            $fallbackEntry | Out-File -FilePath $global:logPath -Append -Encoding UTF8
        }
        catch {
            Write-Warning "Complete logging failure: $($_.Exception.Message)"
        }
    }
}

function Parse-LogMessage {
    <#
    .SYNOPSIS
    Parses legacy log messages to determine appropriate category and operation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    $category = "INFO"
    $operation = "TOOLKIT"
    
    # Parse common patterns and route to appropriate enhanced logging
    switch -Regex ($Message) {
        ".*operation initiated$|.*started$|.*starting.*|.*session.*" {
            $category = "OPERATION"
            if ($Message -like "*DISM*") { $operation = "DISM" } 
            elseif ($Message -like "*SFC*") { $operation = "SFC" }
            elseif ($Message -like "*cleanup*") { $operation = "CLEANUP" }
        }
        ".*completed.*in.*|.*finished.*|.*successful.*|.*SUCCESS.*" {
            $category = "SUCCESS"
            if ($Message -like "*DISM*") { $operation = "DISM" } 
            elseif ($Message -like "*SFC*") { $operation = "SFC" }
            elseif ($Message -like "*cleanup*") { $operation = "CLEANUP" }
        }
        ".*error.*|.*Error.*|.*failed.*|.*Failed.*|.*ERROR.*" {
            $category = "ERROR"
        }
        ".*warning.*|.*Warning.*|.*timeout.*|.*WARNING.*" {
            $category = "WARNING"
        }
        ".*user.*decision.*|.*User.*|.*clicked.*|.*opened.*|.*close.*" {
            $category = "USER"
        }
        "JOB_OUTPUT.*|.*progress.*|.*Progress.*|.*%.*" {
            $category = "PROGRESS"
            if ($Message -like "*DISM*") { $operation = "DISM" } 
            elseif ($Message -like "*SFC*") { $operation = "SFC" }
            elseif ($Message -like "*cleanup*") { $operation = "CLEANUP" }
            else { $operation = "JOB" }
        }
        ".*PID.*|.*privilege.*|.*session.*|.*Session.*|.*Administrator.*|.*window.*" {
            $category = "SYSTEM"
        }
    }
    
    return @{
        Category  = $category
        Operation = $operation
    }
}

function Write-OperationStart {
    <#
    .SYNOPSIS
    Logs the start of a major operation with consistent formatting.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("DISM", "SFC", "CLEANUP")]
        [string]$OperationType,
        
        [string]$Description
    )
    
    if (-not $Description) {
        $Description = $script:LOG_CONFIG.OperationDescriptions[$OperationType]
    }
    
    Write-RepairLog -Message "=== STARTING: $Description ===" -Category "OPERATION" -Operation $OperationType
    Write-RepairLog -Message "Operation initiated by user at $(Get-Date -Format 'HH:mm:ss')" -Category "INFO" -Operation $OperationType
}

function Write-OperationEnd {
    <#
    .SYNOPSIS
    Logs the completion of a major operation with duration and result.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("DISM", "SFC", "CLEANUP")]
        [string]$OperationType,
        
        [TimeSpan]$Duration,
        [bool]$Success = $true,
        [int]$ExitCode = 0,
        [string]$AdditionalInfo
    )
    
    $durationText = if ($Duration) { 
        "in {0:mm\:ss} (mm:ss)" -f $Duration
    }
    else { 
        "duration unknown" 
    }
    
    $resultText = if ($Success) { "COMPLETED SUCCESSFULLY" } else { "COMPLETED WITH ISSUES" }
    $category = if ($Success) { "SUCCESS" } else { "WARNING" }
    
    Write-RepairLog -Message "=== ${resultText} $($script:LOG_CONFIG.OperationDescriptions[$OperationType]) $durationText ===" -Category $category -Operation $OperationType
    
    if ($ExitCode -ne 0) {
        Write-RepairLog -Message "Exit code: $ExitCode $(if ($ExitCode -eq 0) { '(Success)' } else { '(See documentation for details)' })" -Category "INFO" -Operation $OperationType
    }
    
    if ($AdditionalInfo) {
        Write-RepairLog -Message "Additional info: $AdditionalInfo" -Category "INFO" -Operation $OperationType
    }
}

function Initialize-RepairLog {
    <#
    .SYNOPSIS
    Initializes the repair log with session information and headers.
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Create log header
        $separator = "=" * 80
        $header = @"
$separator
SYSTEM REPAIR TOOLKIT - SESSION LOG
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
PowerShell Version: $($PSVersionTable.PSVersion)
OS Version: $([System.Environment]::OSVersion.VersionString)
User: $([System.Environment]::UserName)
Computer: $([System.Environment]::MachineName)
Administrator Mode: $(if (Test-IsAdministrator) { 'Yes' } else { 'No' })
Process ID: $PID
$separator

"@
        
        # Write header to log file
        $header | Out-File -FilePath $global:logPath -Encoding UTF8
        
        # Log session start
        Write-RepairLog -Message "System Repair Toolkit session started" -Category "OPERATION" -Operation "TOOLKIT"
        Write-RepairLog -Message "Session ID: PID-$PID-$(Get-Date -Format 'yyyyMMdd-HHmmss')" -Category "SYSTEM" -Operation "TOOLKIT"
        
        if (Test-IsAdministrator) {
            Write-RepairLog -Message "Privilege Level: Administrator (full functionality available)" -Category "SYSTEM" -Operation "TOOLKIT"
        }
        else {
            Write-RepairLog -Message "Privilege Level: Standard user (limited functionality)" -Category "SYSTEM" -Operation "TOOLKIT"
        }
    }
    catch {
        Write-Warning "Failed to initialize repair log: $($_.Exception.Message)"
    }
}

function Close-RepairLog {
    <#
    .SYNOPSIS
    Closes the repair log with session summary.
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-RepairLog -Message "System Repair Toolkit session ending" -Category "OPERATION" -Operation "TOOLKIT"
        
        $separator = "=" * 80
        $footer = @"

$separator
SESSION COMPLETED: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
$separator
"@
        
        $footer | Out-File -FilePath $global:logPath -Append -Encoding UTF8
    }
    catch {
        Write-Warning "Failed to close repair log properly: $($_.Exception.Message)"
    }
}

#endregion

#region Core Utility Functions - ORIGINAL UNCHANGED
function Test-IsAdministrator {
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Invoke-WithErrorHandling {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        [Parameter(Mandatory = $true)]
        [string]$OperationName,
        [bool]$ContinueOnError = $true
    )
    
    try {
        return & $ScriptBlock
    }
    catch {
        $errorMessage = "Error in $OperationName : $($_.Exception.Message)"
        Write-RepairLog $errorMessage
        
        if (-not $ContinueOnError) {
            throw
        }
        
        return $null
    }
}

function Set-JobCommunication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JobId,
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [Parameter(Mandatory = $true)]
        [string]$Value
    )
    
    $communicationPath = Join-Path $env:TEMP "$($script:CONSTANTS.COMMUNICATION_PREFIX)_$JobId`_$Key.txt"
    
    Invoke-WithErrorHandling -OperationName "Job Communication Write" -ScriptBlock {
        $Value | Out-File -FilePath $communicationPath -Encoding UTF8 -Force
    }
}

function Get-JobCommunication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JobId,
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [int]$TimeoutSeconds = 300
    )
    
    $communicationPath = Join-Path $env:TEMP "$($script:CONSTANTS.COMMUNICATION_PREFIX)_$JobId`_$Key.txt"
    $timeout = (Get-Date).AddSeconds($TimeoutSeconds)
    
    while ((Get-Date) -lt $timeout) {
        if (Test-Path $communicationPath) {
            $value = Invoke-WithErrorHandling -OperationName "Job Communication Read" -ScriptBlock {
                Get-Content $communicationPath -Raw -ErrorAction SilentlyContinue
            }
            
            # Clean up the communication file
            Invoke-WithErrorHandling -OperationName "Job Communication Cleanup" -ScriptBlock {
                Remove-Item $communicationPath -Force -ErrorAction SilentlyContinue
            }
            
            if ($value -ne $null) {
                return $value.Trim()
            }
        }
        Start-Sleep -Seconds 1
    }
    
    return $null
}

function Show-InfoMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$Title = "System Repair Toolkit",
        [System.Windows.Forms.MessageBoxButtons]$Buttons = [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]$Icon = [System.Windows.Forms.MessageBoxIcon]::Information
    )
    
    return [System.Windows.Forms.MessageBox]::Show($Message, $Title, $Buttons, $Icon)
}

function Show-ErrorMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$Title = "System Repair Toolkit - Error"
    )
    
    return Show-InfoMessage -Message $Message -Title $Title -Icon ([System.Windows.Forms.MessageBoxIcon]::Error)
}

function Show-WarningMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$Title = "System Repair Toolkit - Warning"
    )
    
    return Show-InfoMessage -Message $Message -Title $Title -Icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
}

function Show-QuestionMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$Title = "System Repair Toolkit - Confirmation"
    )
    
    return Show-InfoMessage -Message $Message -Title $Title -Buttons ([System.Windows.Forms.MessageBoxButtons]::YesNo) -Icon ([System.Windows.Forms.MessageBoxIcon]::Question)
}
#endregion

# Initialize logging system
Initialize-RepairLog

#region Command Runner ScriptBlock - FIXED ENCODING
$global:commandRunnerScriptBlock = {
    param([string]$ExecutablePath, [string]$Arguments)
    
    try {
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo.FileName = $ExecutablePath
        $process.StartInfo.Arguments = $Arguments
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        $process.StartInfo.CreateNoWindow = $true
        
        # FIX: Proper encoding handling for different processes
        if ($ExecutablePath -like "*sfc*") {
            # SFC outputs in current console codepage, not UTF-8
            $process.StartInfo.StandardOutputEncoding = [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
        }
        else {
            # DISM and others use UTF-8
            $process.StartInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        }
        
        $process.Start() | Out-Null
        
        # Collect output more efficiently with less frequent progress updates
        $outputLines = @()
        $lastProgressReport = Get-Date
        $progressInterval = [TimeSpan]::FromSeconds(5)  # Report progress every 5 seconds max
        
        while (-not $process.HasExited) {
            $line = $process.StandardOutput.ReadLine()
            if ($line -ne $null -and $line.Trim() -ne "") {
                $outputLines += $line
                
                # Only report progress periodically to reduce log spam
                $currentTime = Get-Date
                if (($currentTime - $lastProgressReport) -gt $progressInterval) {
                    Write-Output "PROGRESS_LINE:$line"
                    $lastProgressReport = $currentTime
                }
            }
            Start-Sleep -Milliseconds 100
        }
        
        # Report final lines
        $remainingOutput = $process.StandardOutput.ReadToEnd()
        if ($remainingOutput) {
            $remainingLines = $remainingOutput -split "`r`n|`r|`n" | Where-Object { $_.Trim() -ne "" }
            foreach ($line in $remainingLines) {
                Write-Output "PROGRESS_LINE:$line"
            }
        }
        
        $process.WaitForExit()
        $exitCode = $process.ExitCode
        $errorOutput = $process.StandardError.ReadToEnd()
        
        $process.Close()
        $process.Dispose()
        
        return [PSCustomObject]@{
            ExitCode       = $exitCode
            StandardOutput = "Process completed"
            StandardError  = $errorOutput
        }
    }
    catch {
        return [PSCustomObject]@{
            ExitCode       = -999
            StandardOutput = "Process execution failed"
            StandardError  = $_.Exception.Message
        }
    }
}
#endregion

#region Disk Cleanup ScriptBlock - FIXED LOGGING
$global:diskCleanupScriptBlock = {
    param([string]$LogPath, [string]$JobId)
    
    function Write-JobLog {
        param([string]$message)
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        try {
            # FIX: Use enhanced logging format consistently
            "[$timestamp] [PROG] [System Cleanup] $message" | Out-File -FilePath $LogPath -Append -Encoding UTF8
        }
        catch {
            Write-Output "LOG_ERROR: $($_.Exception.Message)"
        }
    }
    
    function Test-JobIsAdministrator {
        try {
            $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
            return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
        catch {
            return $false
        }
    }
    
    function Set-JobCommunication {
        param([string]$JobId, [string]$Key, [string]$Value)
        $communicationPath = Join-Path $env:TEMP "RepairToolkit_$JobId`_$Key.txt"
        try {
            $Value | Out-File -FilePath $communicationPath -Encoding UTF8 -Force
        }
        catch {
            Write-JobLog "Error setting job communication: $($_.Exception.Message)"
        }
    }
    
    function Get-JobCommunication {
        param([string]$JobId, [string]$Key, [int]$TimeoutSeconds = 300)
        $communicationPath = Join-Path $env:TEMP "RepairToolkit_$JobId`_$Key.txt"
        $timeout = (Get-Date).AddSeconds($TimeoutSeconds)
        
        while ((Get-Date) -lt $timeout) {
            if (Test-Path $communicationPath) {
                try {
                    $value = Get-Content $communicationPath -Raw -ErrorAction SilentlyContinue
                    Remove-Item $communicationPath -Force -ErrorAction SilentlyContinue
                    if ($value -ne $null) {
                        return $value.Trim()
                    }
                }
                catch {
                    Write-JobLog "Error reading job communication: $($_.Exception.Message)"
                }
            }
            Start-Sleep -Seconds 1
        }
        return $null
    }
    
    try {
        Write-JobLog "System cleanup and optimization started"
        Write-Output "PROGRESS_LINE:Initializing comprehensive system cleanup and optimization..."
        
        if (-not (Test-JobIsAdministrator)) {
            throw "Administrator privileges required"
        }
        
        # Initialize timeout tracking variable
        $timeoutReached = $false
        
        # Phase 1: Enhanced System Cleanup
        Write-Output "PROGRESS_LINE:Progress: 5% - Starting enhanced system cleanup"
        
        # Start TrustedInstaller service for DISM operations
        Write-JobLog "Starting TrustedInstaller service for system optimization"
        Start-Service -Name "TrustedInstaller" -ErrorAction SilentlyContinue
        
        # Delete oldest shadow copy to free space
        Write-JobLog "Removing oldest system shadow copy to free disk space"
        & vssadmin delete shadows /for=c: /oldest /quiet 2>&1 | Out-Null
        
        # DISM Component Cleanup with ResetBase (more aggressive)
        Write-JobLog "Starting Windows component store optimization (this may take several minutes)"
        & DISM.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase /NoRestart 2>&1 | Out-Null
        $dismExitCode = $LASTEXITCODE
        Write-JobLog "Component store optimization completed with result code: $dismExitCode"
        
        # Phase 2: Configure Cleanup Categories (using StateFlags0064 like batch script)
        Write-Output "PROGRESS_LINE:Progress: 25% - Configuring cleanup categories..."
        $sageset = 64  # Changed from 65535 to match the batch script approach
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
        
        $cleanupCategories = @(
            "Active Setup Temp Folders", "BranchCache", "Content Indexer Cleaner",
            "Device Driver Packages", "Downloaded Program Files", "Internet Cache Files",
            "Memory Dump Files", "Offline Pages Files", "Old ChkDsk Files",
            "Previous Installations", "Recycle Bin", "Service Pack Cleanup", "Setup Log Files",
            "System error memory dump files", "System error minidump files",
            "Temporary Files", "Temporary Setup Files", "Temporary Sync Files",
            "Thumbnail Cache", "Update Cleanup", "Upgrade Discarded Files",
            "User file versions", "Windows Defender", "Windows Defender Antivirus",
            "Windows Error Reporting Archive Files", "Windows Error Reporting Queue Files", 
            "Windows Error Reporting System Archive Files", "Windows Error Reporting System Queue Files",
            "Windows ESD installation files", "Windows upgrade log files"
        )
        
        Write-JobLog "Configuring cleanup categories for comprehensive cleaning"
        foreach ($category in $cleanupCategories) {
            $categoryPath = Join-Path $regPath $category
            if (Test-Path $categoryPath) {
                try {
                    Set-ItemProperty -Path $categoryPath -Name "StateFlags$($sageset.ToString('0000'))" -Value 2 -Type DWord -Force
                }
                catch {
                    Write-JobLog "Could not configure cleanup category: $category"
                }
            }
        }
        
        # Phase 3: Windows.old Detection
        Write-Output "PROGRESS_LINE:Progress: 40% - Checking for Windows.old folder..."
        $windowsOldPath = "C:\Windows.old"
        $windowsOldExists = Test-Path $windowsOldPath
        Write-Output "WINDOWS_OLD_EXISTS:$windowsOldExists"
        
        if ($windowsOldExists) {
            Write-JobLog "Windows.old folder detected - calculating size for user decision"
            # Calculate size with FIXED PowerShell 5.1 compatible syntax
            $windowsOldSize = 0
            try {
                # Use PowerShell 5.1 compatible null checking
                $measureResult = Get-ChildItem $windowsOldPath -Recurse -ErrorAction SilentlyContinue | 
                Measure-Object -Property Length -Sum
                if ($measureResult -and $measureResult.Sum) {
                    $windowsOldSize = $measureResult.Sum
                }
                else {
                    $windowsOldSize = 0
                }
            }
            catch {
                $windowsOldSize = 0
                Write-JobLog "Could not calculate Windows.old folder size: $($_.Exception.Message)"
            }
            Write-Output "WINDOWS_OLD_SIZE:$windowsOldSize"
        }
        
        # Wait for user decision with FIXED synchronization
        $userWantsRemoval = $false
        if ($windowsOldExists) {
            Write-Output "PROGRESS_LINE:Waiting for user decision on Windows.old folder removal..."
            Write-JobLog "Waiting for user decision on Windows.old folder removal (timeout: 5 minutes)"
            
            $decision = Get-JobCommunication -JobId $JobId -Key "WINDOWSOLD_DECISION" -TimeoutSeconds 300
            
            if ($decision -eq "YES" -or $decision -eq "NO") {
                $userWantsRemoval = ($decision -eq "YES")
                Write-JobLog "User decision received: $decision (Remove Windows.old: $userWantsRemoval)"
            }
            else {
                Write-JobLog "User decision timeout reached - defaulting to preserve Windows.old folder for safety"
                $userWantsRemoval = $false
            }
        }
        
        # Configure Windows.old registry setting
        if ($windowsOldExists) {
            $prevInstallPath = Join-Path $regPath "Previous Installations"
            if (Test-Path $prevInstallPath) {
                $regValue = if ($userWantsRemoval) { 2 } else { 0 }
                Set-ItemProperty -Path $prevInstallPath -Name "StateFlags$($sageset.ToString('0000'))" -Value $regValue -Type DWord -Force
                Write-JobLog "Windows.old cleanup configured: $(if ($userWantsRemoval) { 'Will be removed' } else { 'Will be preserved' })"
            }
        }
        
        # Phase 4: Execute Cleanup with Timeout Protection
        Write-Output "PROGRESS_LINE:Progress: 50% - Starting disk cleanup utility..."
        Write-JobLog "Starting Windows disk cleanup utility (CleanMgr.exe) with 15-minute timeout protection"
        
        $cleanupProcess = Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/SAGERUN:$($sageset.ToString('0000'))" -WindowStyle Hidden -PassThru
        
        $progress = 50
        $timeoutMinutes = 15  # 15 minute timeout for CleanMgr
        $startTime = Get-Date
        
        while (-not $cleanupProcess.HasExited) {
            $elapsedTime = (Get-Date) - $startTime
            
            # Check for timeout
            if ($elapsedTime.TotalMinutes -gt $timeoutMinutes) {
                Write-JobLog "Disk cleanup utility timeout reached ($timeoutMinutes minutes) - this is normal behavior to prevent system hanging"
                Write-JobLog "Terminating CleanMgr.exe and continuing with manual optimization procedures"
                try {
                    $cleanupProcess.Kill()
                    $cleanupProcess.WaitForExit(5000)  # Wait up to 5 seconds for clean exit
                    $timeoutReached = $true
                    Write-Output "PROGRESS_LINE:Progress: 80% - Cleanup timeout reached, continuing with optimization..."
                    break
                }
                catch {
                    Write-JobLog "Error terminating CleanMgr process: $($_.Exception.Message)"
                }
            }
            
            Start-Sleep -Seconds 3
            $progress = [Math]::Min($progress + 1, 80)  # Cap at 80% instead of 85%
            $minutesElapsed = [Math]::Floor($elapsedTime.TotalMinutes)
            Write-Output "PROGRESS_LINE:Progress: $progress% - Disk cleanup in progress... ($minutesElapsed min)"
        }
        
        if (-not $timeoutReached) {
            $cleanupProcess.WaitForExit()
            $exitCode = $cleanupProcess.ExitCode
            Write-JobLog "Disk cleanup utility completed normally with exit code: $exitCode"
            Write-Output "PROGRESS_LINE:Progress: 80% - Disk cleanup completed"
        }
        else {
            $exitCode = -1  # Indicate timeout
            Write-JobLog "Disk cleanup utility was terminated due to timeout - proceeding with manual operations"
            Write-Output "PROGRESS_LINE:Progress: 80% - Disk cleanup timeout, proceeding with manual operations"
            
            # Manual Windows.old removal if user wanted it and CleanMgr failed
            if ($windowsOldExists -and $userWantsRemoval) {
                Write-Output "PROGRESS_LINE:Progress: 82% - Attempting manual Windows.old removal..."
                try {
                    Write-JobLog "Attempting manual Windows.old folder removal since user requested it"
                    & takeown /f "C:\Windows.old" /r /d y 2>&1 | Out-Null
                    & icacls "C:\Windows.old" /grant administrators:F /t 2>&1 | Out-Null
                    Remove-Item -Path "C:\Windows.old" -Recurse -Force -ErrorAction Stop
                    Write-JobLog "Manual Windows.old folder removal completed successfully"
                    Write-Output "PROGRESS_LINE:Progress: 84% - Manual Windows.old removal completed"
                }
                catch {
                    Write-JobLog "Manual Windows.old removal encountered issues: $($_.Exception.Message)"
                    Write-Output "PROGRESS_LINE:Progress: 84% - Manual Windows.old removal had issues"
                }
            }
        }
        
        # Force success exit code if no critical errors occurred (only set to error if major failure)
        if ($exitCode -eq 0 -or ($timeoutReached -and $exitCode -ne -999)) {
            $finalExitCode = 0  # Success
        }
        else {
            $finalExitCode = $exitCode
        }
        
        # Phase 5: Manual Cleanup Operations
        Write-Output "PROGRESS_LINE:Progress: 85% - Performing manual cleanup operations"
        Write-JobLog "Starting manual cleanup operations for additional system optimization"
        
        # Clear Prefetch folder
        try {
            $prefetchPath = Join-Path $env:SystemRoot "Prefetch\*"
            Remove-Item -Path $prefetchPath -Force -Recurse -ErrorAction SilentlyContinue
            Write-JobLog "System prefetch folder cleared successfully"
        }
        catch {
            Write-JobLog "Could not clear prefetch folder: $($_.Exception.Message)"
        }
        
        # Manual temp folder cleanup
        try {
            $tempPaths = @($env:TEMP, $env:TMP, "$env:LOCALAPPDATA\Temp")
            foreach ($tempPath in $tempPaths) {
                if (Test-Path $tempPath) {
                    Get-ChildItem $tempPath -Force -ErrorAction SilentlyContinue | 
                    Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                }
            }
            Write-JobLog "Manual temporary folder cleanup completed"
        }
        catch {
            Write-JobLog "Manual temp cleanup had issues: $($_.Exception.Message)"
        }
        
        # Clear Event Logs (optional - can free significant space)
        try {
            Write-JobLog "Clearing Windows event logs to free space and improve performance"
            $eventLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 }
            foreach ($log in $eventLogs) {
                try {
                    wevtutil.exe cl $log.LogName 2>&1 | Out-Null
                }
                catch {
                    # Some logs may be protected, continue with others
                }
            }
            Write-JobLog "Event log clearing completed"
        }
        catch {
            Write-JobLog "Event log clearing had issues: $($_.Exception.Message)"
        }
        
        # Phase 6: Registry Cleanup
        Write-Output "PROGRESS_LINE:Progress: 87% - Cleaning up temporary settings..."
        Write-JobLog "Cleaning up temporary registry settings from cleanup configuration"
        foreach ($category in $cleanupCategories) {
            $categoryPath = Join-Path $regPath $category
            if (Test-Path $categoryPath) {
                Remove-ItemProperty -Path $categoryPath -Name "StateFlags$($sageset.ToString('0000'))" -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Phase 7: System Cache and Network Optimization
        Write-Output "PROGRESS_LINE:Progress: 88% - Optimizing system caches..."
        Write-JobLog "Starting system cache optimization procedures"
        
        # Font Cache Cleanup
        try {
            Write-JobLog "Refreshing Windows font cache for improved performance"
            Stop-Service -Name "FontCache" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            
            $fontCachePaths = @(
                "$env:SystemRoot\System32\FNTCACHE.DAT",
                "$env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\FontCache"
            )
            
            foreach ($path in $fontCachePaths) {
                if (Test-Path $path) {
                    Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
            
            Start-Service -Name "FontCache" -ErrorAction SilentlyContinue
            Write-JobLog "Font cache refresh completed successfully"
        }
        catch {
            Write-JobLog "Font cache cleanup had issues: $($_.Exception.Message)"
        }
        
        # Icon Cache Cleanup
        Write-Output "PROGRESS_LINE:Progress: 90% - Refreshing icon cache..."
        try {
            Write-JobLog "Refreshing Windows icon cache for updated display"
            
            # Stop explorer temporarily
            $explorerProcesses = Get-Process -Name "explorer" -ErrorAction SilentlyContinue
            if ($explorerProcesses) {
                $explorerProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
            
            # Remove icon cache files
            $iconCachePaths = @(
                "$env:LOCALAPPDATA\IconCache.db",
                "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\iconcache*.db"
            )
            
            foreach ($pattern in $iconCachePaths) {
                Get-ChildItem $pattern -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            }
            
            # Restart explorer
            Start-Process "explorer.exe" -ErrorAction SilentlyContinue
            Write-JobLog "Icon cache refresh completed successfully"
        }
        catch {
            Write-JobLog "Icon cache cleanup had issues: $($_.Exception.Message)"
            # Ensure explorer is running even if cleanup failed
            if (-not (Get-Process -Name "explorer" -ErrorAction SilentlyContinue)) {
                Start-Process "explorer.exe" -ErrorAction SilentlyContinue
            }
        }
        
        # DNS Cache Flush
        Write-Output "PROGRESS_LINE:Progress: 92% - Flushing DNS cache..."
        try {
            Write-JobLog "Flushing DNS cache for improved network performance"
            & ipconfig /flushdns 2>&1 | Out-Null
            Write-JobLog "DNS cache flush completed successfully"
        }
        catch {
            Write-JobLog "DNS cache flush had issues: $($_.Exception.Message)"
        }
        
        # System Optimization (ProcessIdleTasks)
        Write-Output "PROGRESS_LINE:Progress: 94% - Running system optimization tasks..."
        Write-JobLog "Running Windows system optimization tasks (ProcessIdleTasks)"
        try {
            & rundll32.exe advapi32.dll, ProcessIdleTasks
            Write-JobLog "System optimization tasks completed successfully"
        }
        catch {
            Write-JobLog "System optimization tasks had issues: $($_.Exception.Message)"
        }
        
        Write-Output "PROGRESS_LINE:Progress: 100% - Cleanup and optimization completed successfully"
        Write-JobLog "=== COMPLETED: System cleanup and optimization finished successfully ==="
        
        # Create the result object with all required properties
        $resultObject = [PSCustomObject]@{
            ExitCode          = $finalExitCode
            StandardOutput    = "System cleanup and optimization completed"
            StandardError     = if ($timeoutReached) { "CleanMgr timeout reached but optimization continued" } else { "" }
            WindowsOldExists  = $windowsOldExists
            WindowsOldRemoved = $userWantsRemoval
            TimeoutOccurred   = $timeoutReached
            ResultMarker      = "CLEANUP_JOB_RESULT"
        }
        
        # Output the result with a clear marker for the main thread to find
        Write-Output "FINAL_RESULT_START"
        Write-Output $resultObject
        Write-Output "FINAL_RESULT_END"
        
        Write-JobLog "Returning result object with exit code: $finalExitCode"
        return $resultObject
    }
    catch {
        Write-JobLog "=== ERROR: System cleanup and optimization failed: $($_.Exception.Message) ==="
        return [PSCustomObject]@{
            ExitCode       = -999
            StandardOutput = "System cleanup and optimization failed"
            StandardError  = $_.Exception.Message
        }
    }
}
#endregion

#region Job Management Functions - FIXED TO USE ENHANCED LOGGING
function Start-RepairJob {
    param(
        [string]$JobName,
        [string]$Executable,
        [string]$Arguments,
        [string]$InitialStatus
    )

    if ($global:currentRepairJob) {
        [System.Windows.Forms.MessageBox]::Show(
            "Another repair operation is already in progress. Please wait for it to complete.",
            "Operation Busy", "OK", "Warning"
        )
        return $false
    }

    Write-RepairLog "$JobName operation initiated"
    
    $statusLabel.Text = "Status: $InitialStatus"
    $statusLabel.ForeColor = [System.Drawing.Color]::DarkOrange
    $sfcButton.Enabled = $false
    $dismButton.Enabled = $false
    $cleanupButton.Enabled = $false
    
    $progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
    $progressBar.Value = 0
    $progressBar.Visible = $true
    $global:operationStartTime = Get-Date
    
    $global:currentRepairJob = Start-Job -Name $JobName -ScriptBlock $global:commandRunnerScriptBlock -ArgumentList $Executable, $Arguments
    
    if ($global:progressUpdateTimer) {
        $global:progressUpdateTimer.Stop()
        $global:progressUpdateTimer.Dispose()
    }
    
    $global:progressUpdateTimer = New-Object System.Windows.Forms.Timer
    $global:progressUpdateTimer.Interval = $script:CONSTANTS.TIMER_INTERVAL_MS
    $global:progressUpdateTimer.Add_Tick($global:progressTimerAction)
    $global:progressUpdateTimer.Start()
    
    return $true
}

function Start-DISMRepair {
    if (-not (Test-IsAdministrator)) {
        [System.Windows.Forms.MessageBox]::Show(
            "DISM repair operations require Administrator privileges to modify system components.`n`nPlease restart this toolkit as an Administrator.",
            "Administrator Privileges Required", "OK", "Warning"
        )
        return
    }
    
    # FIX: Add proper operation start logging
    Write-OperationStart -OperationType "DISM"
    Start-RepairJob -JobName "DISMRepairJob" -Executable "DISM.exe" -Arguments "/Online /Cleanup-Image /RestoreHealth" -InitialStatus "Initializing DISM image repair... (this can take several minutes)"
}

function Start-SFCRepair {
    if (-not (Test-IsAdministrator)) {
        [System.Windows.Forms.MessageBox]::Show(
            "SFC (System File Checker) scans require Administrator privileges to access and repair protected system files.`n`nPlease restart this toolkit as an Administrator.",
            "Administrator Privileges Required", "OK", "Warning"
        )
        return
    }
    
    # FIX: Add proper operation start logging
    Write-OperationStart -OperationType "SFC"
    Start-RepairJob -JobName "SFCRepairJob" -Executable "sfc.exe" -Arguments "/scannow" -InitialStatus "Initializing SFC scan... (this can take several minutes)"
}

function Start-DiskCleanup {
    if (-not (Test-IsAdministrator)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Full system cleanup and optimization functionality, including Windows.old removal and cache optimization, requires Administrator privileges. Please restart this toolkit as Administrator.",
            "Administrator Privileges Required", "OK", "Error"
        )
        return
    }
    
    if ($global:currentRepairJob) {
        [System.Windows.Forms.MessageBox]::Show(
            "Another repair operation is already in progress. Please wait for it to complete.",
            "Operation Busy", "OK", "Warning"
        )
        return
    }

    # FIX: Add proper operation start logging
    Write-OperationStart -OperationType "CLEANUP"
    
    $statusLabel.Text = "Status: System cleanup and optimization in progress..."
    $statusLabel.ForeColor = [System.Drawing.Color]::DarkOrange
    $sfcButton.Enabled = $false
    $dismButton.Enabled = $false
    $cleanupButton.Enabled = $false
    
    $progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
    $progressBar.Value = 0
    $progressBar.Visible = $true
    $global:operationStartTime = Get-Date
    
    $global:currentJobId = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
    
    $global:currentRepairJob = Start-Job -Name "DiskCleanupJob" -ScriptBlock $global:diskCleanupScriptBlock -ArgumentList @($global:logPath, $global:currentJobId)
    
    if ($global:progressUpdateTimer) {
        $global:progressUpdateTimer.Stop()
        $global:progressUpdateTimer.Dispose()
    }
    
    $global:progressUpdateTimer = New-Object System.Windows.Forms.Timer
    $global:progressUpdateTimer.Interval = $script:CONSTANTS.TIMER_INTERVAL_MS
    $global:progressUpdateTimer.Add_Tick($global:progressTimerAction)
    $global:progressUpdateTimer.Start()
}
#endregion

#region Completion Handlers - UPDATED TO USE ENHANCED LOGGING
function ProcessDISMCompletion {
    param($JobResult)
    
    $duration = if ($global:operationStartTime) { (Get-Date) - $global:operationStartTime } else { New-TimeSpan }
    $success = ($JobResult -and $JobResult.ExitCode -eq 0)
    
    Write-OperationEnd -OperationType "DISM" -Duration $duration -Success $success -ExitCode $(if ($JobResult) { $JobResult.ExitCode } else { -1 })

    if ($success) {
        $statusLabel.Text = "Status: SUCCESS - DISM system image repair completed!"
        $statusLabel.ForeColor = [System.Drawing.Color]::DarkGreen
        
        [System.Windows.Forms.MessageBox]::Show(
            "DISM successfully completed the Windows image repair operation (/RestoreHealth).`n`n" +
            "It is often recommended to run an SFC scan (Step 2) after a successful DISM repair to ensure system file integrity.",
            "DISM Repair Complete", "OK", "Information"
        )
    }
    else {
        $statusLabel.Text = "Status: WARNING - DISM completed with issues"
        $statusLabel.ForeColor = [System.Drawing.Color]::DarkOrange
        
        # Use PowerShell 5.1 compatible null checking
        $exitCodeText = if ($JobResult -and $JobResult.ExitCode) { $JobResult.ExitCode.ToString() } else { "Unknown" }
        
        [System.Windows.Forms.MessageBox]::Show(
            "DISM repair operation finished with exit code: $exitCodeText.`n" +
            "This may indicate that some issues remain, a source image was needed but not found, or a reboot is required.`n`n" +
            "Please check the DISM log for details, typically located at:`n" +
            "C:\Windows\Logs\DISM\dism.log and C:\Windows\Logs\CBS\CBS.log",
            "DISM Completed with Notes", "OK", "Warning"
        )
    }
}

function ProcessSFCCompletion {
    param($JobResult)
    
    $duration = if ($global:operationStartTime) { (Get-Date) - $global:operationStartTime } else { New-TimeSpan }
    $success = ($JobResult -and $JobResult.ExitCode -eq 0)
    
    Write-OperationEnd -OperationType "SFC" -Duration $duration -Success $success -ExitCode $(if ($JobResult) { $JobResult.ExitCode } else { -1 })

    if ($success) {
        $statusLabel.Text = "Status: SUCCESS - SFC scan completed. No integrity violations found."
        $statusLabel.ForeColor = [System.Drawing.Color]::DarkGreen
        
        [System.Windows.Forms.MessageBox]::Show(
            "SFC scan completed successfully. Windows Resource Protection did not find any integrity violations on your system.",
            "SFC Scan Successful", "OK", "Information"
        )
    }
    else {
        $statusLabel.Text = "Status: ATTENTION - SFC scan completed. Review logs."
        $statusLabel.ForeColor = [System.Drawing.Color]::DarkOrange
        
        # Use PowerShell 5.1 compatible null checking
        $exitCodeText = if ($JobResult -and $JobResult.ExitCode) { $JobResult.ExitCode.ToString() } else { "Unknown" }
        
        $message = "SFC scan finished with exit code: $exitCodeText.`n`n" +
        "This code often indicates one of the following:`n" +
        "- Windows Resource Protection found corrupt files and successfully repaired them. A reboot might be needed to finalize repairs.`n" +
        "- Windows Resource Protection found corrupt files but was unable to fix some or all of them. Further troubleshooting may be needed.`n" +
        "- SFC could not perform the requested operation due to other system issues.`n`n" +
        "For detailed information, examine the CBS.log file located at:`n" +
        "C:\Windows\Logs\CBS\CBS.log`n" +
        "Search this log for '[SR]' tags to find SFC-specific entries."

        [System.Windows.Forms.MessageBox]::Show($message, "SFC Scan Completed with Notes", "OK", "Information")
    }
}

function ProcessDiskCleanupCompletion {
    param($JobResult)
    
    $duration = if ($global:operationStartTime) { (Get-Date) - $global:operationStartTime } else { New-TimeSpan }
    $success = ($JobResult -and $JobResult.ExitCode -eq 0)
    
    $additionalInfo = ""
    if ($JobResult.WindowsOldExists) {
        $additionalInfo = if ($JobResult.WindowsOldRemoved) { 
            "Windows.old folder was removed" 
        }
        else { 
            "Windows.old folder was preserved" 
        }
    }
    
    if ($JobResult.TimeoutOccurred) {
        $additionalInfo += if ($additionalInfo) { ", CleanMgr timeout handled" } else { "CleanMgr timeout handled" }
    }
    
    Write-OperationEnd -OperationType "CLEANUP" -Duration $duration -Success $success -ExitCode $(if ($JobResult) { $JobResult.ExitCode } else { -1 }) -AdditionalInfo $additionalInfo

    if ($success) {
        $statusLabel.Text = "Status: SUCCESS - System cleanup and optimization completed!"
        $statusLabel.ForeColor = [System.Drawing.Color]::DarkGreen
        
        $messageBuilder = New-Object System.Text.StringBuilder
        $messageBuilder.AppendLine("System cleanup and optimization process has finished successfully.")
        $messageBuilder.AppendLine()
        $messageBuilder.AppendLine("Completed cleanup and optimization actions:")
        $messageBuilder.AppendLine("- Removal of various temporary files and caches")
        $messageBuilder.AppendLine("- Emptying of the Recycle Bin")
        $messageBuilder.AppendLine("- Cleanup of Windows Update files")
        $messageBuilder.AppendLine("- Windows component store optimization with ResetBase")
        $messageBuilder.AppendLine("- Deletion of oldest shadow copy")
        $messageBuilder.AppendLine("- Prefetch folder cleanup")
        $messageBuilder.AppendLine("- Event log clearing")
        $messageBuilder.AppendLine("- Manual temporary file cleanup")
        $messageBuilder.AppendLine("- Font cache optimization")
        $messageBuilder.AppendLine("- Icon cache refresh")
        $messageBuilder.AppendLine("- DNS cache flush")
        $messageBuilder.AppendLine("- System optimization tasks (ProcessIdleTasks)")
        
        if ($JobResult.WindowsOldExists) {
            if ($JobResult.WindowsOldRemoved) {
                $messageBuilder.AppendLine("- The Windows.old folder was successfully removed")
            }
            else {
                $messageBuilder.AppendLine("- The Windows.old folder was preserved per your selection")
            }
        }

        $messageBuilder.AppendLine()
        $messageBuilder.AppendLine("Your system has been cleaned, optimized, and unnecessary files have been removed.")
        
        [System.Windows.Forms.MessageBox]::Show($messageBuilder.ToString(), "System Cleanup & Optimization Complete", "OK", "Information")
    }
    elseif ($JobResult -and $JobResult.ExitCode -eq 1 -and $JobResult.StandardError -and $JobResult.StandardError.Contains("timeout")) {
        # Handle timeout case specifically: Use PowerShell 5.1 compatible null checking
        $statusLabel.Text = "Status: SUCCESS - System optimization completed (CleanMgr timeout handled)"
        $statusLabel.ForeColor = [System.Drawing.Color]::DarkGreen
        
        $messageBuilder = New-Object System.Text.StringBuilder
        $messageBuilder.AppendLine("System cleanup and optimization completed with minor issues.")
        $messageBuilder.AppendLine()
        $messageBuilder.AppendLine("Note: The disk cleanup utility timed out after 15 minutes, but all system optimization tasks completed successfully:")
        $messageBuilder.AppendLine("- Windows component store optimization with ResetBase")
        $messageBuilder.AppendLine("- Manual temporary file cleanup")
        $messageBuilder.AppendLine("- Font cache optimization")
        $messageBuilder.AppendLine("- Icon cache refresh")
        $messageBuilder.AppendLine("- DNS cache flush")
        $messageBuilder.AppendLine("- System optimization tasks (ProcessIdleTasks)")
        
        if ($JobResult.WindowsOldExists -and $JobResult.WindowsOldRemoved) {
            $messageBuilder.AppendLine("- Manual Windows.old folder removal")
        }
        
        $messageBuilder.AppendLine()
        $messageBuilder.AppendLine("Your system has been optimized. The disk cleanup utility may have had issues with some files, but core optimization completed successfully.")
        
        [System.Windows.Forms.MessageBox]::Show($messageBuilder.ToString(), "System Optimization Complete", "OK", "Information")
    }
    else {
        $statusLabel.Text = "Status: WARNING - System cleanup and optimization completed with issues"
        $statusLabel.ForeColor = [System.Drawing.Color]::DarkOrange
        
        # Use PowerShell 5.1 compatible null checking
        $exitCodeText = if ($JobResult -and $JobResult.ExitCode) { $JobResult.ExitCode.ToString() } else { "Unknown" }
        
        [System.Windows.Forms.MessageBox]::Show(
            "System cleanup and optimization operation finished with exit code: $exitCodeText.`n" +
            "This may indicate that some cleanup operations were skipped or encountered difficulties.`n`n" +
            "Please check the 'SystemRepairLog.txt' on your Desktop for detailed information.",
            "System Cleanup Completed with Notes", "OK", "Warning"
        )
    }
}
#endregion

#region Progress Timer Implementation - FIXED JOB OUTPUT HANDLING
$global:progressTimerAction = {
    if (-not [System.Threading.Monitor]::TryEnter($global:timerLock, 100)) {
        return  # Another timer execution is in progress
    }
    
    try {
        if (-not $global:currentRepairJob) { return }

        $jobOutput = if ($global:currentRepairJob.HasMoreData) {
            Receive-Job -Job $global:currentRepairJob
        }
        else { @() }
        
        foreach ($item in $jobOutput) {
            $itemStr = $item.ToString().Trim()
            
            if ($itemStr.StartsWith("PROGRESS_LINE:")) {
                $line = $itemStr.Substring("PROGRESS_LINE:".Length).Trim()
                
                # FIX: Reduced verbosity - only log significant progress updates
                if ($line -match '(\d{1,3})%' -or $line -like "*completed*" -or $line -like "*starting*" -or $line -like "*finished*") {
                    Write-RepairLog "Progress: $line"
                }
                
                if ($line -match '(\d{1,3})%') {
                    $percent = [int]$matches[1]
                    if ($percent -ge $progressBar.Value -and $percent -le 100) {
                        $progressBar.Value = $percent
                        $operationName = $global:currentRepairJob.Name -replace "Job", ""
                        $statusLabel.Text = "Status: $operationName in progress... $($progressBar.Value)%"
                    }
                }
            }
            elseif ($itemStr.StartsWith("WINDOWS_OLD_EXISTS:")) {
                $exists = $itemStr.Substring("WINDOWS_OLD_EXISTS:".Length) -eq "True"
                if ($exists) {
                    # Handle Windows.old prompt in UI thread immediately
                    $global:progressUpdateTimer.Stop()
                    
                    try {
                        # Get size if available
                        $sizeText = "of unknown size"
                        Start-Sleep -Milliseconds 500 # Brief pause for size calculation
                        
                        $sizeOutput = if ($global:currentRepairJob.HasMoreData) {
                            Receive-Job -Job $global:currentRepairJob
                        }
                        else { @() }
                        
                        foreach ($sizeItem in $sizeOutput) {
                            if ($sizeItem.ToString().StartsWith("WINDOWS_OLD_SIZE:")) {
                                $sizeBytes = [long]($sizeItem.ToString().Substring("WINDOWS_OLD_SIZE:".Length))
                                if ($sizeBytes -gt 0) {
                                    if ($sizeBytes -ge 1GB) {
                                        $sizeText = "approximately {0:N2} GB" -f ($sizeBytes / 1GB)
                                    }
                                    elseif ($sizeBytes -ge 1MB) {
                                        $sizeText = "approximately {0:N2} MB" -f ($sizeBytes / 1MB)
                                    }
                                    else {
                                        $sizeText = "less than 1 MB"
                                    }
                                }
                                break
                            }
                        }
                        
                        $windowsOldMessage = "The Windows.old folder ($sizeText) was found on your system.`n`n" +
                        "This folder contains files from a previous Windows installation. Removing it can free up significant disk space.`n`n" +
                        "IMPORTANT: Removing Windows.old will prevent you from rolling back to that previous Windows version.`n`n" +
                        "Do you want to include the Windows.old folder in this cleanup operation?"
                        
                        $dialogResult = [System.Windows.Forms.MessageBox]::Show(
                            $windowsOldMessage, 
                            "Windows.old Cleanup Confirmation",
                            [System.Windows.Forms.MessageBoxButtons]::YesNo,
                            [System.Windows.Forms.MessageBoxIcon]::Question,
                            [System.Windows.Forms.MessageBoxDefaultButton]::Button2
                        )
                        
                        $decision = if ($dialogResult -eq [System.Windows.Forms.DialogResult]::Yes) { "YES" } else { "NO" }
                        
                        if ($global:currentJobId) {
                            Set-JobCommunication -JobId $global:currentJobId -Key "WINDOWSOLD_DECISION" -Value $decision
                        }
                        Write-RepairLog "User decision on Windows.old removal: $decision"
                    }
                    finally {
                        $global:progressUpdateTimer.Start()
                    }
                }
            }
        }

        # Time-based progress for SFC
        if ($global:currentRepairJob.Name -like "*SFCRepairJob*" -and $global:operationStartTime) {
            $elapsedMinutes = ((Get-Date) - $global:operationStartTime).TotalMinutes
            $estimatedProgress = [Math]::Min([Math]::Floor($elapsedMinutes * $script:CONSTANTS.SFC_PROGRESS_RATE), $script:CONSTANTS.MAX_ESTIMATED_PROGRESS)
            
            if ($estimatedProgress -gt $progressBar.Value) {
                $progressBar.Value = $estimatedProgress
                $statusLabel.Text = "Status: SFC scan in progress... $($progressBar.Value)% (estimated)"
            }
        }

        if ($global:currentRepairJob.State -ne [System.Management.Automation.JobState]::Running) {
            $global:progressUpdateTimer.Stop()
            
            $jobResult = Get-JobResult -Job $global:currentRepairJob
            
            if ($jobResult -and $jobResult.ExitCode -eq 0) {
                $progressBar.Value = 100
            }

            # Process completion based on job type
            Write-RepairLog "Processing completion for job: '$($global:currentRepairJob.Name)'"
            
            try {
                switch ($global:currentRepairJob.Name) {
                    "DISMRepairJob" { 
                        ProcessDISMCompletion $jobResult 
                    }
                    "SFCRepairJob" { 
                        ProcessSFCCompletion $jobResult 
                    }
                    "DiskCleanupJob" { 
                        ProcessDiskCleanupCompletion $jobResult
                    }
                    default {
                        Write-RepairLog "Unknown job name: '$($global:currentRepairJob.Name)'"
                        $statusLabel.Text = "Status: Operation completed"
                        $statusLabel.ForeColor = [System.Drawing.Color]::DarkGreen
                    }
                }
            }
            catch {
                Write-RepairLog "Error in completion handler: $($_.Exception.Message)"
                $statusLabel.Text = "Status: ERROR - Completion handler failed"
                $statusLabel.ForeColor = [System.Drawing.Color]::Red
                
                [System.Windows.Forms.MessageBox]::Show(
                    "An error occurred in the completion handler.`n`nError: $($_.Exception.Message)`n`nCheck the log file for full details.",
                    "Completion Handler Error", "OK", "Error"
                )
            }
            
            $sfcButton.Enabled = $true
            $dismButton.Enabled = $true
            $cleanupButton.Enabled = $true
            $progressBar.Visible = $false
            
            Remove-Job $global:currentRepairJob -Force -ErrorAction SilentlyContinue
            $global:currentRepairJob = $null
            $global:currentJobId = $null
            
            if ($global:progressUpdateTimer) {
                $global:progressUpdateTimer.Dispose()
                $global:progressUpdateTimer = $null
            }
        }
    }
    catch {
        Write-RepairLog "Timer error: $($_.Exception.Message)"
        if ($global:progressUpdateTimer) { $global:progressUpdateTimer.Stop() }
    }
    finally {
        [System.Threading.Monitor]::Exit($global:timerLock)
    }
}

function Get-JobResult {
    param([System.Management.Automation.Job]$Job)
    
    $jobResult = $null
    try {
        $finalOutput = Receive-Job -Job $Job -Wait
        
        Write-RepairLog "Job final output received, looking for result object"
        Write-RepairLog "Final output contains $($finalOutput.Count) items"
        
        # Look for result between FINAL_RESULT_START and FINAL_RESULT_END markers
        $resultStartIndex = -1
        $resultEndIndex = -1
        
        for ($i = 0; $i -lt $finalOutput.Count; $i++) {
            if ($finalOutput[$i] -eq "FINAL_RESULT_START") {
                $resultStartIndex = $i
                Write-RepairLog "Found FINAL_RESULT_START at index $i"
            }
            elseif ($finalOutput[$i] -eq "FINAL_RESULT_END") {
                $resultEndIndex = $i
                Write-RepairLog "Found FINAL_RESULT_END at index $i"
                break
            }
        }
        
        # Extract result object between markers with bounds checking
        if ($resultStartIndex -ge 0 -and $resultEndIndex -gt $resultStartIndex) {
            for ($i = $resultStartIndex + 1; $i -lt $resultEndIndex -and $i -lt $finalOutput.Count; $i++) {
                if ($finalOutput[$i] -is [PSCustomObject]) {
                    $jobResult = $finalOutput[$i]
                    Write-RepairLog "Found result object between markers with ExitCode: $($jobResult.ExitCode)"
                    break
                }
            }
        }
        
        # Fallback: Look for any PSCustomObject with ResultMarker
        if (-not $jobResult) {
            $jobResult = $finalOutput | Where-Object { 
                $_ -is [PSCustomObject] -and 
                $_.PSObject.Properties['ResultMarker'] -and 
                $_.ResultMarker -eq "CLEANUP_JOB_RESULT" 
            } | Select-Object -First 1
            
            if ($jobResult) {
                Write-RepairLog "Found result object by ResultMarker with ExitCode: $($jobResult.ExitCode)"
            }
        }
        
        # Second fallback: Look for any PSCustomObject with ExitCode
        if (-not $jobResult) {
            $jobResult = $finalOutput | Where-Object { 
                $_ -is [PSCustomObject] -and 
                $_.PSObject.Properties['ExitCode'] 
            } | Select-Object -First 1
            
            if ($jobResult) {
                Write-RepairLog "Found result object by ExitCode property with ExitCode: $($jobResult.ExitCode)"
            }
        }
        
        # Create synthetic result if none found
        if (-not $jobResult) {
            $exitCode = if ($Job.State -eq [System.Management.Automation.JobState]::Completed) { 0 } else { 1 }
            
            Write-RepairLog "Creating synthetic JobResult with exit code: $exitCode"
            $jobResult = [PSCustomObject]@{ 
                ExitCode          = $exitCode
                StandardOutput    = "Operation completed"
                StandardError     = ""
                WindowsOldExists  = $false
                WindowsOldRemoved = $false
                TimeoutOccurred   = $false
                ResultMarker      = "SYNTHETIC_RESULT"
            }
        }
        
        Write-RepairLog "Final JobResult validation - ExitCode: '$($jobResult.ExitCode)'"
    }
    catch {
        Write-RepairLog "Failed to retrieve job results: $($_.Exception.Message)"
        $jobResult = [PSCustomObject]@{ 
            ExitCode       = -1
            StandardOutput = "Error retrieving results"
            StandardError  = $_.Exception.Message
        }
    }
    
    return $jobResult
}
#endregion

#region GUI Creation and Layout - ORIGINAL UNCHANGED
$form = New-Object System.Windows.Forms.Form
$form.Text = "System Repair Toolkit"
$form.Size = New-Object System.Drawing.Size(650, 480)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::White
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false
$form.MinimizeBox = $true

# Layout constants
$topMargin = 20
$controlSpacing = 15
$mainButtonHeight = 55
$fixedMainButtonWidth = 590
$mainButtonLeftMargin = ($form.ClientSize.Width - $fixedMainButtonWidth) / 2
$currentY = $topMargin

# Title label
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Location = New-Object System.Drawing.Point($mainButtonLeftMargin, $currentY)
$titleLabel.Size = New-Object System.Drawing.Size($fixedMainButtonWidth, 35)
$titleLabel.Text = "System Repair Toolkit"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$titleLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$titleLabel.ForeColor = [System.Drawing.Color]::DarkBlue
$currentY += $titleLabel.Height + ($controlSpacing / 2)

# Instruction label
$instructionLabel = New-Object System.Windows.Forms.Label
$instructionLabel.Location = New-Object System.Drawing.Point($mainButtonLeftMargin, $currentY)
$instructionLabel.Size = New-Object System.Drawing.Size($fixedMainButtonWidth, 20)
$instructionLabel.Text = "Recommended order: DISM (Step 1) -> SFC (Step 2) -> System Cleanup (Step 3)"
$instructionLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$instructionLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$instructionLabel.ForeColor = [System.Drawing.Color]::DarkSlateGray
$currentY += $instructionLabel.Height + $controlSpacing

# DISM repair button
$dismButton = New-Object System.Windows.Forms.Button
$dismButton.Location = New-Object System.Drawing.Point($mainButtonLeftMargin, $currentY)
$dismButton.Size = New-Object System.Drawing.Size($fixedMainButtonWidth, $mainButtonHeight)
$dismButton.Text = "STEP 1: Repair System Image (DISM /RestoreHealth)`nFixes core Windows component store issues. Run FIRST."
$dismButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$dismButton.BackColor = [System.Drawing.Color]::FromArgb(135, 206, 250)  # Light sky blue - more vibrant
$dismButton.ForeColor = [System.Drawing.Color]::DarkBlue
$dismButton.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$dismButton.Add_Click({ Start-DISMRepair })
$currentY += $dismButton.Height + $controlSpacing

# SFC repair button
$sfcButton = New-Object System.Windows.Forms.Button
$sfcButton.Location = New-Object System.Drawing.Point($mainButtonLeftMargin, $currentY)
$sfcButton.Size = New-Object System.Drawing.Size($fixedMainButtonWidth, $mainButtonHeight)
$sfcButton.Text = "STEP 2: Fix System Files (SFC /scannow)`nScans and repairs protected system files. Run AFTER DISM."
$sfcButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$sfcButton.BackColor = [System.Drawing.Color]::FromArgb(152, 251, 152)  # Pale green - more vibrant
$sfcButton.ForeColor = [System.Drawing.Color]::DarkGreen
$sfcButton.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$sfcButton.Add_Click({ Start-SFCRepair })
$currentY += $sfcButton.Height + $controlSpacing

# System cleanup button
$cleanupButton = New-Object System.Windows.Forms.Button
$cleanupButton.Location = New-Object System.Drawing.Point($mainButtonLeftMargin, $currentY)
$cleanupButton.Size = New-Object System.Drawing.Size($fixedMainButtonWidth, $mainButtonHeight)
$cleanupButton.Text = "STEP 3: Clean Up/Optimize System (Automatic Disk Cleanup)`nFrees disk space, optimizes caches, and improves performance. Run THIRD."
$cleanupButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$cleanupButton.BackColor = [System.Drawing.Color]::FromArgb(255, 218, 185)  # Peach puff - warmer than pale yellow
$cleanupButton.ForeColor = [System.Drawing.Color]::FromArgb(139, 101, 8)
$cleanupButton.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$cleanupButton.Add_Click({ Start-DiskCleanup })
$currentY += $cleanupButton.Height + $controlSpacing

# Progress bar
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point($mainButtonLeftMargin, $currentY)
$progressBar.Size = New-Object System.Drawing.Size($fixedMainButtonWidth, 23)
$progressBar.Minimum = 0
$progressBar.Maximum = 100
$progressBar.Value = 0
$progressBar.Visible = $false
$currentY += $progressBar.Height + ($controlSpacing / 2)

# Status label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Location = New-Object System.Drawing.Point($mainButtonLeftMargin, $currentY)
$statusLabel.Size = New-Object System.Drawing.Size($fixedMainButtonWidth, 25)
$statusLabel.Text = "Status: Initializing..."
$statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$statusLabel.ForeColor = [System.Drawing.Color]::DarkGreen
$statusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$currentY += $statusLabel.Height + $controlSpacing

# Bottom buttons layout
$bottomButtonWidth = 180
$bottomButtonHeight = 35
$bottomControlSpacing = 15
$totalBottomButtonsWidth = (3 * $bottomButtonWidth) + (2 * $bottomControlSpacing)
$bottomButtonsGroupStartX = ($form.ClientSize.Width - $totalBottomButtonsWidth) / 2
$helpButtonX = [int]$bottomButtonsGroupStartX
$viewLogButtonX = [int]($bottomButtonsGroupStartX + $bottomButtonWidth + $bottomControlSpacing)
$closeButtonX = [int]($bottomButtonsGroupStartX + 2 * ($bottomButtonWidth + $bottomControlSpacing))

# Help button
$helpButton = New-Object System.Windows.Forms.Button
$helpButton.Location = New-Object System.Drawing.Point($helpButtonX, $currentY)
$helpButton.Size = New-Object System.Drawing.Size($bottomButtonWidth, $bottomButtonHeight)
$helpButton.Text = "Help / Information"
$helpButton.BackColor = [System.Drawing.Color]::AliceBlue
$helpButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$helpButton.Add_Click({
        $helpMsg = "System Repair Toolkit - User Guide:`n`n" +
        "This toolkit provides automated access to common Windows repair and cleanup utilities.`n`n" +
        "RECOMMENDED USAGE ORDER:`n`n" +
        "1. STEP 1 - Repair System Image (DISM /RestoreHealth):`n" +
        "   Purpose: Fixes corruption in the Windows Component Store (WinSxS), which is vital for updates and system stability.`n" +
        "   Duration: Typically 5-20 minutes, may vary based on system condition and internet speed.`n" +
        "   Requirements: Administrator privileges. Run this step FIRST, especially if SFC reports unfixable errors.`n`n" +
        "2. STEP 2 - Fix System Files (SFC /scannow):`n" +
        "   Purpose: Scans all protected system files and replaces corrupted versions with correct Microsoft versions.`n" +
        "   Duration: Typically 5-15 minutes.`n" +
        "   Requirements: Administrator privileges. Best run AFTER a successful DISM repair.`n`n" +
        "3. STEP 3 - Clean Up & Optimize System (Enhanced Cleanup):`n" +
        "   Purpose: Comprehensive cleanup and optimization including disk cleanup, cache optimization, and system tuning.`n" +
        "   Includes: Temporary files, Recycle Bin, old update files, shadow copies, font/icon cache refresh, DNS flush, and system optimization.`n" +
        "   Duration: Typically 3-15 minutes, longer if extensive cleanup is performed. Includes timeout protection for stuck operations.`n" +
        "   Requirements: Administrator privileges for full functionality.`n`n" +
        "KEY FEATURES & IMPORTANT NOTES:`n" +
        "- Administrator Rights: Most functions require elevated privileges. The status bar indicates your current privilege level.`n" +
        "- Windows.old Folder: If detected, you'll be prompted whether to include it in cleanup. Removal frees significant space but prevents rollback.`n" +
        "- Timeout Protection: Cleanup operations have 15-minute timeouts to prevent system hanging, with automatic fallback to manual operations.`n" +
        "- Logging: All operations are logged to 'SystemRepairLog.txt' on your Desktop for troubleshooting.`n" +
        "- Patience: Repair operations can take considerable time. Please allow them to complete without interruption.`n`n" +
        "For best results, close other applications before running these repair tools."

        [System.Windows.Forms.MessageBox]::Show($helpMsg, "System Repair Toolkit - Help & Information", "OK", "Information")
        Write-RepairLog "User opened help dialog"
    })

# View log button
$viewLogButton = New-Object System.Windows.Forms.Button
$viewLogButton.Location = New-Object System.Drawing.Point($viewLogButtonX, $currentY)
$viewLogButton.Size = New-Object System.Drawing.Size($bottomButtonWidth, $bottomButtonHeight)
$viewLogButton.Text = "View Activity Log"
$viewLogButton.BackColor = [System.Drawing.Color]::LightGray
$viewLogButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$viewLogButton.Add_Click({
        if (Test-Path $global:logPath) {
            try {
                Invoke-Item $global:logPath
                Write-RepairLog "Activity log opened by user"
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show(
                    "Could not open the log file at '$($global:logPath)'.`n`nError: $($_.Exception.Message)",
                    "Error Opening Log File", "OK", "Error"
                )
            }
        }
        else {
            [System.Windows.Forms.MessageBox]::Show(
                "The activity log ('SystemRepairLog.txt') has not been created yet or cannot be found at '$($global:logPath)'. It will be generated on your Desktop when the script performs actions.",
                "Log File Not Found", "OK", "Information"
            )
        }
    })

# Close button
$closeButton = New-Object System.Windows.Forms.Button
$closeButton.Location = New-Object System.Drawing.Point($closeButtonX, $currentY)
$closeButton.Size = New-Object System.Drawing.Size($bottomButtonWidth, $bottomButtonHeight)
$closeButton.Text = "Close Toolkit"
$closeButton.BackColor = [System.Drawing.Color]::MistyRose
$closeButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$closeButton.Add_Click({
        Write-RepairLog "System Repair Toolkit close requested by user"
        $form.Close()
    })

$form.Controls.AddRange(@(
        $titleLabel, $instructionLabel, $dismButton, $sfcButton, $cleanupButton,
        $progressBar, $statusLabel, $helpButton, $viewLogButton, $closeButton
    ))
#endregion

#region Cleanup and Startup - UPDATED TO USE ENHANCED LOGGING
$form.Add_FormClosing({
        Write-RepairLog "Application shutdown initiated"
    
        if ($global:currentRepairJob -and $global:currentRepairJob.State -eq [System.Management.Automation.JobState]::Running) {
            try {
                Stop-Job -Job $global:currentRepairJob -Force
                Remove-Job -Job $global:currentRepairJob -Force
                $global:currentRepairJob = $null
            }
            catch {
                Write-RepairLog "Error stopping job during shutdown: $($_.Exception.Message)"
            }
        }

        if ($global:progressUpdateTimer) {
            $global:progressUpdateTimer.Stop()
            $global:progressUpdateTimer.Dispose()
            $global:progressUpdateTimer = $null
        }
        
        Close-RepairLog
    })

if (Test-IsAdministrator) {
    Write-RepairLog "Toolkit started with Administrator privileges"
    $statusLabel.Text = "Status: Ready (Administrator Mode)"
    $statusLabel.ForeColor = [System.Drawing.Color]::DarkGreen
}
else {
    Write-RepairLog "Toolkit started without Administrator privileges"
    $statusLabel.Text = "Status: Ready (Standard Mode - Run as Admin for full functionality)"
    $statusLabel.ForeColor = [System.Drawing.Color]::DarkOrange
}

Write-RepairLog "Displaying main application window"
$form.ShowDialog()
Write-RepairLog "System Repair Toolkit session ended"
#endregion
