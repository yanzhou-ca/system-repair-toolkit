<#
.SYNOPSIS
    A Windows Forms-based GUI toolkit for performing common system repair and optimization tasks,
    including DISM image repair, SFC system file checking, and comprehensive disk cleanup.

.DESCRIPTION
    This script provides a user-friendly interface to execute a sequence of recommended repair
    operations. It uses PowerShell background jobs to run tasks asynchronously, providing real-time
    progress updates to the user without freezing the UI. All actions are logged to a file on
    the user's Desktop for easy troubleshooting.

.NOTES
    Version: 2.0
    Author: Yan Zhou
    Requirements: PowerShell 5.0+, Windows 10/11, Administrator privileges for full functionality.
    
    ==============================
    SYSTEM REPAIR TOOLKIT v2.0
    ==============================

    WHAT THIS TOOLKIT DOES:
    1. DISM system image repair with component store cleanup
    2. SFC system file scanning and repair
    3. Registry cleanup configuration for maximum disk space recovery
    4. Windows.old folder management with user consent
    5. Comprehensive disk cleanup using CleanMgr with timeout handling
    6. Manual cleanup of temp files, caches, and logs with size reporting
    7. Performance optimization (prefetch, network stack reset, DNS flush)
    8. Visual performance optimization (icon cache refresh with Explorer restart)
    
    DESIGN PRINCIPLES:
    - Windows 11 compatible UI design with modern styling
    - Background job management for responsive user interface
    - Comprehensive logging for troubleshooting and verification
    - User consent for potentially disruptive operations
    - Administrator privilege validation with graceful degradation
    - Cross-session log file continuity for tracking multiple runs
#>

#region Assembly Loading and Initialization
# Load required .NET assemblies for Windows Forms GUI and drawing functionality
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Initialize script-level state tracking
$script:isInitialized = $false
$script:lastUiUpdate = $null
$script:progressCommunicationFailures = 0
#endregion

#region Constants and Configuration
# Define all configuration constants with Windows 11 design standards
$script:CONSTANTS = @{
    # Performance and timing constants - OPTIMIZED
    TIMER_INTERVAL_MS             = 1000      # Timer interval for progress updates
    USER_DECISION_TIMEOUT_SECONDS = 90        # FIXED: Reduced from 120s to 90s for better UX
    CLEANMGR_TIMEOUT_MINUTES      = 3         # FIXED: Reduced from 5 to 3 minutes
    MAX_ESTIMATED_PROGRESS        = 95        # Maximum progress percentage for estimated tasks
    UI_UPDATE_THROTTLE_MS         = 250       # IMPROVED: Faster UI updates
    PROGRESS_COMM_FAILURE_LIMIT   = 8         # IMPROVED: Increased from 5 to 8 to be less aggressive
    
    # Cleanup and file system constants
    SAGESET_VALUE                 = 64        # StateFlags value for disk cleanup
    LOG_FILENAME                  = "SystemRepairLog.txt"
    LOG_MAX_SIZE_MB               = 10        # Maximum log file size before rotation
    COMMUNICATION_PREFIX          = "RepairToolkit"
    
    # Windows 11 UI Design System
    UI                            = @{
        # Layout and spacing (Windows 11 standards)
        MAIN_BUTTON_HEIGHT    = 44        # Standard button height
        MAIN_BUTTON_WIDTH     = 320       # More proportional width
        SMALL_BUTTON_HEIGHT   = 30        # Utility button height
        SMALL_BUTTON_WIDTH    = 95        # Utility button width
        CONTROL_SPACING       = 16        # Spacing between controls
        TOP_MARGIN            = 20        # Top margin for layout
        
        # Windows 11 Color Palette
        PRIMARY_COLOR         = [System.Drawing.Color]::FromArgb(0, 103, 192)    # Windows 11 accent blue
        PRIMARY_HOVER_COLOR   = [System.Drawing.Color]::FromArgb(16, 90, 170)    # Darker blue for hover
        SECONDARY_COLOR       = [System.Drawing.Color]::FromArgb(243, 243, 243)  # Light gray
        SECONDARY_HOVER_COLOR = [System.Drawing.Color]::FromArgb(235, 235, 235)  # Darker gray for hover
        BACKGROUND_COLOR      = [System.Drawing.Color]::FromArgb(249, 249, 249)  # Subtle warm white
        TEXT_PRIMARY          = [System.Drawing.Color]::FromArgb(25, 25, 25)     # Near black
        TEXT_SECONDARY        = [System.Drawing.Color]::FromArgb(96, 96, 96)     # Medium gray
        SUCCESS_COLOR         = [System.Drawing.Color]::FromArgb(16, 137, 62)    # Success green
        WARNING_COLOR         = [System.Drawing.Color]::FromArgb(255, 140, 0)    # Warning orange
        ERROR_COLOR           = [System.Drawing.Color]::FromArgb(196, 43, 28)    # Error red
        BORDER_COLOR          = [System.Drawing.Color]::FromArgb(200, 200, 200)  # Light border
        BORDER_HOVER_COLOR    = [System.Drawing.Color]::FromArgb(160, 160, 160)  # Darker border
    }
}
#endregion

#region Script Variables and State Management
# Define all script-level variables for state management with proper initialization
$script:currentRepairJob = $null           # Current background job reference
$script:progressUpdateTimer = $null        # Timer for UI progress updates
$script:operationStartTime = $null         # Timestamp when current operation started
$script:timerLock = New-Object System.Object # Thread synchronization for timer
$script:logPath = $null                    # Full path to the log file
$script:currentJobId = $null               # Unique identifier for job communication
$script:capturedJobResult = $null          # Final job result captured early
$script:fallbackProgressEnabled = $false   # NEW: Fallback progress mode
$script:lastProgressUpdate = $null         # NEW: Track last progress update

# Progress tracking and deduplication variables
$script:lastLoggedProgress = ""            # Last progress message logged (for deduplication)
$script:lastLoggedPercent = -1             # Last percentage logged (for deduplication)
$script:lastProgressLogTime = $null        # Timestamp of last progress log entry
$script:progressMessageCount = 0           # Counter for progress message throttling
$script:lastFallbackLogTime = $null        # NEW: Track fallback logging to reduce spam
#endregion

#region Enhanced Logging System
# Configuration for the enhanced logging system with improved categorization
$script:LOG_CONFIG = @{
    Categories            = @{
        INFO      = @{ Display = "INFO"; Color = "White"; Description = "General information" }
        OPERATION = @{ Display = "STEP"; Color = "Cyan"; Description = "Major operation start/end" }
        PROGRESS  = @{ Display = "PROG"; Color = "Yellow"; Description = "Progress updates" }
        SUCCESS   = @{ Display = "DONE"; Color = "Green"; Description = "Successful completion" }
        WARNING   = @{ Display = "WARN"; Color = "DarkYellow"; Description = "Non-critical issues" }
        ERROR     = @{ Display = "ERR!"; Color = "Red"; Description = "Error conditions" }
        USER      = @{ Display = "USER"; Color = "Magenta"; Description = "User interactions" }
        SYSTEM    = @{ Display = "SYS "; Color = "Gray"; Description = "System events" }
        JOB       = @{ Display = "JOB "; Color = "DarkCyan"; Description = "Background job management" }
        DEBUG     = @{ Display = "DBG "; Color = "DarkGray"; Description = "Debug information" }
    }
    Operations            = @{
        DISM    = "System Image Repair"
        SFC     = "System File Check"
        CLEANUP = "System Cleanup"
        TOOLKIT = "Repair Toolkit"
        JOB     = "Background Task"
    }
    OperationDescriptions = @{
        DISM    = "Repairing Windows system image and component store"
        SFC     = "Scanning and repairing system files"
        CLEANUP = "Cleaning temporary files and optimizing system"
    }
}

# Enhanced logging function with improved validation and performance
function Write-RepairLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        
        [Parameter(Position = 1)]
        [ValidateSet("INFO", "OPERATION", "PROGRESS", "SUCCESS", "WARNING", "ERROR", "USER", "SYSTEM", "JOB", "DEBUG")]
        [string]$Category = "INFO",
        
        [Parameter(Position = 2)]
        [ValidateSet("DISM", "SFC", "CLEANUP", "TOOLKIT", "JOB")]
        [string]$Operation = "TOOLKIT",
        
        [switch]$IncludeInConsole
    )

    try {
        # Enhanced message validation and cleaning
        if ([string]::IsNullOrWhiteSpace($Message)) {
            $Message = "[Empty message received]"
        }
        
        # More efficient regex for cleaning control characters
        $cleanMessage = $Message -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+', '' -replace '\s+', ' '
        $cleanMessage = $cleanMessage.Trim()
        
        # Limit message length with better truncation
        if ($cleanMessage.Length -gt 1000) {
            $cleanMessage = $cleanMessage.Substring(0, 997) + "..."
        }
        
        # Enhanced corruption detection
        if ($cleanMessage -match '^[^\w\s\-\[\]():.,!?]{10,}') {
            $cleanMessage = "[Corrupted output detected and filtered]"
        }
        
        # Build formatted log entry with validation
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $categoryInfo = $script:LOG_CONFIG.Categories[$Category]
        $operationName = $script:LOG_CONFIG.Operations[$Operation]

        $logEntry = "[$timestamp] [$($categoryInfo.Display)] [$operationName] $cleanMessage"
        
        # Thread-safe file writing with better error handling
        try {
            Add-Content -Path $script:logPath -Value $logEntry -Encoding UTF8 -ErrorAction Stop
        }
        catch [System.IO.IOException] {
            # Handle file locking issues with retry
            Start-Sleep -Milliseconds 100
            Add-Content -Path $script:logPath -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
        }

        # Optional console output with color
        if ($IncludeInConsole) {
            Write-Host $logEntry -ForegroundColor $categoryInfo.Color
        }
    }
    catch {
        # Enhanced fallback logging
        $fallbackEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERR!] [TOOLKIT] Logging error: $($_.Exception.Message) | Original: $($Message.Substring(0, [Math]::Min($Message.Length, 200)))"
        try {
            Add-Content -Path $script:logPath -Value $fallbackEntry -Encoding UTF8 -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "Complete logging failure: $($_.Exception.Message)"
        }
    }
}

# Enhanced operation logging functions with better error handling
function Write-OperationStart {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("DISM", "SFC", "CLEANUP")]
        [string]$OperationType,
        
        [ValidateNotNullOrEmpty()]
        [string]$Description
    )

    try {
        if (-not $Description) {
            $Description = $script:LOG_CONFIG.OperationDescriptions[$OperationType]
        }
        Write-RepairLog -Message "=== STARTING: $Description ===" -Category "OPERATION" -Operation $OperationType
    }
    catch {
        Write-RepairLog -Message "Error logging operation start: $($_.Exception.Message)" -Category "ERROR"
    }
}

function Write-OperationEnd {
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

    try {
        $durationText = if ($Duration) { 
            "in {0:mm\:ss} (mm:ss)" -f $Duration 
        }
        else { 
            "duration unknown" 
        }
        
        $resultText = if ($Success) { "COMPLETED SUCCESSFULLY" } else { "COMPLETED WITH ISSUES" }
        $category = if ($Success) { "SUCCESS" } else { "WARNING" }

        Write-RepairLog -Message "=== $resultText $($script:LOG_CONFIG.OperationDescriptions[$OperationType]) $durationText ===" -Category $category -Operation $OperationType

        if ($ExitCode -ne 0) {
            Write-RepairLog -Message "Exit code: $ExitCode (See tool-specific documentation for details)" -Category "INFO" -Operation $OperationType
        }
        if ($AdditionalInfo) {
            Write-RepairLog -Message "Additional info: $AdditionalInfo" -Category "INFO" -Operation $OperationType
        }
    }
    catch {
        Write-RepairLog -Message "Error logging operation end: $($_.Exception.Message)" -Category "ERROR"
    }
}

# Enhanced log initialization with proper cross-session continuity and size management
function Initialize-RepairLog {
    [CmdletBinding()]
    param()
    
    try {
        # Use more reliable method to get desktop path
        $desktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
        $script:logPath = [System.IO.Path]::Combine($desktopPath, $script:CONSTANTS.LOG_FILENAME)
        
        # Check if log file exists and manage size
        if (Test-Path $script:logPath) {
            try {
                $logFile = Get-Item $script:logPath
                $logSizeMB = [Math]::Round($logFile.Length / 1MB, 2)
                
                # If log file is larger than 10MB, rotate it
                if ($logFile.Length -gt 10MB) {
                    $backupPath = [System.IO.Path]::Combine($desktopPath, "SystemRepairLog_backup.txt")
                    
                    # If backup exists, remove it (keep only one backup)
                    if (Test-Path $backupPath) {
                        Remove-Item $backupPath -Force -ErrorAction SilentlyContinue
                    }
                    
                    # Move current log to backup
                    Move-Item $script:logPath $backupPath -Force -ErrorAction SilentlyContinue
                    
                    Write-Host "Log file rotated (was $logSizeMB MB). Previous log saved as SystemRepairLog_backup.txt" -ForegroundColor Yellow
                }
                else {
                    Write-Host "Continuing existing log file ($logSizeMB MB)" -ForegroundColor Green
                }
            }
            catch {
                Write-Warning "Could not check log file size: $($_.Exception.Message)"
            }
        }
        
        # Create session header with enhanced system information
        $separator = "=" * 80
        $adminStatus = if (Test-IsAdministrator) { 'Yes' } else { 'No' }
        $psVersion = if ($PSVersionTable.PSVersion) { $PSVersionTable.PSVersion.ToString() } else { "Unknown" }
        
        $header = @"
$separator
SYSTEM REPAIR TOOLKIT - SESSION LOG
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
PowerShell Version: $psVersion
OS Version: $([System.Environment]::OSVersion.VersionString)
User: $([System.Environment]::UserName)
Computer: $([System.Environment]::MachineName)
Administrator Mode: $adminStatus
Process ID: $PID
Log Path: $script:logPath
$separator

"@
        # Use Add-Content to preserve cross-session logs
        Add-Content -Path $script:logPath -Value $header -Encoding UTF8
        Write-RepairLog -Message "System Repair Toolkit session started" -Category "SYSTEM"
        $script:isInitialized = $true
    }
    catch {
        Write-Warning "Failed to initialize repair log: $($_.Exception.Message)"
        $script:isInitialized = $false
    }
}

function Close-RepairLog {
    [CmdletBinding()]
    param()
    
    try {
        if ($script:isInitialized -and $script:logPath) {
            $separator = "=" * 80
            $footer = @"

$separator
SESSION COMPLETED: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Total Progress Messages: $script:progressMessageCount
Communication Failures: $script:progressCommunicationFailures
$separator
"@
            Write-RepairLog -Message "System Repair Toolkit session ending" -Category "SYSTEM"
            Add-Content -Path $script:logPath -Value $footer -Encoding UTF8
        }
    }
    catch {
        Write-Warning "Failed to close repair log properly: $($_.Exception.Message)"
    }
}
#endregion

#region Core Utility Functions
# Enhanced administrator privilege checking with better error handling
function Test-IsAdministrator {
    [CmdletBinding()]
    param()
    
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Write-RepairLog -Message "Failed to determine administrator status: $($_.Exception.Message)" -Category "ERROR"
        return $false
    }
}

function Confirm-AdminOrFail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OperationName
    )
    
    if (-not (Test-IsAdministrator)) {
        $message = "$OperationName requires Administrator privileges. Please restart the toolkit as an Administrator."
        Show-WarningMessage -Message $message
        Write-RepairLog -Message "Operation '$OperationName' blocked: Administrator privileges required" -Category "WARNING"
        return $false
    }
    return $true
}

# Enhanced error handling wrapper with better logging
function Invoke-WithErrorHandling {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OperationName,
        
        [bool]$ContinueOnError = $true
    )
    
    try {
        return & $ScriptBlock
    }
    catch {
        $errorMessage = "Error in '$OperationName': $($_.Exception.Message)"
        Write-RepairLog -Message $errorMessage -Category 'ERROR' -Operation 'TOOLKIT'
        
        if (-not $ContinueOnError) { 
            throw 
        }
        return $null
    }
}

# Enhanced message box functions with Windows 11 styling
function Show-InfoMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        
        [string]$Title = "System Repair Toolkit",
        [System.Windows.Forms.MessageBoxButtons]$Buttons = 'OK',
        [System.Windows.Forms.MessageBoxIcon]$Icon = 'Information'
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
    Show-InfoMessage -Message $Message -Title $Title -Icon 'Error'
}

function Show-WarningMessage { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message, 
        [string]$Title = "System Repair Toolkit - Warning"
    )
    Show-InfoMessage -Message $Message -Title $Title -Icon 'Warning'
}

function Show-QuestionMessage { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message, 
        [string]$Title = "System Repair Toolkit - Confirmation"
    )
    Show-InfoMessage -Message $Message -Title $Title -Buttons 'YesNo' -Icon 'Question'
}
#endregion

#region Enhanced Job Communication Functions
# FIXED: Enhanced secure communication with user-specific temp directory
function Set-JobCommunication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$JobId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Key,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Value
    )
    
    try {
        # Use single predictable file path instead of marker system
        $userTempPath = [System.IO.Path]::GetTempPath()
        $communicationPath = [System.IO.Path]::Combine($userTempPath, "$($script:CONSTANTS.COMMUNICATION_PREFIX)_${JobId}_${Key}.tmp")
        
        # Create communication file with proper permissions
        Set-Content -Path $communicationPath -Value $Value -Encoding UTF8 -Force
        
        Write-RepairLog -Message "Job communication set: $Key = $Value" -Category "JOB"
    }
    catch {
        Write-RepairLog -Message "Failed to set job communication: $($_.Exception.Message)" -Category "ERROR"
    }
}

function Get-JobCommunication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$JobId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Key,
        
        [ValidateRange(1, 3600)]
        [int]$TimeoutSeconds = 90  # FIXED: Reduced from 300 to 90 seconds
    )
    
    try {
        # Direct file path check instead of marker system
        $userTempPath = [System.IO.Path]::GetTempPath()
        $communicationPath = [System.IO.Path]::Combine($userTempPath, "$($script:CONSTANTS.COMMUNICATION_PREFIX)_${JobId}_${Key}.tmp")
        $timeout = (Get-Date).AddSeconds($TimeoutSeconds)

        while ((Get-Date) -lt $timeout) {
            if (Test-Path $communicationPath) {
                $value = Get-Content $communicationPath -Raw -ErrorAction SilentlyContinue
                
                # Clean up communication file securely
                Remove-Item $communicationPath -Force -ErrorAction SilentlyContinue
                
                if ($null -ne $value) { 
                    return $value.Trim() 
                }
            }
            Start-Sleep -Seconds 1
        }
        
        Write-RepairLog -Message "Job communication timeout for key: $Key after $TimeoutSeconds seconds" -Category "WARNING"
        return $null
    }
    catch {
        Write-RepairLog -Message "Error retrieving job communication: $($_.Exception.Message)" -Category "ERROR"
        return $null
    }
}
#endregion

# Initialize logging system early
Initialize-RepairLog

#region Enhanced Command Runner ScriptBlock
# FIXED: Improved background job script for running DISM and SFC with better encoding support
$script:commandRunnerScriptBlock = {
    param(
        [string]$ExecutablePath, 
        [string]$Arguments
    )

    # Initialize job start time in the job scope
    $jobStartTime = Get-Date

    # Enhanced output cleaning with better performance
    function Get-CleanOutputLine {
        param([string]$RawLine)
        
        if ([string]::IsNullOrWhiteSpace($RawLine)) { 
            return $null 
        }
        
        # More efficient cleaning with combined regex
        $cleanLine = $RawLine -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+', '' -replace '\s+', ' '
        $cleanLine = $cleanLine.Trim()
        
        # Enhanced validation
        if ($cleanLine.Length -lt 2 -or $cleanLine.Length -gt 500) {
            return $null
        }
        
        return $cleanLine
    }

    try {
        Write-Output "PROGRESS_LINE:Starting $ExecutablePath with arguments: $Arguments"
        
        # Enhanced process configuration with encoding fallbacks
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo.FileName = $ExecutablePath
        $process.StartInfo.Arguments = $Arguments
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        $process.StartInfo.CreateNoWindow = $true

        # Improved encoding handling with fallbacks for .NET Framework compatibility
        if ($ExecutablePath -like "*sfc.exe*") {
            try {
                $process.StartInfo.StandardOutputEncoding = [System.Text.Encoding]::GetEncoding(850)
                $process.StartInfo.StandardErrorEncoding = [System.Text.Encoding]::GetEncoding(850)
                Write-Output "PROGRESS_LINE:Using OEM 850 encoding for SFC"
            }
            catch {
                # Fallback to default encoding if OEM 850 is not available
                $process.StartInfo.StandardOutputEncoding = [System.Text.Encoding]::Default
                $process.StartInfo.StandardErrorEncoding = [System.Text.Encoding]::Default
                Write-Output "PROGRESS_LINE:Using default encoding due to OEM 850 unavailability"
            }
        }
        else {
            $process.StartInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
            $process.StartInfo.StandardErrorEncoding = [System.Text.Encoding]::UTF8
            Write-Output "PROGRESS_LINE:Using UTF-8 encoding for DISM"
        }

        # Start the process and verify it started
        $processStarted = $process.Start()
        if (-not $processStarted) {
            throw "Failed to start process $ExecutablePath"
        }
        
        Write-Output "PROGRESS_LINE:Process started successfully with PID: $($process.Id)"

        # Enhanced real-time output monitoring with better performance
        $outputLines = @()
        $lastOutputTime = Get-Date
        
        while (-not $process.HasExited) {
            try {
                # Non-blocking read with timeout
                if ($process.StandardOutput.Peek() -ge 0) {
                    $line = $process.StandardOutput.ReadLine()
                    
                    if ($null -ne $line) {
                        $cleanLine = Get-CleanOutputLine -RawLine $line
                        
                        if ($null -ne $cleanLine) {
                            $outputLines += $cleanLine
                            Write-Output "PROGRESS_LINE:$cleanLine"
                            $lastOutputTime = Get-Date
                        }
                    }
                }
                
                # Prevent infinite loops for silent commands
                if (((Get-Date) - $lastOutputTime).TotalMinutes -gt 5) {
                    Write-Output "PROGRESS_LINE:Command running... (no recent output)"
                    $lastOutputTime = Get-Date
                }
            }
            catch {
                Write-Output "PROGRESS_LINE:Output reading error: $($_.Exception.Message)"
                break
            }
            
            # Optimized sleep interval
            Start-Sleep -Milliseconds 250
        }

        # Enhanced remaining output processing
        try {
            $remainingOutput = $process.StandardOutput.ReadToEnd()
            if (-not [string]::IsNullOrWhiteSpace($remainingOutput)) {
                $remainingLines = $remainingOutput -split "`r`n|`r|`n" | Where-Object { $_ }
                foreach ($line in $remainingLines) {
                    $cleanLine = Get-CleanOutputLine -RawLine $line
                    if ($null -ne $cleanLine) {
                        $outputLines += $cleanLine
                        Write-Output "PROGRESS_LINE:$cleanLine"
                    }
                }
            }
        }
        catch {
            Write-Output "PROGRESS_LINE:Error processing remaining output: $($_.Exception.Message)"
        }

        # Wait for process to fully complete and get the actual exit code
        $process.WaitForExit()
        $actualExitCode = $process.ExitCode
        
        Write-Output "PROGRESS_LINE:Process completed with exit code: $actualExitCode"
        
        # Special handling for DISM - it often produces minimal console output but logs extensively
        if ($ExecutablePath -like "*DISM.exe*" -and $outputLines.Count -eq 0 -and $actualExitCode -eq 0) {
            Write-Output "PROGRESS_LINE:DISM completed successfully (detailed logs written to dism.log)"
            $outputLines += "DISM operation completed - check Windows\Logs\DISM\dism.log for details"
        }
        
        # Safe error output reading
        $standardError = ""
        try {
            $errorOutput = $process.StandardError.ReadToEnd()
            if (-not [string]::IsNullOrWhiteSpace($errorOutput)) {
                $standardError = Get-CleanOutputLine -RawLine $errorOutput
                if ($null -eq $standardError) { 
                    $standardError = "Error output contained invalid characters" 
                }
            }
        }
        catch {
            $standardError = "Failed to read standard error: $($_.Exception.Message)"
        }
        
        # Calculate job duration
        $jobDuration = (Get-Date) - $jobStartTime
        
        # Return enhanced structured result with the ACTUAL exit code
        Write-Output "COMMAND_RESULT_START"
        Write-Output ([PSCustomObject]@{
                ExitCode       = $actualExitCode
                StandardError  = $standardError
                JobType        = "COMMAND"
                OutputLines    = $outputLines.Count
                Duration       = $jobDuration
                ProcessId      = $process.Id
                ExecutablePath = $ExecutablePath
            })
        Write-Output "COMMAND_RESULT_END"
        
        $process.Close()
        Write-Output "PROGRESS_LINE:Job completed successfully"
    }
    catch {
        $jobDuration = (Get-Date) - $jobStartTime
        $errorMessage = "Failed to start or monitor process: $($_.Exception.Message)"
        Write-Output "PROGRESS_LINE:ERROR: $errorMessage"
        
        Write-Output "COMMAND_RESULT_START"
        Write-Output ([PSCustomObject]@{
                ExitCode       = -999
                StandardError  = $errorMessage
                JobType        = "COMMAND"
                OutputLines    = 0
                Duration       = $jobDuration
                ProcessId      = if ($process -and $process.Id) { $process.Id } else { 0 }
                ExecutablePath = $ExecutablePath
            })
        Write-Output "COMMAND_RESULT_END"
    }
}
#endregion

#region Enhanced Disk Cleanup ScriptBlock with Improved Error Handling
# FIXED: Disk Cleanup and Performance Optimization ScriptBlock
$script:diskCleanupScriptBlock = {
    param(
        [string]$LogPath, 
        [string]$JobId
    )

    # Initialize job start time in the job scope
    $jobStartTime = Get-Date

    function Write-SimpleLog {
        param([string]$message)
        try {
            if (-not [string]::IsNullOrWhiteSpace($LogPath) -and (Test-Path (Split-Path $LogPath -Parent))) {
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                "[$timestamp] [PROG] [Disk Cleanup] $message" | Add-Content -Path $LogPath -Encoding UTF8 -ErrorAction SilentlyContinue
            }
        }
        catch {
            # Silent failure for logging within background job - write to output instead
            Write-Output "PROGRESS_LINE:LOG: $message"
        }
    }

    function Update-Progress {
        param([int]$Percent, [string]$Message)
        # FIXED: More explicit progress line format
        Write-Output "PROGRESS_LINE:$Percent% - $Message"
        Write-SimpleLog "$Percent% - $Message"
    }

    try {
        Write-SimpleLog "Focused disk cleanup and optimization job started with Job ID: $JobId"
        Update-Progress -Percent 0 -Message "Starting disk cleanup and optimization..."
        
        # IMPROVED: More robust parameter validation
        if ([string]::IsNullOrWhiteSpace($JobId)) {
            Write-SimpleLog "ERROR: Job ID is missing"
            Update-Progress -Percent 5 -Message "Configuration error detected"
            throw "Job ID is required for cleanup operation"
        }
        
        Write-SimpleLog "Job validation passed, proceeding with cleanup phases"
        
        # Phase 1: Registry Cleanup Configuration (0-15%) - OPTIMIZED for speed
        Update-Progress -Percent 5 -Message "Configuring disk cleanup categories..."
        $sageset = 64
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
        $configured = 0
        
        # IMPROVED: Verify registry access with timeout protection
        try {
            if (-not (Test-Path $regPath)) {
                Write-SimpleLog "Warning: Cannot access volume caches registry path: $regPath"
                Update-Progress -Percent 10 -Message "Registry access limited - proceeding with manual cleanup"
                $configured = 0
            }
            else {
                Write-SimpleLog "Registry access confirmed, configuring cleanup categories"
                
                # OPTIMIZED: Reduced and essential cleanup categories only
                $cleanupCategories = @(
                    "Downloaded Program Files", "Internet Cache Files", "Memory Dump Files", 
                    "Recycle Bin", "Temporary Files", "Thumbnail Cache", 
                    "Update Cleanup", "Windows Error Reporting Archive Files", 
                    "Windows Update Cleanup", "User file versions"
                )
                
                # IMPROVED: Add timeout protection for registry operations
                $regStartTime = Get-Date
                foreach ($category in $cleanupCategories) {
                    # IMPROVED: Timeout protection for registry operations
                    if (((Get-Date) - $regStartTime).TotalSeconds -gt 30) {
                        Write-SimpleLog "Registry configuration timeout reached, proceeding with $configured categories"
                        break
                    }
                    
                    $categoryPath = Join-Path $regPath $category
                    if (Test-Path $categoryPath) {
                        try { 
                            Set-ItemProperty -Path $categoryPath -Name "StateFlags$($sageset.ToString('0000'))" -Value 2 -Type DWord -Force -ErrorAction Stop
                            $configured++
                        }
                        catch {
                            Write-SimpleLog "Warning: Could not configure '$category': $($_.Exception.Message)"
                        }
                    }
                }
                Write-SimpleLog "Registry configuration completed: $configured categories configured"
            }
        }
        catch {
            Write-SimpleLog "Registry configuration failed: $($_.Exception.Message)"
            Update-Progress -Percent 10 -Message "Registry configuration failed - using manual cleanup"
            $configured = 0
        }
        
        Update-Progress -Percent 15 -Message "Cleanup categories configured ($configured categories enabled)"

        # Phase 2: Windows.old Management (15-25%) - IMPROVED with faster detection
        Update-Progress -Percent 18 -Message "Checking for Windows.old folder..."
        $windowsOldPath = "C:\Windows.old"
        $windowsOldExists = $false
        $userWantsRemoval = $false

        # IMPROVED: Faster file system check with timeout
        try {
            $checkStartTime = Get-Date
            $windowsOldExists = Test-Path $windowsOldPath
            $checkDuration = ((Get-Date) - $checkStartTime).TotalSeconds
            Write-SimpleLog "Windows.old check completed in $checkDuration seconds"
            
            if ($windowsOldExists) {
                Update-Progress -Percent 20 -Message "Windows.old folder detected - requesting user decision..."
                Write-SimpleLog "Windows.old folder detected. Requesting user decision."
                
                # IMPROVED: Skip size calculation if it takes too long
                try {
                    $sizeCheckStart = Get-Date
                    $size = (Get-ChildItem $windowsOldPath -Recurse -ErrorAction SilentlyContinue | 
                        Select-Object -First 100 | 
                        Measure-Object -Property Length -Sum).Sum
                    
                    if (((Get-Date) - $sizeCheckStart).TotalSeconds -lt 10 -and $size -gt 0) {
                        $sizeGB = [Math]::Round($size / 1GB, 2)
                        Write-SimpleLog "Windows.old folder size estimated: $sizeGB GB (partial scan)"
                    }
                    else {
                        Write-SimpleLog "Windows.old folder size calculation skipped (timeout or empty)"
                    }
                }
                catch {
                    Write-SimpleLog "Windows.old size calculation failed: $($_.Exception.Message)"
                }
                
                Write-Output "WINDOWS_OLD_EXISTS:True"
                
                # FIXED: Reduced timeout and better feedback
                $timeout = (Get-Date).AddSeconds(90)  # FIXED: 90 seconds instead of 60
                $decision = $null
                
                while ((Get-Date) -lt $timeout -and $null -eq $decision) {
                    $userTempPath = [System.IO.Path]::GetTempPath()
                    $decisionFile = [System.IO.Path]::Combine($userTempPath, "RepairToolkit_${JobId}_WINDOWSOLD_DECISION.tmp")
                    
                    if (Test-Path $decisionFile) {
                        try {
                            $decision = Get-Content $decisionFile -Raw -ErrorAction SilentlyContinue
                            Remove-Item $decisionFile -Force -ErrorAction SilentlyContinue
                            Write-SimpleLog "User decision received: $decision"
                        } 
                        catch {
                            Write-SimpleLog "Error reading user decision: $($_.Exception.Message)"
                        }
                    }
                    Start-Sleep -Seconds 2
                }
                
                if ($decision -eq "YES") { 
                    $userWantsRemoval = $true
                    Write-SimpleLog "User chose to REMOVE Windows.old folder."
                    Update-Progress -Percent 22 -Message "User approved Windows.old removal - will be cleaned"
                }
                else { 
                    Write-SimpleLog "User chose to PRESERVE Windows.old folder or decision timed out."
                    Update-Progress -Percent 22 -Message "Windows.old folder will be preserved per user choice"
                }
                
                # Configure Previous Installations cleanup based on user choice
                if (Test-Path $regPath) {
                    $prevInstallPath = Join-Path $regPath "Previous Installations"
                    if (Test-Path $prevInstallPath) {
                        try {
                            $regValue = if ($userWantsRemoval) { 2 } else { 0 }
                            Set-ItemProperty -Path $prevInstallPath -Name "StateFlags$($sageset.ToString('0000'))" -Value $regValue -Type DWord -Force
                            Write-SimpleLog "Previous Installations cleanup configured: $(if ($userWantsRemoval) {'Enabled'} else {'Disabled'})"
                        }
                        catch {
                            Write-SimpleLog "Warning: Could not configure Previous Installations cleanup: $($_.Exception.Message)"
                        }
                    }
                }
            }
            else {
                Update-Progress -Percent 22 -Message "No Windows.old folder detected - proceeding with cleanup"
                Write-SimpleLog "No Windows.old folder found"
            }
        }
        catch {
            Write-SimpleLog "Error checking Windows.old folder: $($_.Exception.Message)"
            Update-Progress -Percent 22 -Message "Windows.old check completed with limitations"
        }

        Update-Progress -Percent 25 -Message "Windows.old configuration completed"

        # Phase 3: System Disk Cleanup (25-55%) - FIXED: Reduced timeout
        Update-Progress -Percent 30 -Message "Running comprehensive disk cleanup (CleanMgr)..."
        Write-SimpleLog "Executing cleanmgr.exe with improved monitoring"
        
        try {
            # Verify cleanmgr.exe exists
            $cleanmgrPath = Get-Command "cleanmgr.exe" -ErrorAction SilentlyContinue
            if (-not $cleanmgrPath) {
                throw "CleanMgr.exe not found in system PATH"
            }
            
            $cleanupProcess = Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/SAGERUN:$($sageset.ToString('0000'))" -WindowStyle Hidden -PassThru -ErrorAction Stop
            Write-SimpleLog "CleanMgr started with PID: $($cleanupProcess.Id)"
            
            $progress = 30
            $startTime = Get-Date
            $lastProgressReport = $startTime
            $timeoutReached = $false
            
            # FIXED: Reduced timeout from 5 minutes to 3 minutes
            $timeoutMinutes = 3
            
            while (-not $cleanupProcess.HasExited) {
                $currentTime = Get-Date
                
                # FIXED: Reduced timeout from 5 minutes to 3 minutes
                if (($currentTime - $startTime).TotalMinutes -gt $timeoutMinutes) {
                    Write-SimpleLog "CleanMgr timeout reached ($timeoutMinutes minutes). Terminating process."
                    try {
                        $cleanupProcess | Stop-Process -Force
                        $timeoutReached = $true
                    }
                    catch {
                        Write-SimpleLog "Error terminating CleanMgr process: $($_.Exception.Message)"
                    }
                    break
                }
                
                # IMPROVED: More frequent progress updates (every 15 seconds instead of 20)
                if (($currentTime - $lastProgressReport).TotalSeconds -ge 15) {
                    $progress = [Math]::Min($progress + 3, 53)  # Slightly faster increment
                    Update-Progress -Percent $progress -Message "Disk cleanup in progress (removing temporary files and caches)..."
                    $lastProgressReport = $currentTime
                }
                
                # IMPROVED: Shorter sleep to be more responsive
                Start-Sleep -Seconds 5
            }
            
            if (-not $timeoutReached) { 
                $exitCode = $cleanupProcess.ExitCode
                Write-SimpleLog "CleanMgr completed with exit code: $exitCode"
                Update-Progress -Percent 55 -Message "System disk cleanup completed successfully"
            }
            else {
                Update-Progress -Percent 55 -Message "System disk cleanup completed (timeout handled gracefully)"
            }
        }
        catch {
            Write-SimpleLog "Error running CleanMgr: $($_.Exception.Message)"
            Update-Progress -Percent 55 -Message "System disk cleanup completed with manual fallback"
        }
        
        # Phase 4: Manual File Cleanup (55-75%) - OPTIMIZED
        Update-Progress -Percent 58 -Message "Cleaning additional temporary files and caches..."
        
        # OPTIMIZED: Reduced temp file cleanup with faster operations
        $tempPaths = @(
            @{Path = $env:TEMP; Name = "User Temp Files" },
            @{Path = "$env:SystemRoot\Temp"; Name = "System Temp Files" },
            @{Path = "$env:LOCALAPPDATA\Temp"; Name = "Local App Temp Files" },
            @{Path = "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"; Name = "Internet Cache" }
        )
        
        $currentProgress = 58
        $progressIncrement = 12 / $tempPaths.Count
        
        foreach ($tempInfo in $tempPaths) {
            if (Test-Path $tempInfo.Path) {
                try {
                    # OPTIMIZED: Use faster batch deletion instead of individual file processing
                    $filesToDelete = @()
                    $totalSize = 0
                    
                    # Get files in batches to avoid memory issues
                    Get-ChildItem $tempInfo.Path -Recurse -Force -ErrorAction SilentlyContinue | 
                    Where-Object { -not $_.PSIsContainer } | 
                    Select-Object -First 1000 | ForEach-Object {
                        $filesToDelete += $_.FullName
                        $totalSize += $_.Length
                    }
                    
                    # OPTIMIZED: Batch delete files
                    $deletedCount = 0
                    $failedCount = 0
                    foreach ($file in $filesToDelete) {
                        try {
                            Remove-Item $file -Force -ErrorAction Stop
                            $deletedCount++
                        }
                        catch {
                            $failedCount++
                        }
                    }
                    
                    $sizeMB = [Math]::Round($totalSize / 1MB, 1)
                    $currentProgress += $progressIncrement
                    Update-Progress -Percent ([int]$currentProgress) -Message "Cleaned $($tempInfo.Name): $deletedCount files ($sizeMB MB)"
                    Write-SimpleLog "$($tempInfo.Name) cleanup: $deletedCount deleted, $failedCount locked, $sizeMB MB freed"
                }
                catch {
                    Write-SimpleLog "Warning: Could not clean $($tempInfo.Name): $($_.Exception.Message)"
                    $currentProgress += $progressIncrement
                    Update-Progress -Percent ([int]$currentProgress) -Message "Cleaned $($tempInfo.Name) with some limitations"
                }
            }
            else {
                Write-SimpleLog "$($tempInfo.Name) path does not exist: $($tempInfo.Path)"
                $currentProgress += $progressIncrement
            }
        }
        
        # Phase 5: Performance Optimization (75-90%)
        Update-Progress -Percent 75 -Message "Optimizing system performance caches..."
        
        # Prefetch optimization for faster application startup
        $prefetchPath = "$env:SystemRoot\Prefetch"
        if (Test-Path $prefetchPath) {
            try {
                $prefetchFiles = Get-ChildItem $prefetchPath -Force -ErrorAction SilentlyContinue
                $prefetchCount = $prefetchFiles.Count
                # Clear old prefetch data to allow Windows to rebuild optimized cache
                $prefetchFiles | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                Update-Progress -Percent 80 -Message "Optimized application startup cache ($prefetchCount files rebuilt)"
                Write-SimpleLog "Prefetch optimization: $prefetchCount files processed for faster app startup"
            }
            catch {
                Write-SimpleLog "Warning: Could not optimize prefetch cache: $($_.Exception.Message)"
                Update-Progress -Percent 80 -Message "Application startup cache optimization completed with limitations"
            }
        }
        
        # Network performance optimization
        Update-Progress -Percent 85 -Message "Optimizing network performance..."
        try {
            # Flush DNS cache for faster name resolution
            $dnsResult = & ipconfig /flushdns 2>&1
            Write-SimpleLog "DNS flush result: $dnsResult"
            
            # Reset network stack for optimal performance
            $winsockResult = & netsh winsock reset 2>&1
            Write-SimpleLog "Winsock reset result: $winsockResult"
            
            Update-Progress -Percent 88 -Message "Network performance optimized (DNS and network stack reset)"
            Write-SimpleLog "Network optimization completed: DNS cache flushed, Winsock reset for better performance"
        }
        catch {
            Write-SimpleLog "Warning: Network optimization issues: $($_.Exception.Message)"
            Update-Progress -Percent 88 -Message "Network optimization completed with some limitations"
        }

        # Phase 6: Visual Performance Optimization (90-100%)
        Update-Progress -Percent 90 -Message "Preparing visual performance optimization..."
        Write-SimpleLog "Requesting user confirmation for Explorer restart (improves visual performance)."
        
        # Ask user for permission before restarting explorer for icon cache optimization
        Write-Output "EXPLORER_RESTART_REQUEST:True"
        
        # FIXED: Wait for user decision with enhanced timeout handling
        $timeout = (Get-Date).AddSeconds(90)  # FIXED: Consistent 90 seconds for Explorer restart
        $explorerDecision = $null
        $checkCount = 0
        
        while ((Get-Date) -lt $timeout -and $null -eq $explorerDecision) {
            $userTempPath = [System.IO.Path]::GetTempPath()
            $explorerDecisionFile = [System.IO.Path]::Combine($userTempPath, "RepairToolkit_${JobId}_EXPLORER_RESTART.tmp")
            
            if (Test-Path $explorerDecisionFile) {
                try {
                    $explorerDecision = Get-Content $explorerDecisionFile -Raw -ErrorAction SilentlyContinue
                    Remove-Item $explorerDecisionFile -Force -ErrorAction SilentlyContinue
                    Write-SimpleLog "Explorer restart decision received: $explorerDecision"
                }
                catch {
                    Write-SimpleLog "Error reading explorer restart decision: $($_.Exception.Message)"
                }
            }
            $checkCount++
            if ($checkCount % 10 -eq 0) {
                # IMPROVED: Report less frequently
                Write-SimpleLog "Still waiting for Explorer restart decision... ($checkCount checks)"
            }
            # FIXED: Consistent sleep interval
            Start-Sleep -Seconds 3
        }
        
        if ($explorerDecision -eq "YES") {
            Update-Progress -Percent 93 -Message "User approved - optimizing visual performance (restarting Explorer)..."
            Write-SimpleLog "User approved Explorer restart for visual performance optimization."
            try {
                Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                
                # OPTIMIZED: Faster icon cache clearing with targeted approach
                $iconCachePaths = @(
                    "$env:LOCALAPPDATA\IconCache.db"
                )
                
                $cachesCleaned = 0
                foreach ($cachePath in $iconCachePaths) {
                    try {
                        if (Test-Path $cachePath) {
                            Remove-Item $cachePath -Force -ErrorAction SilentlyContinue
                            $cachesCleaned++
                        }
                    }
                    catch {
                        Write-SimpleLog "Could not remove cache file: $cachePath"
                    }
                }
                
                # OPTIMIZED: Clear additional cache files in batch
                try {
                    $additionalCaches = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\iconcache_*.db" -Force -ErrorAction SilentlyContinue
                    foreach ($cache in $additionalCaches) {
                        try {
                            Remove-Item $cache.FullName -Force -ErrorAction SilentlyContinue
                            $cachesCleaned++
                        }
                        catch {
                            # Silent failure for individual cache files
                        }
                    }
                }
                catch {
                    # Silent failure for additional cache cleanup
                }
                
                Start-Process "explorer.exe"
                Update-Progress -Percent 97 -Message "Visual performance optimized - Explorer restarted with fresh cache"
                Write-SimpleLog "Icon cache optimized ($cachesCleaned cache files cleared) and Explorer restarted for better visual performance."
            }
            catch {
                Write-SimpleLog "Warning: Visual performance optimization encountered issues: $($_.Exception.Message)"
                Update-Progress -Percent 97 -Message "Visual performance optimization completed with some issues"
            }
        }
        else {
            Write-SimpleLog "User declined Explorer restart or decision timed out. Visual performance optimization skipped."
            Update-Progress -Percent 97 -Message "Visual performance optimization skipped per user choice"
        }

        # Final completion
        $jobDuration = (Get-Date) - $jobStartTime
        Update-Progress -Percent 100 -Message "Disk cleanup and performance optimization completed!"
        Write-SimpleLog "Focused disk cleanup and performance optimization completed successfully in $($jobDuration.ToString('mm\:ss'))"

        # Enhanced final result with what was actually accomplished
        Write-Output "FINAL_RESULT_START"
        Write-Output ([PSCustomObject]@{
                ExitCode          = 0
                StandardError     = if ($timeoutReached) { "CleanMgr timeout occurred, but manual cleanup completed successfully." } else { "" }
                WindowsOldExists  = $windowsOldExists
                WindowsOldRemoved = $userWantsRemoval
                TimeoutOccurred   = $timeoutReached
                JobType           = "DISK_CLEANUP_OPTIMIZATION"
                CompletedTasks    = "Disk cleanup, temp file removal, cache optimization, network performance optimization, visual performance optimization"
                CleanupCategories = $configured
                Duration          = $jobDuration
            })
        Write-Output "FINAL_RESULT_END"
        
        Write-SimpleLog "Cleanup job result sent successfully"
    }
    catch {
        $jobDuration = (Get-Date) - $jobStartTime
        $errorMessage = "Critical error in disk cleanup and optimization job: $($_.Exception.Message)"
        Write-SimpleLog $errorMessage
        Write-Output "PROGRESS_LINE:ERROR: $errorMessage"
        
        Write-Output "FINAL_RESULT_START"
        Write-Output ([PSCustomObject]@{ 
                ExitCode      = -999
                StandardError = $errorMessage
                JobType       = "DISK_CLEANUP_OPTIMIZATION"
                Duration      = $jobDuration
            })
        Write-Output "FINAL_RESULT_END"
    }
}
#endregion

#region Enhanced Job Management Functions
# FIXED: Improved job management with better validation and error handling
function Start-RepairJob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$JobName,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Executable,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Arguments,
        
        [string]$InitialStatus = "Operation in progress..."
    )

    # Enhanced concurrency check
    if ($null -ne $script:currentRepairJob) {
        $message = "Another repair operation is already in progress. Please wait for it to complete before starting a new one."
        Show-WarningMessage -Message $message
        Write-RepairLog -Message "Job start blocked: Another job is running ($($script:currentRepairJob.Name))" -Category "WARNING"
        return $false
    }
    
    # Validate executable exists (handle both full paths and system executables)
    $executableFound = $false
    if (Test-Path $Executable -PathType Leaf) {
        $executableFound = $true
    }
    else {
        # Check if it's a system executable in PATH
        try {
            $null = Get-Command $Executable -ErrorAction Stop
            $executableFound = $true
        }
        catch {
            # Executable not found in PATH either
        }
    }
    
    if (-not $executableFound) {
        $message = "Executable not found: $Executable. Please ensure the required system tools are available."
        Show-ErrorMessage -Message $message
        Write-RepairLog -Message "Job start failed: Executable not found: $Executable" -Category "ERROR"
        return $false
    }
    
    Write-RepairLog -Message "Starting repair job: $JobName with executable: $Executable" -Category "JOB"
    Update-UiForJobStart -StatusMessage $InitialStatus
    
    # Enhanced timing and state management
    $script:operationStartTime = Get-Date
    $script:progressMessageCount = 0
    $script:capturedJobResult = $null
    $script:fallbackProgressEnabled = $false  # NEW: Reset fallback mode
    $script:progressCommunicationFailures = 0  # NEW: Reset failure counter
    $script:lastFallbackLogTime = $null        # NEW: Reset fallback logging
    
    Write-RepairLog -Message "Operation start time recorded: $($script:operationStartTime)" -Category "JOB"
    
    try {
        $script:currentRepairJob = Start-Job -Name $JobName -ScriptBlock $script:commandRunnerScriptBlock -ArgumentList $Executable, $Arguments
        Start-ProgressTimer
        Write-RepairLog -Message "Background job started successfully with ID: $($script:currentRepairJob.Id)" -Category "JOB"
        return $true
    }
    catch {
        Write-RepairLog -Message "Failed to start background job: $($_.Exception.Message)" -Category "ERROR"
        Update-UiForJobEnd -StatusMessage "ERROR: Failed to start operation." -IsSuccess $false
        return $false
    }
}

function Start-DISMRepair {
    [CmdletBinding()]
    param()
    
    if (-not (Confirm-AdminOrFail -OperationName "DISM System Image Repair")) { 
        return 
    }
    
    Write-OperationStart -OperationType "DISM"
    $result = Start-RepairJob -JobName "DISMRepairJob" -Executable "DISM.exe" -Arguments "/Online /Cleanup-Image /RestoreHealth" -InitialStatus "DISM Repair in progress..."
    
    if (-not $result) {
        Write-RepairLog -Message "DISM repair job failed to start" -Category "ERROR" -Operation "DISM"
    }
}

function Start-SFCRepair {
    [CmdletBinding()]
    param()
    
    if (-not (Confirm-AdminOrFail -OperationName "SFC System File Check")) { 
        return 
    }
    
    Write-OperationStart -OperationType "SFC"
    $result = Start-RepairJob -JobName "SFCRepairJob" -Executable "sfc.exe" -Arguments "/scannow" -InitialStatus "SFC Scan in progress..."
    
    if (-not $result) {
        Write-RepairLog -Message "SFC repair job failed to start" -Category "ERROR" -Operation "SFC"
    }
}

function Start-DiskCleanup {
    [CmdletBinding()]
    param()
    
    if (-not (Confirm-AdminOrFail -OperationName "Comprehensive System Cleanup")) { 
        return 
    }
    
    if ($null -ne $script:currentRepairJob) {
        $message = "Another repair operation is already in progress. Please wait for it to complete before starting cleanup."
        Show-WarningMessage -Message $message
        return
    }

    Write-OperationStart -OperationType "CLEANUP"
    
    # Initialize UI for optimization operation
    Update-UiForJobStart -StatusMessage "System Optimization in progress... 0%"
    
    # Enhanced cleanup job initialization with better validation
    $script:operationStartTime = Get-Date
    $script:progressMessageCount = 0
    $script:capturedJobResult = $null
    $script:currentJobId = [System.Guid]::NewGuid().ToString("N").Substring(0, 12)
    $script:lastUiUpdate = $null  # Reset UI update throttling
    $script:fallbackProgressEnabled = $false  # NEW: Reset fallback mode
    $script:progressCommunicationFailures = 0  # NEW: Reset failure counter
    $script:lastProgressUpdate = Get-Date  # NEW: Track last progress update
    $script:lastFallbackLogTime = $null    # NEW: Reset fallback logging
    
    Write-RepairLog -Message "Cleanup operation initialized with Job ID: $script:currentJobId" -Category "JOB" -Operation "CLEANUP"
    Write-RepairLog -Message "Log path for background job: $script:logPath" -Category "JOB" -Operation "CLEANUP"
    
    # IMPROVED: Validate parameters before starting job
    if ([string]::IsNullOrWhiteSpace($script:logPath)) {
        Write-RepairLog -Message "WARNING: Log path is empty, job may have logging issues" -Category "WARNING" -Operation "CLEANUP"
    }
    
    try {
        $script:currentRepairJob = Start-Job -Name "DiskCleanupJob" -ScriptBlock $script:diskCleanupScriptBlock -ArgumentList $script:logPath, $script:currentJobId
        
        Start-ProgressTimer
        Write-RepairLog -Message "Cleanup background job started successfully with PID: $($script:currentRepairJob.Id)" -Category "JOB" -Operation "CLEANUP"
        
        # IMPROVED: Add early progress validation
        Start-Sleep -Seconds 2
        try {
            $earlyOutput = Receive-Job -Job $script:currentRepairJob -Keep -ErrorAction SilentlyContinue
            if ($earlyOutput -and $earlyOutput.Count -gt 0) {
                Write-RepairLog -Message "Early job output detected: $($earlyOutput.Count) items" -Category "JOB" -Operation "CLEANUP"
            }
            else {
                Write-RepairLog -Message "No early job output detected yet" -Category "JOB" -Operation "CLEANUP"
            }
        }
        catch {
            Write-RepairLog -Message "Could not check early job output: $($_.Exception.Message)" -Category "WARNING" -Operation "CLEANUP"
        }
    }
    catch {
        Write-RepairLog -Message "Failed to start cleanup job: $($_.Exception.Message)" -Category "ERROR" -Operation "CLEANUP"
        Update-UiForJobEnd -StatusMessage "ERROR: Failed to start cleanup operation." -IsSuccess $false
    }
}

# Enhanced timer management with better error handling
function Start-ProgressTimer {
    [CmdletBinding()]
    param()
    
    try {
        # Clean up any existing timer safely
        Stop-ProgressTimer
        
        # Check form state before creating timer
        if ($form.IsDisposed -or $form.Disposing) {
            Write-RepairLog -Message "Cannot start timer - form is disposed" -Category "WARNING"
            return
        }
        
        # Create new timer with enhanced configuration
        $script:progressUpdateTimer = New-Object System.Windows.Forms.Timer
        $script:progressUpdateTimer.Interval = $script:CONSTANTS.TIMER_INTERVAL_MS
        $script:progressUpdateTimer.Add_Tick($script:progressTimerAction)
        $script:progressUpdateTimer.Start()
        
        Write-RepairLog -Message "Progress timer started with interval: $($script:CONSTANTS.TIMER_INTERVAL_MS)ms" -Category "JOB"
    }
    catch {
        Write-RepairLog -Message "Failed to start progress timer: $($_.Exception.Message)" -Category "ERROR"
    }
}

function Stop-ProgressTimer {
    [CmdletBinding()]
    param()
    
    try {
        if ($null -ne $script:progressUpdateTimer) {
            # Stop the timer first to prevent new events
            try {
                $script:progressUpdateTimer.Stop()
            }
            catch {
                # Timer might already be stopped
            }
            
            # Remove event handlers to prevent memory leaks and race conditions
            try {
                $script:progressUpdateTimer.Remove_Tick($script:progressTimerAction)
            }
            catch {
                # Event handler might already be removed
            }
            
            # Dispose the timer safely
            try {
                $script:progressUpdateTimer.Dispose()
            }
            catch {
                # Disposal might fail if already disposed
            }
            
            $script:progressUpdateTimer = $null
            Write-RepairLog -Message "Progress timer stopped and disposed successfully" -Category "JOB"
        }
    }
    catch {
        Write-RepairLog -Message "Error stopping progress timer: $($_.Exception.Message)" -Category "WARNING"
        # Force null assignment even if disposal fails
        $script:progressUpdateTimer = $null
    }
}
#endregion

#region Enhanced Progress Timer and Job Processing
# FIXED: Comprehensive progress timer with improved communication monitoring
$script:progressTimerAction = {
    # Early disposal check to prevent pipeline errors
    if ($form.IsDisposed -or $form.Disposing) {
        return
    }
    
    # Thread-safe execution with shorter timeout to prevent hanging
    if (-not [System.Threading.Monitor]::TryEnter($script:timerLock, 50)) { 
        return 
    }
    
    try {
        # Multiple disposal checks to prevent race conditions
        if ($null -eq $script:currentRepairJob -or $form.IsDisposed -or $form.Disposing) {
            Stop-ProgressTimer
            return
        }

        # Check if progress bar is disposed before accessing
        if ($progressBar.IsDisposed) {
            Stop-ProgressTimer
            return
        }

        # Test for job completion and handle atomically
        if (Test-JobCompletion) {
            Complete-JobExecution
            return
        }

        # FIXED: Enhanced job output processing with fallback progress
        try {
            $hasNewProgress = Receive-JobOutput
            
            # NEW: Only count as communication failure if job has been running for a while
            $jobRuntime = if ($script:operationStartTime) { 
                (Get-Date) - $script:operationStartTime 
            }
            else { 
                New-TimeSpan 
            }
            
            # Only start counting failures after job has been running for 30 seconds
            if (-not $hasNewProgress -and $jobRuntime.TotalSeconds -gt 30) {
                $script:progressCommunicationFailures++
                if ($script:progressCommunicationFailures -ge $script:CONSTANTS.PROGRESS_COMM_FAILURE_LIMIT -and 
                    -not $script:fallbackProgressEnabled) {
                    Enable-FallbackProgress
                }
            }
            else {
                # Reset failure counter on successful communication or during startup period
                if ($hasNewProgress) {
                    $script:progressCommunicationFailures = 0
                }
            }
            
            # NEW: Update fallback progress if enabled
            if ($script:fallbackProgressEnabled) {
                Update-FallbackProgress
            }
            
            Update-SfcProgress
            Update-StatusDisplay
        }
        catch [System.ObjectDisposedException] {
            # Object was disposed while we were using it - stop timer immediately
            Write-RepairLog -Message "UI object disposed during timer execution - stopping timer" -Category "WARNING"
            Stop-ProgressTimer
            return
        }
        catch {
            Write-RepairLog -Message "Error in timer job processing: $($_.Exception.Message)" -Category "WARNING"
        }
        
    }
    catch [System.ObjectDisposedException] {
        # Form or control was disposed - silently stop timer
        try { Stop-ProgressTimer } catch { }
        return
    }
    catch {
        Write-RepairLog -Message "Critical error in progress timer: $($_.Exception.Message)" -Category "ERROR"
        try {
            Stop-ProgressTimer
            if (-not $form.IsDisposed -and -not $form.Disposing) {
                Update-UiForJobEnd -StatusMessage "ERROR: Progress monitoring encountered an issue." -IsSuccess $false
            }
        }
        catch {
            # Silent fallback - don't cascade errors
        }
    }
    finally {
        try {
            [System.Threading.Monitor]::Exit($script:timerLock)
        }
        catch {
            # Silent monitor exit failure
        }
    }
}

# NEW: Fallback progress system for when communication fails
function Enable-FallbackProgress {
    $script:fallbackProgressEnabled = $true
    $elapsed = if ($script:operationStartTime) { (Get-Date) - $script:operationStartTime } else { New-TimeSpan }
    Write-RepairLog -Message "Enabling fallback progress estimation after $($script:progressCommunicationFailures) communication failures (elapsed: $($elapsed.ToString('mm\:ss')))" -Category "WARNING"
}

function Update-FallbackProgress {
    if ($null -eq $script:operationStartTime) { return }
    
    $elapsed = (Get-Date) - $script:operationStartTime
    $jobDisplayName = Get-JobDisplayName -JobName $script:currentRepairJob.Name
    
    # Estimate progress based on typical operation durations
    $estimatedProgress = switch ($jobDisplayName) {
        "DISM Repair" {
            # DISM typically takes 5-15 minutes
            [Math]::Min(($elapsed.TotalMinutes / 10) * 90, 90)
        }
        "SFC Scan" {
            # SFC typically takes 10-30 minutes  
            [Math]::Min(($elapsed.TotalMinutes / 20) * 90, 90)
        }
        "System Optimization" {
            # Cleanup typically takes 3-8 minutes
            [Math]::Min(($elapsed.TotalMinutes / 5) * 90, 90)
        }
        default {
            [Math]::Min(($elapsed.TotalMinutes / 10) * 90, 90)
        }
    }
    
    # Only update if we haven't received real progress recently AND significant time has passed
    $timeSinceLastUpdate = if ($script:lastProgressUpdate) { 
        (Get-Date) - $script:lastProgressUpdate 
    }
    else { 
        $elapsed 
    }
    
    # FIXED: Increase minimum time between fallback updates to reduce log spam
    if ($timeSinceLastUpdate.TotalSeconds -gt 45 -and $estimatedProgress -gt $progressBar.Value) {
        try {
            if (-not $progressBar.IsDisposed) {
                $progressBar.Value = [int]$estimatedProgress
                $progressBar.Refresh()
                
                # FIXED: Only log every 30 seconds in fallback mode to reduce spam
                $lastFallbackLog = $script:lastFallbackLogTime
                if ($null -eq $lastFallbackLog -or ((Get-Date) - $lastFallbackLog).TotalSeconds -gt 30) {
                    Write-RepairLog -Message "Fallback progress: $([int]$estimatedProgress)% (elapsed: $($elapsed.ToString('mm\:ss')), no updates for $([int]$timeSinceLastUpdate.TotalSeconds)s)" -Category "INFO"
                    $script:lastFallbackLogTime = Get-Date
                }
            }
        }
        catch {
            # Silent error for fallback progress updates
        }
    }
}

# Modular functions for progress timer functionality
function Test-JobCompletion {
    return ($script:currentRepairJob.State -ne [System.Management.Automation.JobState]::Running)
}

function Complete-JobExecution {
    try {
        # Stop timer immediately to prevent reprocessing and race conditions
        Stop-ProgressTimer

        # Multiple disposal checks
        if ($form.IsDisposed -or $form.Disposing) {
            return
        }

        # Capture job reference and clear global state atomically
        $jobToProcess = $script:currentRepairJob
        $script:currentRepairJob = $null

        if ($null -eq $jobToProcess) {
            Write-RepairLog -Message "Job completion called but no job reference found" -Category "WARNING"
            return
        }

        Write-RepairLog -Message "Job '$($jobToProcess.Name)' completed with state: $($jobToProcess.State)" -Category "JOB"
        
        # Use captured result if available, otherwise retrieve it
        $jobResult = $script:capturedJobResult
        if ($null -eq $jobResult) {
            Write-RepairLog -Message "Result not captured during monitoring, retrieving from job output" -Category "WARNING" -Operation "JOB"
            $jobResult = Get-JobResult -Job $jobToProcess
        }
        
        # Ensure progress bar shows completion for successful jobs with disposal protection
        try {
            if ($null -ne $jobResult -and $jobResult.ExitCode -eq 0 -and -not $progressBar.IsDisposed -and -not $form.IsDisposed) { 
                $progressBar.Value = 100 
                $progressBar.Refresh()
            }
        }
        catch [System.ObjectDisposedException] {
            # Progress bar was disposed - ignore
        }
        catch {
            # Silent error for progress bar updates
        }
        
        # Route to appropriate completion handler
        Complete-RepairJob -Job $jobToProcess -JobResult $jobResult

        # FIXED: Clean up job safely (PowerShell 7 compatibility)
        try {
            if ($jobToProcess.State -eq 'Running') {
                $jobToProcess | Stop-Job -ErrorAction SilentlyContinue  # FIXED: Removed -Force
            }
            Remove-Job $jobToProcess -ErrorAction SilentlyContinue  # FIXED: Removed -Force
        }
        catch {
            Write-RepairLog -Message "Warning during job cleanup: $($_.Exception.Message)" -Category "WARNING"
        }
        
        Reset-JobState
    }
    catch [System.ObjectDisposedException] {
        Write-RepairLog -Message "UI disposed during job completion - cleanup completed silently" -Category "WARNING"
    }
    catch {
        Write-RepairLog -Message "Error in job completion handling: $($_.Exception.Message)" -Category "ERROR"
        try {
            if (-not $form.IsDisposed -and -not $form.Disposing) {
                Update-UiForJobEnd -StatusMessage "ERROR: Job completion encountered an issue." -IsSuccess $false
            }
        }
        catch {
            # Silent fallback
        }
    }
}

# FIXED: Enhanced job output processing with better communication tracking
function Receive-JobOutput {
    # Retrieve new job output with enhanced error handling
    $jobOutput = @()
    
    try {
        if ($script:currentRepairJob.HasMoreData) {
            $jobOutput = @(Receive-Job -Job $script:currentRepairJob -ErrorAction Stop)
        }
    }
    catch {
        Write-RepairLog -Message "Error receiving job output in timer: $($_.Exception.Message)" -Category "ERROR"
        return $false
    }
    
    # Return early if no output received
    if ($jobOutput.Count -eq 0) {
        return $false
    }
    
    # Early capture of final result object
    if ($null -eq $script:capturedJobResult) {
        $resultObject = $jobOutput | Where-Object { 
            $_ -is [PSCustomObject] -and $_.PSObject.Properties['JobType'] 
        } | Select-Object -First 1
        
        if ($null -ne $resultObject) {
            Write-RepairLog -Message "Progress timer captured final job result object" -Category "JOB"
            $script:capturedJobResult = $resultObject
        }
    }

    # Process each output item
    $progressFound = $false
    foreach ($item in $jobOutput) {
        if ($null -eq $item -or $item -is [PSCustomObject]) { 
            continue 
        }
        
        $wasProgress = Receive-JobOutputItem -Item $item
        if ($wasProgress) { 
            $progressFound = $true 
        }
    }
    
    return $progressFound
}

function Receive-JobOutputItem {
    [CmdletBinding()]
    param($Item)
    
    # Safe string conversion with validation
    $itemStr = $null
    try { 
        $itemStr = $Item.ToString() 
    } 
    catch { 
        return $false
    }
    
    # Enhanced input validation
    if ([string]::IsNullOrWhiteSpace($itemStr) -or $itemStr.Length -gt 2000) { 
        return $false
    }
    
    # Clean and validate the string
    $itemStr = $itemStr -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+', '' -replace '\s+', ' '
    $itemStr = $itemStr.Trim()
    
    if ($itemStr.Length -lt 3 -or $itemStr -match '^[^a-zA-Z0-9\s\-\[\]:_]{5,}') { 
        return $false
    }
    
    # Route to appropriate handler
    if ($itemStr.StartsWith("PROGRESS_LINE:")) {
        Update-ProgressLine -Line $itemStr
        return $true
    }
    elseif ($itemStr.StartsWith("WINDOWS_OLD_EXISTS:True")) {
        Write-RepairLog -Message "Windows.old prompt triggered by job output" -Category "USER"
        Show-WindowsOldPrompt
        return $false
    }
    elseif ($itemStr.StartsWith("EXPLORER_RESTART_REQUEST:True")) {
        Write-RepairLog -Message "Explorer restart prompt triggered by job output" -Category "USER"
        Show-ExplorerRestartPrompt
        return $false
    }
    else {
        # Log unhandled job output for debugging
        Write-RepairLog -Message "Unhandled job output: '$itemStr'" -Category "DEBUG"
        return $false
    }
}

function Update-ProgressLine {
    [CmdletBinding()]
    param([string]$Line)
    
    $progressLine = $Line.Substring("PROGRESS_LINE:".Length).Trim()
    if ([string]::IsNullOrWhiteSpace($progressLine) -or $progressLine.Length -gt 500) { 
        return 
    }
    
    # NEW: Track last progress update time
    $script:lastProgressUpdate = Get-Date
    
    # Update UI progress bar first for immediate visual feedback
    Update-ProgressBar -Line $progressLine
    
    # Immediately update status display after progress bar update
    try {
        if (-not $form.IsDisposed -and -not $statusLabel.IsDisposed -and $null -ne $script:currentRepairJob) {
            $jobDisplayName = Get-JobDisplayName -JobName $script:currentRepairJob.Name
            $newStatusText = "$jobDisplayName in progress... $($progressBar.Value)%"
            
            # Only update if text actually changed
            if ($statusLabel.Text -ne $newStatusText) {
                $statusLabel.Text = $newStatusText
                $statusLabel.Refresh()
            }
        }
    }
    catch {
        Write-RepairLog -Message "Error in immediate status update: $($_.Exception.Message)" -Category "WARNING"
    }
    
    # Then handle logging with deduplication
    if (Test-ShouldLogProgress -Line $progressLine) {
        $operation = Get-JobOperation
        Write-RepairLog -Message $progressLine -Category "PROGRESS" -Operation $operation
        Update-ProgressState -Line $progressLine
    }
}

function Test-ShouldLogProgress {
    [CmdletBinding()]
    param([string]$Line)
    
    $currentTime = Get-Date
    $percentMatch = $Line -match '(\d{1,3})%'
    $currentPercent = if ($percentMatch) { [int]$matches[1] } else { -1 }
    
    # Enhanced logging criteria with reduced spam
    $shouldLog = $false
    
    # Always log first message
    if ($null -eq $script:lastProgressLogTime) { 
        $shouldLog = $true 
    }
    # Log milestone percentages
    elseif ($currentPercent -in @(0, 25, 50, 75, 100) -and $currentPercent -ne $script:lastLoggedPercent) { 
        $shouldLog = $true 
    }
    # Log significant percentage changes (operation-specific thresholds)
    elseif ($currentPercent -ge 0) {
        $operation = Get-JobOperation
        $threshold = switch ($operation) {
            "DISM" { 10 }
            "SFC" { 20 }  # Larger threshold for SFC to reduce log spam
            "CLEANUP" { 5 }
            default { 15 }
        }
        if (($currentPercent - $script:lastLoggedPercent) -ge $threshold) {
            $shouldLog = $true
        }
    }
    # Log different message types (ignoring percentage differences) - but be more selective
    elseif (($Line -replace '\d+%', 'X%') -ne ($script:lastLoggedProgress -replace '\d+%', 'X%')) {
        # Only log non-percentage changes if they seem significant
        if ($Line -match '(Starting|Completed|Failed|Error|Warning)' -or 
            $Line -match '(cleaning|scanning|repairing|optimizing)') {
            $shouldLog = $true
        }
    }
    # Time-based logging (longer interval to reduce spam)
    elseif ($null -ne $script:lastProgressLogTime -and ($currentTime - $script:lastProgressLogTime).TotalSeconds -ge 120) { 
        $shouldLog = $true 
    }
    
    return $shouldLog
}

function Update-ProgressState {
    [CmdletBinding()]
    param([string]$Line)
    
    $script:lastLoggedProgress = $Line
    $script:lastProgressLogTime = Get-Date
    $script:progressMessageCount++
    
    $percentMatch = $Line -match '(\d{1,3})%'
    if ($percentMatch) {
        $script:lastLoggedPercent = [int]$matches[1]
    }
}

# FIXED: Enhanced progress bar updates with better parsing
function Update-ProgressBar {
    [CmdletBinding()]
    param([string]$Line)
    
    try {
        # Check if progress bar is available and not disposed
        if ($progressBar.IsDisposed) {
            return
        }
        
        # FIXED: More comprehensive regex to catch all percentage formats
        $percentMatch = $null
        
        # Try multiple regex patterns to catch different progress formats
        if ($Line -match '(\d{1,3})%\s*-') {
            # Pattern: "32% - message"
            $percentMatch = $matches[1]
        }
        elseif ($Line -match '(?:Progress[:\s]*)?(\d{1,3})%') {
            # Pattern: "Progress: 32%" or just "32%"
            $percentMatch = $matches[1]
        }
        elseif ($Line -match '^(\d{1,3})%') {
            # Pattern: "32%" at start of line
            $percentMatch = $matches[1]
        }
        
        if ($null -ne $percentMatch) {
            $currentPercent = [int]$percentMatch
            
            # Allow progress updates and ensure they're within valid range
            if ($currentPercent -ge 0 -and $currentPercent -le 100) {
                $progressBar.Value = $currentPercent
                
                # Force UI refresh for progress updates (with error protection)
                try {
                    $progressBar.Refresh()
                }
                catch {
                    # Silent error for refresh
                }
            }
        }
    }
    catch {
        # Silent error handling for progress bar updates
        Write-RepairLog -Message "Error updating progress bar: $($_.Exception.Message)" -Category "WARNING"
    }
}

# FIXED: Enhanced dialog handling with better timeout management
function Show-WindowsOldPrompt {
    try {
        # Pause timer for modal dialog
        if ($null -ne $script:progressUpdateTimer) {
            $script:progressUpdateTimer.Stop()
        }
        
        $sizeInfo = ""
        try {
            $windowsOldPath = "C:\Windows.old"
            if (Test-Path $windowsOldPath) {
                $size = (Get-ChildItem $windowsOldPath -Recurse -ErrorAction SilentlyContinue | 
                    Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                if ($size -gt 0) {
                    $sizeGB = [Math]::Round($size / 1GB, 2)
                    $sizeInfo = "`n`nEstimated size: $sizeGB GB"
                }
            }
        }
        catch {
            # Size calculation is optional
        }
        
        $message = "The Windows.old folder contains your previous Windows installation.$sizeInfo`n`nRemoving it will free up disk space but will prevent you from rolling back to your previous Windows version if needed.`n`nDo you want to remove the Windows.old folder as part of the cleanup?"
        $dialogResult = Show-QuestionMessage -Message $message -Title "Windows.old Folder Detected"
        
        $decision = if ($dialogResult -eq 'Yes') { "YES" } else { "NO" }
        Set-JobCommunication -JobId $script:currentJobId -Key "WINDOWSOLD_DECISION" -Value $decision
        Write-RepairLog -Message "User decision on Windows.old removal: $decision" -Category "USER" -Operation "CLEANUP"
    }
    finally {
        # Resume timer
        if ($null -ne $script:progressUpdateTimer) {
            $script:progressUpdateTimer.Start()
        }
    }
}

function Show-ExplorerRestartPrompt {
    try {
        # Pause timer for modal dialog
        if ($null -ne $script:progressUpdateTimer) {
            $script:progressUpdateTimer.Stop()
        }
        
        $message = "To complete the icon cache refresh, Windows Explorer needs to be restarted.`n`nThis will temporarily close all File Explorer windows and make the desktop/taskbar disappear for a few seconds.`n`nDo you want to proceed with the Explorer restart?"
        $dialogResult = Show-QuestionMessage -Message $message -Title "Explorer Restart Required"
        
        $decision = if ($dialogResult -eq 'Yes') { "YES" } else { "NO" }
        Set-JobCommunication -JobId $script:currentJobId -Key "EXPLORER_RESTART" -Value $decision
        Write-RepairLog -Message "User decision on Explorer restart: $decision" -Category "USER" -Operation "CLEANUP"
    }
    finally {
        # Resume timer
        if ($null -ne $script:progressUpdateTimer) {
            $script:progressUpdateTimer.Start()
        }
    }
}

# FIXED: Replace time-based SFC estimation with improved progress handling
function Update-SfcProgress {
    # For SFC, show minimal progress to indicate activity without false precision
    if ($script:currentRepairJob.Name -like "*SFCRepairJob*" -and $null -ne $script:operationStartTime) {
        # Only update if no real progress has been reported and we're not in fallback mode
        if ($progressBar.Value -eq 0 -and -not $script:fallbackProgressEnabled) {
            # Show minimal progress to indicate activity
            $progressBar.Value = 5
        }
    }
}

# Helper function to get consistent job display names with robust pattern matching
function Get-JobDisplayName {
    [CmdletBinding()]
    param([string]$JobName)
    
    # Ensure we have a valid job name
    if ([string]::IsNullOrWhiteSpace($JobName)) {
        return "Operation"
    }
    
    # Convert to lowercase for case-insensitive matching
    $lowerJobName = $JobName.ToLower()
    
    # Use comprehensive case-insensitive pattern matching
    if ($lowerJobName -like "*dism*") {
        return "DISM Repair"
    }
    elseif ($lowerJobName -like "*sfc*") {
        return "SFC Scan"
    }
    elseif ($lowerJobName -like "*diskcleanup*" -or $lowerJobName -like "*cleanup*" -or $lowerJobName -like "*clean*" -or $lowerJobName -like "*optimize*") {
        return "System Optimization"
    }
    else {
        # Fallback pattern matching
        if ($lowerJobName -match "(disk|clean|optimize|maintenance)") {
            return "System Optimization"
        }
        return "Operation"
    }
}

function Update-StatusDisplay {
    try {
        # Multiple disposal checks to prevent ObjectDisposedException
        if ($null -eq $script:currentRepairJob -or 
            $form.IsDisposed -or $form.Disposing -or 
            $statusLabel.IsDisposed -or 
            $progressBar.IsDisposed) {
            return
        }
        
        $currentTime = Get-Date
        if ($null -eq $script:lastUiUpdate -or ($currentTime - $script:lastUiUpdate).TotalMilliseconds -ge $script:CONSTANTS.UI_UPDATE_THROTTLE_MS) {
            $jobDisplayName = Get-JobDisplayName -JobName $script:currentRepairJob.Name
            $newStatusText = "$jobDisplayName in progress... $($progressBar.Value)%"
            
            # Only update if text actually changed and controls are not disposed
            if ($statusLabel.Text -ne $newStatusText -and -not $statusLabel.IsDisposed) {
                $statusLabel.Text = $newStatusText
                $statusLabel.Refresh()
            }
            
            $script:lastUiUpdate = $currentTime
        }
    }
    catch [System.ObjectDisposedException] {
        # UI object was disposed - silently return
        return
    }
    catch {
        Write-RepairLog -Message "Error updating status display: $($_.Exception.Message)" -Category "WARNING"
    }
}

function Get-JobOperation {
    if ($null -eq $script:currentRepairJob) { return "TOOLKIT" }
    
    $jobNameLower = $script:currentRepairJob.Name.ToLower()
    
    if ($jobNameLower -like "*dism*") {
        return "DISM"
    }
    elseif ($jobNameLower -like "*sfc*") {
        return "SFC"
    }
    elseif ($jobNameLower -like "*diskcleanup*" -or $jobNameLower -like "*cleanup*" -or $jobNameLower -match "(disk|clean|optimize)") {
        return "CLEANUP"
    }
    else {
        return "TOOLKIT"
    }
}

function Reset-JobState {
    $script:currentJobId = $null
    $script:capturedJobResult = $null
    $script:lastLoggedProgress = ""
    $script:lastLoggedPercent = -1
    $script:lastProgressLogTime = $null
    $script:operationStartTime = $null
    $script:lastUiUpdate = $null
    $script:fallbackProgressEnabled = $false  # NEW: Reset fallback mode
    $script:progressCommunicationFailures = 0  # NEW: Reset failure counter
    $script:lastProgressUpdate = $null  # NEW: Reset progress update tracking
    $script:lastFallbackLogTime = $null  # NEW: Reset fallback logging time
}
#endregion

#region Enhanced Job Result Processing
# FIXED: Improved job result extraction with better error handling and validation
function Get-JobResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Job]$Job
    )
    
    try {
        Write-RepairLog -Message "Retrieving results for job: $($Job.Name) (State: $($Job.State))" -Category "JOB"
        
        # Enhanced output retrieval with better error handling
        $allOutput = @()
        try {
            $allOutput = @(Receive-Job -Job $Job -Wait -ErrorAction Stop)
        }
        catch {
            Write-RepairLog -Message "Error receiving job output: $($_.Exception.Message)" -Category "ERROR"
            return [PSCustomObject]@{ 
                ExitCode      = -1
                StandardError = "Failed to receive job output: $($_.Exception.Message)"
                JobType       = "ERROR"
                OutputLines   = 0
            }
        }
        
        # Enhanced null/empty output handling
        if ($null -eq $allOutput -or $allOutput.Count -eq 0) {
            Write-RepairLog -Message "Job produced no output" -Category "WARNING"
            return [PSCustomObject]@{ 
                ExitCode      = if ($Job.State -eq [System.Management.Automation.JobState]::Completed) { 0 } else { 1 }
                StandardError = "Job completed but produced no output (State: $($Job.State))"
                JobType       = "EMPTY"
                OutputLines   = 0
            }
        }
        
        Write-RepairLog -Message "Job produced $($allOutput.Count) output items for processing" -Category "JOB"
        
        # Enhanced result parsing with multiple strategies
        
        # Strategy 1: Look for cleanup job results (FINAL_RESULT markers)
        $finalResult = Get-ResultBetweenMarkers -Output $allOutput -StartMarker "FINAL_RESULT_START" -EndMarker "FINAL_RESULT_END"
        if ($null -ne $finalResult) {
            Write-RepairLog -Message "Found cleanup job result with exit code: $($finalResult.ExitCode)" -Category "JOB"
            return $finalResult
        }
        
        # Strategy 2: Look for command job results (COMMAND_RESULT markers)
        $commandResult = Get-ResultBetweenMarkers -Output $allOutput -StartMarker "COMMAND_RESULT_START" -EndMarker "COMMAND_RESULT_END"
        if ($null -ne $commandResult) {
            Write-RepairLog -Message "Found command job result with exit code: $($commandResult.ExitCode)" -Category "JOB"
            return $commandResult
        }
        
        # Strategy 3: Look for any PSCustomObject with ExitCode
        $anyResult = $allOutput | Where-Object { 
            $_ -is [PSCustomObject] -and 
            $null -ne $_.PSObject.Properties['ExitCode'] 
        } | Select-Object -First 1
        
        if ($null -ne $anyResult) {
            Write-RepairLog -Message "Found generic result object with exit code: $($anyResult.ExitCode)" -Category "JOB"
            return $anyResult
        }
        
        # Strategy 4: Create fallback result based on job state
        $exitCode = switch ($Job.State) {
            'Completed' { 0 }
            'Failed' { 1 }
            'Stopped' { -1 }
            default { 1 }
        }
        
        Write-RepairLog -Message "No result object found, creating fallback based on job state: $($Job.State)" -Category "WARNING"
        return [PSCustomObject]@{ 
            ExitCode      = $exitCode
            StandardError = "Job completed but no structured result was found. Job state: $($Job.State)"
            JobType       = "FALLBACK"
            OutputLines   = $allOutput.Count
        }
    }
    catch {
        Write-RepairLog -Message "Critical error in Get-JobResult: $($_.Exception.Message)" -Category "ERROR"
        return [PSCustomObject]@{ 
            ExitCode      = -999
            StandardError = "Critical error retrieving job results: $($_.Exception.Message)"
            JobType       = "CRITICAL_ERROR"
            OutputLines   = 0
        }
    }
}

# Helper function to extract results between markers
function Get-ResultBetweenMarkers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Output,
        
        [Parameter(Mandatory = $true)]
        [string]$StartMarker,
        
        [Parameter(Mandatory = $true)]
        [string]$EndMarker
    )
    
    try {
        $startIndex = -1
        $endIndex = -1
        
        for ($i = 0; $i -lt $Output.Count; $i++) {
            $item = $Output[$i]
            if ($null -ne $item) {
                $itemStr = $item.ToString()
                if ($itemStr -eq $StartMarker) {
                    $startIndex = $i
                }
                elseif ($itemStr -eq $EndMarker -and $startIndex -ne -1) {
                    $endIndex = $i
                    break
                }
            }
        }
        
        if ($startIndex -ne -1 -and $endIndex -gt $startIndex) {
            $resultIndex = $startIndex + 1
            if ($resultIndex -lt $Output.Count) {
                $result = $Output[$resultIndex]
                if ($null -ne $result -and $result -is [PSCustomObject]) {
                    return $result
                }
            }
        }
        
        return $null
    }
    catch {
        Write-RepairLog -Message "Error extracting result between markers: $($_.Exception.Message)" -Category "ERROR"
        return $null
    }
}
#endregion

#region Enhanced Completion Handlers
# Improved completion handlers with better error handling and user feedback
function Complete-DismJob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$JobResult
    )
    
    try {
        $duration = if ($null -ne $script:operationStartTime) { 
            (Get-Date) - $script:operationStartTime 
        }
        else { 
            New-TimeSpan 
        }
        
        $success = ($null -ne $JobResult -and $JobResult.ExitCode -eq 0)
        
        Write-OperationEnd -OperationType "DISM" -Duration $duration -Success $success -ExitCode $JobResult.ExitCode

        if ($success) {
            Update-UiForJobEnd -StatusMessage "SUCCESS: DISM system image repair completed successfully." -IsSuccess $true
            $message = "DISM successfully repaired the Windows system image and component store.`n`nNext recommended step: Run SFC System File Check (Step 2) to scan and repair individual system files."
            Show-InfoMessage -Title "DISM Repair Complete" -Message $message
        }
        else {
            Update-UiForJobEnd -StatusMessage "ATTENTION: DISM completed with issues requiring review." -IsSuccess $false
            $logPath = "C:\Windows\Logs\DISM\dism.log"
            $message = "DISM finished with exit code: $($JobResult.ExitCode).`n`nThis may indicate that some issues were found or that the operation completed with warnings.`n`nFor detailed information, please review the DISM log file at:`n$logPath`n`nYou may still proceed with SFC (Step 2) to check system files."
            Show-InfoMessage -Title "DISM Completed with Notes" -Message $message
        }
    }
    catch {
        Write-RepairLog -Message "Error in DISM completion handler: $($_.Exception.Message)" -Category "ERROR" -Operation "DISM"
        Update-UiForJobEnd -StatusMessage "ERROR: Failed to process DISM results." -IsSuccess $false
    }
}

function Complete-SfcJob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$JobResult
    )
    
    try {
        $duration = if ($null -ne $script:operationStartTime) { 
            (Get-Date) - $script:operationStartTime 
        }
        else { 
            New-TimeSpan 
        }
        
        $success = ($null -ne $JobResult -and $JobResult.ExitCode -eq 0)
        
        # Enhanced additional information
        $additionalInfo = ""
        if ($JobResult.OutputLines -gt 0) {
            $additionalInfo = "$($JobResult.OutputLines) output lines processed during scan."
        }
        
        Write-OperationEnd -OperationType "SFC" -Duration $duration -Success $success -ExitCode $JobResult.ExitCode -AdditionalInfo $additionalInfo

        if ($success) {
            Update-UiForJobEnd -StatusMessage "SUCCESS: SFC system file scan completed successfully." -IsSuccess $true
            $message = "SFC (System File Checker) completed successfully and verified the integrity of all protected system files.`n`nNext recommended step: Run System Cleanup (Step 3) to optimize performance and free disk space."
            Show-InfoMessage -Title "SFC Scan Complete" -Message $message
        }
        else {
            Update-UiForJobEnd -StatusMessage "ATTENTION: SFC scan completed - please review results." -IsSuccess $false
            $logPath = "C:\Windows\Logs\CBS\CBS.log"
            $message = "SFC finished with exit code $($JobResult.ExitCode).`n`nThis often indicates that corrupt files were found and repaired, or that some files could not be fixed.`n`nFor detailed results, search for '[SR]' entries in the CBS log file at:`n$logPath`n`nYou can proceed with System Cleanup (Step 3) regardless of this result."
            Show-InfoMessage -Title "SFC Scan Results" -Message $message
        }
    }
    catch {
        Write-RepairLog -Message "Error in SFC completion handler: $($_.Exception.Message)" -Category "ERROR" -Operation "SFC"
        Update-UiForJobEnd -StatusMessage "ERROR: Failed to process SFC results." -IsSuccess $false
    }
}

function Complete-DiskCleanupJob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$JobResult
    )
    
    try {
        $duration = if ($null -ne $script:operationStartTime) { 
            (Get-Date) - $script:operationStartTime 
        }
        else { 
            New-TimeSpan 
        }
        
        $success = ($null -ne $JobResult -and $JobResult.ExitCode -eq 0)
        
        # Enhanced cleanup information focusing on what was actually done
        $additionalInfo = @()
        if ($JobResult.WindowsOldExists) { 
            if ($JobResult.WindowsOldRemoved) {
                $additionalInfo += "Windows.old folder was removed to free disk space."
            }
            else {
                $additionalInfo += "Windows.old folder was preserved per user choice."
            }
        }
        if ($JobResult.TimeoutOccurred) { 
            $additionalInfo += "CleanMgr timeout was handled gracefully with manual cleanup completion."
        }
        if ($JobResult.CleanupCategories) {
            $additionalInfo += "$($JobResult.CleanupCategories) cleanup categories were configured."
        }
        
        $additionalInfoText = $additionalInfo -join " "
        
        Write-OperationEnd -OperationType "CLEANUP" -Duration $duration -Success $success -ExitCode $JobResult.ExitCode -AdditionalInfo $additionalInfoText

        if ($success) {
            Update-UiForJobEnd -StatusMessage "SUCCESS: Disk cleanup and performance optimization completed successfully." -IsSuccess $true
            $message = "Disk cleanup and performance optimization finished successfully!`n`nCompleted operations:`n• Temporary file removal and disk space recovery`n• Registry cleanup configuration`n• Cache optimization for better performance`n• Network performance optimization`n• Visual performance optimization"
            if ($additionalInfoText) {
                $message += "`n`nAdditional notes:`n$additionalInfoText"
            }
            $message += "`n`nYour system should now have more available disk space and improved performance."
            Show-InfoMessage -Title "Cleanup and Optimization Complete" -Message $message
        }
        else {
            Update-UiForJobEnd -StatusMessage "ERROR: Cleanup and optimization encountered issues." -IsSuccess $false
            $message = "The cleanup and optimization process encountered some issues but attempted to complete as many operations as possible.`n`nError details: $($JobResult.StandardError)`n`nFor detailed information, please check the log file 'SystemRepairLog.txt' on your Desktop.`n`nSome cleanup operations may have completed successfully despite this error."
            Show-ErrorMessage -Title "Cleanup Completed with Issues" -Message $message
        }
    }
    catch {
        Write-RepairLog -Message "Error in cleanup completion handler: $($_.Exception.Message)" -Category "ERROR" -Operation "CLEANUP"
        Update-UiForJobEnd -StatusMessage "ERROR: Failed to process cleanup results." -IsSuccess $false
    }
}

function Complete-RepairJob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Job]$Job,
        
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$JobResult
    )
    
    try {
        # Log with display name instead of raw job name for consistency
        $displayName = Get-JobDisplayName -JobName $Job.Name
        Write-RepairLog -Message "Processing completion for $displayName (job: $($Job.Name))" -Category "JOB"
        
        # Enhanced job type detection with case-insensitive patterns
        $jobNameLower = $Job.Name.ToLower()
        
        if ($jobNameLower -like "*dism*") {
            Complete-DismJob -JobResult $JobResult
        }
        elseif ($jobNameLower -like "*sfc*") {
            Complete-SfcJob -JobResult $JobResult
        }
        elseif ($jobNameLower -like "*diskcleanup*" -or $jobNameLower -like "*cleanup*" -or $jobNameLower -match "(disk|clean|optimize)") {
            Complete-DiskCleanupJob -JobResult $JobResult
        }
        else {
            Write-RepairLog -Message "Unknown job type completed: '$displayName' (internal name: '$($Job.Name)')" -Category "WARNING"
            Update-UiForJobEnd -StatusMessage "Operation completed with unknown type." -IsSuccess $false
        }
    }
    catch {
        Write-RepairLog -Message "Critical error in job completion handler: $($_.Exception.Message)" -Category "ERROR"
        Show-ErrorMessage -Title "Completion Error" -Message "An unexpected error occurred while finalizing the operation. Please check the log file for details.`n`nError: $($_.Exception.Message)"
        Update-UiForJobEnd -StatusMessage "ERROR: Completion processing failed." -IsSuccess $false
    }
}
#endregion

#region Windows 11 Enhanced GUI Design
# Create main form with Windows 11 design principles
$form = New-Object System.Windows.Forms.Form
$form.Text = "System Repair Toolkit"
$form.Size = New-Object System.Drawing.Size(480, 400)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false
$form.MinimizeBox = $true
$form.BackColor = $script:CONSTANTS.UI.BACKGROUND_COLOR

# Enhanced font handling with fallbacks for compatibility
$secondaryFont = $null
$titleFont = $null
try {
    # Try Windows 11 fonts first
    $titleFont = New-Object System.Drawing.Font("Segoe UI Variable Display", 16, [System.Drawing.FontStyle]::Bold)
    $secondaryFont = New-Object System.Drawing.Font("Segoe UI Variable", 10)
}
catch {
    try {
        # Fallback to standard Segoe UI
        $titleFont = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
        $secondaryFont = New-Object System.Drawing.Font("Segoe UI", 10)
    }
    catch {
        # Final fallback to system default
        $titleFont = New-Object System.Drawing.Font("Microsoft Sans Serif", 16, [System.Drawing.FontStyle]::Bold)
        $secondaryFont = New-Object System.Drawing.Font("Microsoft Sans Serif", 10)
    }
}

# Calculate enhanced layout with Windows 11 spacing
$buttonLeftMargin = ($form.ClientSize.Width - $script:CONSTANTS.UI.MAIN_BUTTON_WIDTH) / 2
$currentY = $script:CONSTANTS.UI.TOP_MARGIN

# Create and configure all UI controls
$titleLabel = New-Object System.Windows.Forms.Label
$instructionLabel = New-Object System.Windows.Forms.Label
$dismButton = New-Object System.Windows.Forms.Button
$sfcButton = New-Object System.Windows.Forms.Button
$cleanupButton = New-Object System.Windows.Forms.Button
$progressBar = New-Object System.Windows.Forms.ProgressBar
$statusLabel = New-Object System.Windows.Forms.Label
$bottomPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$helpButton = New-Object System.Windows.Forms.Button
$viewLogButton = New-Object System.Windows.Forms.Button
$closeButton = New-Object System.Windows.Forms.Button
$toolTip = New-Object System.Windows.Forms.ToolTip

# Enhanced tooltip configuration
$toolTip.InitialDelay = 500
$toolTip.ReshowDelay = 100
$toolTip.AutoPopDelay = 10000

# Configure title label with compact, elegant typography
$titleLabel.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
$titleLabel.Size = New-Object System.Drawing.Size($script:CONSTANTS.UI.MAIN_BUTTON_WIDTH, 32)
$titleLabel.Text = "System Repair Toolkit"
$titleLabel.Font = $titleFont
$titleLabel.ForeColor = $script:CONSTANTS.UI.TEXT_PRIMARY
$titleLabel.TextAlign = "MiddleCenter"
$currentY += $titleLabel.Height + 4

# Configure instruction label with compact clarity
$instructionLabel.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
$instructionLabel.Size = New-Object System.Drawing.Size($script:CONSTANTS.UI.MAIN_BUTTON_WIDTH, 18)
$instructionLabel.Text = "Recommended sequence: DISM → SFC → Optimize"
$instructionLabel.Font = New-Object System.Drawing.Font($secondaryFont.FontFamily, 9)
$instructionLabel.ForeColor = $script:CONSTANTS.UI.TEXT_SECONDARY
$instructionLabel.TextAlign = "MiddleCenter"
$currentY += $instructionLabel.Height + 20

# Enhanced button styling function for Windows 11 with proper scope handling
function Set-Windows11ButtonStyle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.Button]$Button,
        
        [Parameter(Mandatory = $true)]
        [string]$Text,
        
        [bool]$IsPrimary = $false
    )
    
    $Button.Size = New-Object System.Drawing.Size($script:CONSTANTS.UI.MAIN_BUTTON_WIDTH, $script:CONSTANTS.UI.MAIN_BUTTON_HEIGHT)
    $Button.Text = $Text
    $Button.Font = New-Object System.Drawing.Font($secondaryFont.FontFamily, 9.5)
    $Button.FlatStyle = 'Flat'
    $Button.Cursor = 'Hand'
    $Button.TextAlign = 'MiddleCenter'
    
    # Store button type in Tag property for proper scope handling
    $Button.Tag = if ($IsPrimary) { "Primary" } else { "Secondary" }
    
    # Enhanced Windows 11 styling
    if ($IsPrimary) {
        $Button.BackColor = $script:CONSTANTS.UI.PRIMARY_COLOR
        $Button.ForeColor = [System.Drawing.Color]::White
        $Button.FlatAppearance.BorderSize = 0
        
        # Primary button hover effects
        $Button.Add_MouseEnter({
                if ($this.Enabled) {
                    $this.BackColor = $script:CONSTANTS.UI.PRIMARY_HOVER_COLOR
                }
            })
        $Button.Add_MouseLeave({
                if ($this.Enabled) {
                    $this.BackColor = $script:CONSTANTS.UI.PRIMARY_COLOR
                }
            })
    }
    else {
        $Button.BackColor = $script:CONSTANTS.UI.SECONDARY_COLOR
        $Button.ForeColor = $script:CONSTANTS.UI.TEXT_PRIMARY
        $Button.FlatAppearance.BorderSize = 1
        $Button.FlatAppearance.BorderColor = $script:CONSTANTS.UI.BORDER_COLOR
        
        # Secondary button hover effects
        $Button.Add_MouseEnter({
                if ($this.Enabled) {
                    $this.BackColor = $script:CONSTANTS.UI.SECONDARY_HOVER_COLOR
                    $this.FlatAppearance.BorderColor = $script:CONSTANTS.UI.BORDER_HOVER_COLOR
                }
            })
        $Button.Add_MouseLeave({
                if ($this.Enabled) {
                    $this.BackColor = $script:CONSTANTS.UI.SECONDARY_COLOR
                    $this.FlatAppearance.BorderColor = $script:CONSTANTS.UI.BORDER_COLOR
                }
            })
    }
    
    # Enhanced disabled state styling with proper restoration using Tag property
    $Button.Add_EnabledChanged({
            try {
                if (-not $this.Enabled) {
                    # Store original colors before disabling
                    $this.ForeColor = [System.Drawing.Color]::FromArgb(160, 160, 160)
                    $this.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
                }
                else {
                    # More aggressive color restoration based on button's Tag property
                    if ($this.Tag -eq "Primary") {
                        $this.ForeColor = [System.Drawing.Color]::White
                        $this.BackColor = $script:CONSTANTS.UI.PRIMARY_COLOR
                        $this.FlatAppearance.BorderSize = 0
                    }
                    else {
                        $this.ForeColor = $script:CONSTANTS.UI.TEXT_PRIMARY
                        $this.BackColor = $script:CONSTANTS.UI.SECONDARY_COLOR
                        $this.FlatAppearance.BorderSize = 1
                        $this.FlatAppearance.BorderColor = $script:CONSTANTS.UI.BORDER_COLOR
                    }
                    # Force multiple refreshes to ensure colors stick
                    $this.Refresh()
                    $this.Invalidate()
                    $this.Update()
                }
            }
            catch {
                # Silent error handling for button state changes
            }
        })
}

# Configure Step 1 button (DISM) as primary action
$dismButton.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
Set-Windows11ButtonStyle -Button $dismButton -Text "STEP 1: Repair System Image (DISM)" -IsPrimary $true
$dismButton.Add_Click({ Start-DISMRepair })
$toolTip.SetToolTip($dismButton, "Repairs Windows component store and system image")
$currentY += $dismButton.Height + $script:CONSTANTS.UI.CONTROL_SPACING

# Configure Step 2 button (SFC)
$sfcButton.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
Set-Windows11ButtonStyle -Button $sfcButton -Text "STEP 2: Scan & Fix System Files (SFC)"
$sfcButton.Add_Click({ Start-SFCRepair })
$toolTip.SetToolTip($sfcButton, "Scans and repairs corrupted system files")
$currentY += $sfcButton.Height + $script:CONSTANTS.UI.CONTROL_SPACING

# Configure Step 3 button (Disk Cleanup and Performance Optimization)
$cleanupButton.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
Set-Windows11ButtonStyle -Button $cleanupButton -Text "STEP 3: Disk Cleanup && Performance"
$cleanupButton.Add_Click({ Start-DiskCleanup })
$toolTip.SetToolTip($cleanupButton, "Cleans temporary files and optimizes performance")
$currentY += $cleanupButton.Height + 8

# Configure enhanced progress bar with compact Windows 11 styling - right below STEP 3
$progressBar.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
$progressBar.Size = New-Object System.Drawing.Size($script:CONSTANTS.UI.MAIN_BUTTON_WIDTH, 6)
$progressBar.Style = 'Continuous'
$progressBar.ForeColor = $script:CONSTANTS.UI.PRIMARY_COLOR
$progressBar.BackColor = [System.Drawing.Color]::FromArgb(235, 235, 235)
$progressBar.Visible = $false
$currentY += $progressBar.Height + 6

# Configure status label with compact styling - right below progress bar
$statusLabel.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
$statusLabel.Size = New-Object System.Drawing.Size($script:CONSTANTS.UI.MAIN_BUTTON_WIDTH, 28)
$statusLabel.Font = New-Object System.Drawing.Font($secondaryFont.FontFamily, 9.5)
$statusLabel.TextAlign = "MiddleCenter"
$statusLabel.ForeColor = $script:CONSTANTS.UI.TEXT_SECONDARY
$currentY += $statusLabel.Height + 8

# Configure bottom panel with compact Windows 11 spacing - positioned immediately after status
$formWidth = [int]$form.ClientSize.Width
$panelWidth = [int]$formWidth
$buttonGroupWidth = 3 * $script:CONSTANTS.UI.SMALL_BUTTON_WIDTH + 2 * 8
$leftPadding = [int](($formWidth - $buttonGroupWidth) / 2)

$bottomPanel.Location = New-Object System.Drawing.Point(0, $currentY)
$bottomPanel.Size = New-Object System.Drawing.Size($panelWidth, 36)
$bottomPanel.FlowDirection = 'LeftToRight'
$bottomPanel.Anchor = 'None'  # Remove anchor to prevent automatic positioning
$bottomPanel.WrapContents = $false
$bottomPanel.AutoSize = $false
$bottomPanel.Padding = New-Object System.Windows.Forms.Padding($leftPadding, 3, 0, 0)

# Enhanced utility button styling for Windows 11
function Set-UtilityButtonStyle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.Button]$Button,
        
        [Parameter(Mandatory = $true)]
        [string]$Text
    )
    
    $Button.Size = New-Object System.Drawing.Size($script:CONSTANTS.UI.SMALL_BUTTON_WIDTH, $script:CONSTANTS.UI.SMALL_BUTTON_HEIGHT)
    $Button.Text = $Text
    $Button.Font = New-Object System.Drawing.Font($secondaryFont.FontFamily, 8)
    $Button.BackColor = [System.Drawing.Color]::FromArgb(253, 253, 253)
    $Button.ForeColor = $script:CONSTANTS.UI.TEXT_PRIMARY
    $Button.FlatStyle = 'Flat'
    $Button.FlatAppearance.BorderSize = 1
    $Button.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(210, 210, 210)
    $Button.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
    $Button.Cursor = 'Hand'
    $Button.TextAlign = 'MiddleCenter'
    
    # Enhanced hover effects
    $Button.Add_MouseEnter({
            if ($this.Enabled) {
                $this.BackColor = [System.Drawing.Color]::FromArgb(248, 248, 248)
                $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(180, 180, 180)
            }
        })
    $Button.Add_MouseLeave({
            if ($this.Enabled) {
                $this.BackColor = [System.Drawing.Color]::FromArgb(253, 253, 253)
                $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(210, 210, 210)
            }
        })
}

# Configure utility buttons with enhanced functionality
Set-UtilityButtonStyle -Button $helpButton -Text "Help"
$helpButton.Add_Click({
        $helpMsg = "System Repair Toolkit`n" +
        "Windows 11 Compatible • PowerShell 5.0+`n`n" +
        "FIXES IN:`n" +
        "• Fixed progress monitoring communication`n" +
        "• Resolved PowerShell 7.x compatibility issues`n" +
        "• Improved CleanMgr timeout handling (3 minutes)`n" +
        "• Enhanced dialog timeout management`n" +
        "• Added fallback progress estimation`n" +
        "• Better error recovery and job lifecycle management`n`n" +
        "This toolkit automates essential Windows repair and comprehensive system optimization:`n`n" +
        "STEP 1 - DISM System Image Repair:`n" +
        "Fixes the Windows component store and system image. Run this first if you're experiencing system instability, update failures, or corruption issues.`n`n" +
        "STEP 2 - SFC System File Check:`n" +
        "Scans and repairs individual protected system files. Run after DISM for comprehensive system file validation and repair.`n`n" +
        "STEP 3 - Comprehensive System Optimization:`n" +
        "Multi-phase optimization including disk cleanup, registry optimization, cache clearing, network optimization, file system optimization, and performance improvements with detailed progress tracking.`n`n" +
        "Administrator privileges are required for all operations. All actions are logged to 'SystemRepairLog.txt' on your Desktop for troubleshooting and verification.`n`n" +
        "For best results, run all three steps in sequence."
        Show-InfoMessage -Title "System Repair Toolkit - Help" -Message $helpMsg
        Write-RepairLog -Message "User accessed help documentation" -Category "USER"
    })

Set-UtilityButtonStyle -Button $viewLogButton -Text "View Log"
$viewLogButton.Add_Click({
        try {
            if (Test-Path $script:logPath) {
                Start-Process -FilePath "notepad.exe" -ArgumentList $script:logPath -ErrorAction Stop
                Write-RepairLog -Message "Log file opened by user: $script:logPath" -Category "USER"
            }
            else {
                $message = "Log file not found. The log file 'SystemRepairLog.txt' will be created on your Desktop when you perform your first repair operation."
                Show-InfoMessage -Title "Log File Not Found" -Message $message
            }
        }
        catch {
            # Fallback to Invoke-Item if notepad fails
            try {
                Invoke-Item $script:logPath
                Write-RepairLog -Message "Log file opened using system default application" -Category "USER"
            }
            catch {
                $message = "Could not open the log file automatically. Please manually open 'SystemRepairLog.txt' from your Desktop.`n`nPath: $script:logPath"
                Show-WarningMessage -Title "Unable to Open Log" -Message $message
            }
        }
    })

Set-UtilityButtonStyle -Button $closeButton -Text "Close"
$closeButton.Add_Click({ 
        Write-RepairLog -Message "Application closed by user" -Category "USER"
        $form.Close() 
    })

# Add utility buttons to bottom panel
$bottomPanel.Controls.AddRange(@($helpButton, $viewLogButton, $closeButton))

# Add all controls to main form with proper tab order
$form.Controls.AddRange(@(
        $titleLabel, $instructionLabel, $dismButton, $sfcButton, $cleanupButton,
        $progressBar, $statusLabel, $bottomPanel
    ))

# Set tab order for keyboard navigation (accessibility improvement)
$dismButton.TabIndex = 0
$sfcButton.TabIndex = 1
$cleanupButton.TabIndex = 2
$helpButton.TabIndex = 3
$viewLogButton.TabIndex = 4
$closeButton.TabIndex = 5

# Configure keyboard shortcuts (accessibility enhancement)
$form.KeyPreview = $true
$form.Add_KeyDown({
        param($formSender, $keyEventArguments)
    
        switch ($keyEventArguments.KeyCode) {
            'F1' { 
                $helpButton.PerformClick()
                $keyEventArguments.Handled = $true
            }
            'F2' { 
                $viewLogButton.PerformClick()
                $keyEventArguments.Handled = $true
            }
            'Escape' { 
                $closeButton.PerformClick()
                $keyEventArguments.Handled = $true
            }
            'D1' { 
                if ($dismButton.Enabled) { 
                    $dismButton.PerformClick() 
                }
                $keyEventArguments.Handled = $true
            }
            'D2' { 
                if ($sfcButton.Enabled) { 
                    $sfcButton.PerformClick() 
                }
                $keyEventArguments.Handled = $true
            }
            'D3' { 
                if ($cleanupButton.Enabled) { 
                    $cleanupButton.PerformClick() 
                }
                $keyEventArguments.Handled = $true
            }
        }
    })
#endregion

#region Enhanced UI State Management
# Improved UI state management with better visual feedback
function Update-UiForJobStart {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StatusMessage
    )
    
    try {
        # Update status with professional messaging
        $statusLabel.Text = $StatusMessage
        $statusLabel.ForeColor = $script:CONSTANTS.UI.TEXT_PRIMARY
        
        # Disable all action buttons during job execution
        $dismButton.Enabled = $false
        $sfcButton.Enabled = $false  
        $cleanupButton.Enabled = $false
        
        # Show and reset progress bar with immediate refresh
        $progressBar.Value = 0
        $progressBar.Visible = $true
        $progressBar.Refresh()
        
        # Update form title to show operation status
        $form.Text = "System Repair Toolkit - Operation in Progress"
        
        # Force UI refresh
        $form.Refresh()
        
        Write-RepairLog -Message "UI updated for job start: $StatusMessage" -Category "SYSTEM"
    }
    catch {
        Write-RepairLog -Message "Error updating UI for job start: $($_.Exception.Message)" -Category "ERROR"
    }
}

function Update-UiForJobEnd {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StatusMessage,
        
        [Parameter(Mandatory = $true)]
        [bool]$IsSuccess
    )
    
    try {
        # Check form disposal before any UI updates
        if ($form.IsDisposed -or $form.Disposing) {
            return
        }

        # Hide progress bar first to prevent text overlap (with disposal check)
        if (-not $progressBar.IsDisposed) {
            $progressBar.Visible = $false
        }
        
        # Update status with appropriate color coding (with disposal check)
        if (-not $statusLabel.IsDisposed) {
            $statusLabel.Text = $StatusMessage
            if ($IsSuccess) {
                $statusLabel.ForeColor = $script:CONSTANTS.UI.SUCCESS_COLOR
            }
            else {
                $statusLabel.ForeColor = $script:CONSTANTS.UI.ERROR_COLOR
            }
        }
        
        # Re-enable all action buttons with disposal checks
        if (-not $dismButton.IsDisposed) { $dismButton.Enabled = $true }
        if (-not $sfcButton.IsDisposed) { $sfcButton.Enabled = $true }
        if (-not $cleanupButton.IsDisposed) { $cleanupButton.Enabled = $true }
        
        # Force proper color restoration with enhanced error protection
        try {
            Start-Sleep -Milliseconds 50
            
            if (-not $dismButton.IsDisposed) {
                $dismButton.Refresh()
                $dismButton.Invalidate()
                $dismButton.Update()
            }
            
            if (-not $sfcButton.IsDisposed) {
                $sfcButton.Refresh()
                $sfcButton.Invalidate()
                $sfcButton.Update()
            }
            
            if (-not $cleanupButton.IsDisposed) {
                $cleanupButton.Refresh()
                $cleanupButton.Invalidate()
                $cleanupButton.Update()
            }
        }
        catch [System.ObjectDisposedException] {
            # Button was disposed during refresh - ignore
        }
        catch {
            # Silent error for button refresh operations
        }
        
        # Reset form title (with disposal check)
        if (-not $form.IsDisposed) {
            $form.Text = "System Repair Toolkit"
        }
        
        # Force complete UI refresh (with disposal checks)
        if (-not $statusLabel.IsDisposed) { $statusLabel.Refresh() }
        if (-not $form.IsDisposed) { $form.Refresh() }
        
        Write-RepairLog -Message "UI updated for job end: $StatusMessage (Success: $IsSuccess)" -Category "SYSTEM"
    }
    catch [System.ObjectDisposedException] {
        # UI was disposed during update - silently return
        Write-RepairLog -Message "UI disposed during job end update - completed silently" -Category "WARNING"
    }
    catch {
        Write-RepairLog -Message "Error updating UI for job end: $($_.Exception.Message)" -Category "ERROR"
    }
}

function Set-ReadyStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$IsAdministrator
    )
    
    try {
        if ($IsAdministrator) {
            $statusLabel.Text = "Ready • Administrator Mode • All functions available"
            $statusLabel.ForeColor = $script:CONSTANTS.UI.SUCCESS_COLOR
            Write-RepairLog -Message "UI status set: Administrator mode confirmed" -Category "SYSTEM"
        }
        else {
            $statusLabel.Text = "Limited Mode • Run as Administrator for full functionality"
            $statusLabel.ForeColor = $script:CONSTANTS.UI.WARNING_COLOR
            Write-RepairLog -Message "UI status set: Limited mode (non-administrator)" -Category "WARNING"
        }
    }
    catch {
        Write-RepairLog -Message "Error setting ready status: $($_.Exception.Message)" -Category "ERROR"
    }
}
#endregion

#region Form Event Handlers and Startup Logic
# Enhanced form closing event with comprehensive cleanup
$form.Add_FormClosing({
        param($formSender, $closeEventArgs)
    
        try {
            Write-RepairLog -Message "Application shutdown initiated by user" -Category "SYSTEM"
        
            # Stop timer immediately to prevent race conditions
            Stop-ProgressTimer
        
            # Check for running jobs and handle gracefully
            if ($null -ne $script:currentRepairJob) {
                try {
                    $jobState = $script:currentRepairJob.State
                    Write-RepairLog -Message "Current job state during shutdown: $jobState" -Category "JOB"
                
                    if ($jobState -eq 'Running') {
                        $message = "A repair operation is currently in progress. Closing the application will stop the operation.`n`nAre you sure you want to exit?"
                        $result = Show-QuestionMessage -Message $message -Title "Operation in Progress"
                    
                        if ($result -eq 'No') {
                            $closeEventArgs.Cancel = $true
                            Write-RepairLog -Message "Application shutdown cancelled by user (operation in progress)" -Category "USER"
                            # Restart timer if shutdown was cancelled
                            Start-ProgressTimer
                            return
                        }
                    }
                
                    Write-RepairLog -Message "Stopping active repair job due to application shutdown" -Category "JOB"
                    try {
                        # FIXED: PowerShell 7 compatibility - removed -Force parameter
                        $script:currentRepairJob | Stop-Job -ErrorAction SilentlyContinue
                        $script:currentRepairJob | Remove-Job -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-RepairLog -Message "Error stopping job during shutdown: $($_.Exception.Message)" -Category "WARNING"
                    }
                }
                catch {
                    Write-RepairLog -Message "Error checking job state during shutdown: $($_.Exception.Message)" -Category "WARNING"
                }
            }
        
            # Set global shutdown flag to prevent timer reactivation
            $script:currentRepairJob = $null
        
            # Clean up any temporary communication files
            if ($script:currentJobId) {
                try {
                    $userTempPath = [System.IO.Path]::GetTempPath()
                    $tempFiles = Get-ChildItem -Path $userTempPath -Filter "$($script:CONSTANTS.COMMUNICATION_PREFIX)_$script:currentJobId*" -ErrorAction SilentlyContinue
                    foreach ($file in $tempFiles) {
                        Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue
                    }
                }
                catch {
                    # Silent cleanup failure
                }
            }
        
            # Dispose of UI resources safely
            try {
                if ($null -ne $toolTip -and -not $toolTip.IsDisposed) { $toolTip.Dispose() }
                if ($null -ne $titleFont) { $titleFont.Dispose() }
                if ($null -ne $secondaryFont) { $secondaryFont.Dispose() }
            }
            catch {
                # Silent disposal failure
            }
        
            # Close logging system
            Close-RepairLog
        
            Write-RepairLog -Message "Application shutdown completed successfully" -Category "SYSTEM"
        }
        catch {
            # Ensure we can still close even if cleanup fails
            Write-Warning "Error during application shutdown: $($_.Exception.Message)"
            # Force close by not cancelling the event
        }
    })

# Enhanced form load event for initialization
$form.Add_Load({
        try {
            Write-RepairLog -Message "Main application window loaded successfully" -Category "SYSTEM"
        
            # Set initial UI state based on privileges
            $isAdmin = Test-IsAdministrator
            Set-ReadyStatus -IsAdministrator $isAdmin
        
            # Log system information for diagnostics
            $osInfo = [System.Environment]::OSVersion
            $psVersion = if ($PSVersionTable.PSVersion) { $PSVersionTable.PSVersion.ToString() } else { "Unknown" }
        
            Write-RepairLog -Message "System Information - OS: $($osInfo.VersionString), PowerShell: $psVersion" -Category "SYSTEM"
            Write-RepairLog -Message "UI Language: $([System.Globalization.CultureInfo]::CurrentUICulture.Name)" -Category "SYSTEM"
        
            # Set focus to first button for keyboard navigation
            $dismButton.Focus()
        
            # Display startup message for non-administrators
            if (-not $isAdmin) {
                $message = "Welcome to System Repair Toolkit!`n`nYou are currently running in Limited Mode. For full functionality including DISM, SFC, and comprehensive system optimization operations, please restart this application as an Administrator.`n`nYou can still access Help and view logs in this mode."
                Show-InfoMessage -Title "Limited Mode Notice" -Message $message
            }
        
            $script:isInitialized = $true
        }
        catch {
            Write-RepairLog -Message "Error during form load: $($_.Exception.Message)" -Category "ERROR"
            $script:isInitialized = $false
        }
    })

# Enhanced form shown event
$form.Add_Shown({
        try {
            Write-RepairLog -Message "Application interface displayed to user" -Category "SYSTEM"
        
            # Log startup completion
            if (Test-IsAdministrator) {
                Write-RepairLog -Message "Toolkit started with full Administrator privileges - all functions available" -Category "SYSTEM"
            }
            else {
                Write-RepairLog -Message "Toolkit started in standard user mode - functionality limited to information and logging" -Category "WARNING"
            }
        
            # Validate log file accessibility
            if (-not (Test-Path $script:logPath)) {
                Write-RepairLog -Message "Warning: Log file path may not be accessible" -Category "WARNING"
            }
        
            Write-RepairLog -Message "System Repair Toolkit initialization completed successfully" -Category "SYSTEM"
        }
        catch {
            Write-RepairLog -Message "Error during form shown event: $($_.Exception.Message)" -Category "ERROR"
        }
    })
#endregion

#region Application Entry Point and Execution
# Wrap entire application in comprehensive try-catch to prevent unhandled exceptions
try {
    # Set up unhandled exception handler for the application domain
    [System.AppDomain]::CurrentDomain.add_UnhandledException({
            param($exceptionSender, $exceptionEventArgs)
            try {
                $exception = $exceptionEventArgs.ExceptionObject
                Write-RepairLog -Message "Unhandled exception occurred: $($exception.ToString())" -Category "ERROR"
            
                # Try to show error to user
                [System.Windows.Forms.MessageBox]::Show(
                    "An unexpected error occurred. The application will attempt to close safely.`n`nError: $($exception.Message)",
                    "System Repair Toolkit - Unexpected Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
            }
            catch {
                # Last resort error handling
                Write-Error "Critical unhandled exception: $($exceptionEventArgs.ExceptionObject.ToString())"
            }
        })

    # Validate that logging was initialized successfully
    if (-not $script:isInitialized) {
        Write-Warning "Logging system failed to initialize. Some functionality may be limited."
        Initialize-RepairLog
    }
    
    # Log application startup
    Write-RepairLog -Message "=== SYSTEM REPAIR TOOLKIT STARTUP ===" -Category "SYSTEM"
    Write-RepairLog -Message "Application startup initiated with enhanced error handling and fixes applied" -Category "SYSTEM"
    
    # Verify system compatibility
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -lt 10) {
        Write-RepairLog -Message "Warning: Running on pre-Windows 10 system. Some features may not work optimally." -Category "WARNING"
    }
    
    # Verify .NET Framework version for WinForms support
    try {
        $netVersion = [System.Environment]::Version
        Write-RepairLog -Message ".NET Runtime Version: $netVersion" -Category "SYSTEM"
    }
    catch {
        Write-RepairLog -Message "Could not determine .NET version" -Category "WARNING"
    }
    
    # Display the main application window
    Write-RepairLog -Message "Displaying main application window" -Category "SYSTEM"
    
    # Show form and start message loop with error protection
    [void]$form.ShowDialog()
    
    Write-RepairLog -Message "Main application window closed by user" -Category "SYSTEM"
}
catch {
    # Critical startup error handling
    $errorMessage = "Critical startup error: $($_.Exception.Message)"
    Write-RepairLog -Message $errorMessage -Category "ERROR"
    
    try {
        [System.Windows.Forms.MessageBox]::Show(
            "A critical error occurred during application startup:`n`n$($_.Exception.Message)`n`nPlease ensure you have .NET Framework 4.x installed and try running as Administrator.`n`nStack Trace:`n$($_.Exception.StackTrace)",
            "System Repair Toolkit - Startup Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
    catch {
        Write-Error "Critical error - Unable to display UI: $($_.Exception.Message)"
    }
}
finally {
    # Comprehensive cleanup with enhanced error protection
    try {
        Write-RepairLog -Message "Application execution completed - starting final cleanup" -Category "SYSTEM"
        
        # Stop any remaining timers
        Stop-ProgressTimer
        
        # FIXED: Clean up any remaining background jobs with PowerShell 7 compatibility
        try {
            Get-Job | Where-Object { 
                $jobNameLower = $_.Name.ToLower()
                $jobNameLower -like "*repair*" -or 
                $jobNameLower -like "*cleanup*" -or 
                $jobNameLower -like "*diskcleanup*" -or
                $jobNameLower -like "*dism*" -or 
                $jobNameLower -like "*sfc*" -or 
                $jobNameLower -match "(clean|optimize|repair|maintenance)"
            } | ForEach-Object {
                try {
                    Write-RepairLog -Message "Cleaning up remaining job: $($_.Name)" -Category "SYSTEM"
                    # FIXED: PowerShell 7 compatibility - removed -Force parameters
                    $_ | Stop-Job -ErrorAction SilentlyContinue
                    $_ | Remove-Job -ErrorAction SilentlyContinue
                }
                catch {
                    Write-RepairLog -Message "Error cleaning up job $($_.Name): $($_.Exception.Message)" -Category "WARNING"
                }
            }
        }
        catch {
            Write-RepairLog -Message "Error during job cleanup: $($_.Exception.Message)" -Category "WARNING"
        }
        
        # Clean up any remaining temporary files
        try {
            $userTempPath = [System.IO.Path]::GetTempPath()
            $tempFiles = Get-ChildItem -Path $userTempPath -Filter "$($script:CONSTANTS.COMMUNICATION_PREFIX)*" -ErrorAction SilentlyContinue
            foreach ($file in $tempFiles) {
                Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            # Silent cleanup
        }
        
        Write-RepairLog -Message "=== SYSTEM REPAIR TOOLKIT SESSION END ===" -Category "SYSTEM"
        Close-RepairLog
    }
    catch {
        Write-Warning "Error during final cleanup: $($_.Exception.Message)"
    }
}
#endregion