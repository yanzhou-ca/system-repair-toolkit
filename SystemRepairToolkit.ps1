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
    Version: 3.0
    Author: Yan Zhou
    Requirements: PowerShell 5.0+, Windows 10/11, Administrator privileges for full functionality.
    
    ==============================
    SYSTEM REPAIR TOOLKIT v3.0
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
        $userTempPath = [System.IO.Path]::GetTempPath()
        $communicationPath = [System.IO.Path]::Combine($userTempPath, "$($script:CONSTANTS.COMMUNICATION_PREFIX)_${JobId}_${Key}.tmp")
        
        Write-RepairLog -Message "Creating communication file: $communicationPath" -Category "JOB"
        
        # Create communication file with proper permissions
        Set-Content -Path $communicationPath -Value $Value -Encoding UTF8 -Force
        
        # Verify file was actually created
        if (Test-Path $communicationPath) {
            $fileSize = (Get-Item $communicationPath).Length
            Write-RepairLog -Message "Communication file created successfully: $Key = $Value (Size: $fileSize bytes)" -Category "JOB"
        }
        else {
            Write-RepairLog -Message "ERROR: Communication file was not created: $communicationPath" -Category "ERROR"
        }
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
        [int]$TimeoutSeconds = 90
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

#region Enhanced Disk Cleanup ScriptBlock with Fixed Decision Processing
$script:diskCleanupScriptBlock = {
    param(
        [Parameter(Mandatory = $false)]
        [string]$LogPath = "",
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$JobId,
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(60, 3600)]
        [int]$CleanupTimeoutSeconds = 300,
        
        [Parameter(Mandatory = $false)]
        [bool]$AggressiveLogCleanup = $false
    )

    $jobStartTime = Get-Date

    function Write-LockedFileLog {
        param(
            [Parameter(Mandatory = $true)]
            [string]$FileName,
            [Parameter(Mandatory = $true)]
            [string]$Category
        )
        
        # Only log each locked file once per category
        $key = "$Category`:$FileName"
        if (-not $script:loggedLockedFiles.ContainsKey($key)) {
            $script:loggedLockedFiles[$key] = $true
            Write-SimpleLog "Could not remove $FileName (in use) - $Category"
        }
    }

    function Write-SimpleLog {
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNull()]
            [string]$message
        )
        try {
            if (-not [string]::IsNullOrWhiteSpace($script:LogPath) -and (Test-Path (Split-Path $script:LogPath -Parent))) {
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                "[$timestamp] [PROG] [Disk Cleanup] $message" | Add-Content -Path $script:LogPath -Encoding UTF8 -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Error "LOG_FALLBACK: $message"
        }
    }

    function Update-Progress {
        param(
            [Parameter(Mandatory = $true)]
            [ValidateRange(0, 100)]
            [int]$Percent, 
            
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$Message
        )
        Write-Output "PROGRESS_LINE:$Percent% - $Message"
        Write-SimpleLog "$Percent% - $Message"
    }

    function Set-CleanupRegistryFlags {
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNull()]
            [array]$Categories, 
            
            [Parameter(Mandatory = $true)]
            [ValidateRange(0, 9999)]
            [int]$SageSet
        )
        
        if ($Categories.Count -eq 0) {
            Write-SimpleLog "No categories provided to configure"
            return 0
        }
        
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
        $configured = 0
        
        foreach ($category in $Categories) {
            if ([string]::IsNullOrWhiteSpace($category)) {
                continue
            }
            
            try {
                $categoryPath = Join-Path $regPath $category
                if (Test-Path $categoryPath) {
                    Set-ItemProperty -Path $categoryPath -Name "StateFlags$($SageSet.ToString('0000'))" -Value 2 -Type DWord -Force -ErrorAction Stop
                    $configured++
                }
            }
            catch {
                Write-SimpleLog "Could not configure category '$category': $($_.Exception.Message)"
            }
        }
        
        return $configured
    }

    function Get-AvailableCleanupCategories {
        try {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
            $availableCategories = @()
            
            if (Test-Path $regPath) {
                $subKeys = Get-ChildItem $regPath -ErrorAction SilentlyContinue
                if ($subKeys) {
                    foreach ($subKey in $subKeys) {
                        $categoryName = $subKey.PSChildName
                        if (-not [string]::IsNullOrWhiteSpace($categoryName)) {
                            $availableCategories += $categoryName
                        }
                    }
                }
            }
            
            Write-SimpleLog "Found $($availableCategories.Count) available cleanup categories"
            return $availableCategories
        }
        catch {
            Write-SimpleLog "Error enumerating cleanup categories: $($_.Exception.Message)"
            return @("Temporary Files", "Recycle Bin", "Temporary Internet Files", "Thumbnails")
        }
    }

    function Invoke-EnhancedCleanup {
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNull()]
            [array]$Categories, 
            
            [Parameter(Mandatory = $true)]
            [ValidateRange(0, 9999)]
            [int]$SageSet
        )
        
        try {
            Write-SimpleLog "Configuring cleanup categories for native Windows cleanup"
            
            $configured = Set-CleanupRegistryFlags -Categories $Categories -SageSet $SageSet
            
            Write-SimpleLog "Configured $configured cleanup categories for Windows native cleanup"
            if ($configured -gt 0) {
                Write-SimpleLog "Native cleanup will target: $($Categories -join ', ')"
            }
            return $configured -gt 0
        }
        catch {
            Write-SimpleLog "Error in cleanup configuration: $($_.Exception.Message)"
            return $false
        }
    }

    function Test-RobocopyAvailable {
        try {
            $robocopyCmd = Get-Command "robocopy.exe" -ErrorAction SilentlyContinue
            return $null -ne $robocopyCmd
        }
        catch {
            return $false
        }
    }

    function Test-PowerShellVersion {
        param([int]$MinimumVersion = 5)
        return $PSVersionTable.PSVersion.Major -ge $MinimumVersion
    }

    function Wait-ProcessStop {
        param(
            [string]$ProcessName,
            [int]$TimeoutSeconds = 15
        )
        
        $timeout = (Get-Date).AddSeconds($TimeoutSeconds)
        while ((Get-Date) -lt $timeout) {
            $process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
            if (-not $process) {
                return $true
            }
            Start-Sleep -Milliseconds 500
        }
        return $false
    }

    function Remove-WindowsOld {
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$WindowsOldPath
        )
        
        try {
            Write-SimpleLog "Attempting Windows.old removal using multiple methods"
            
            # Method 1: Official cleanmgr method
            try {
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Previous Installations"
                if (Test-Path $regPath) {
                    Set-ItemProperty -Path $regPath -Name "StateFlags0099" -Value 2 -Type DWord -Force -ErrorAction Stop
                    Write-SimpleLog "Configured Previous Installations cleanup category"
                    
                    $process = Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/SAGERUN:0099" -WindowStyle Hidden -PassThru -ErrorAction Stop
                    $completed = $process.WaitForExit($script:CleanupTimeoutSeconds * 1000)
                    
                    if ($completed -and $process.ExitCode -eq 0) {
                        Write-SimpleLog "Windows.old cleanup completed via cleanmgr"
                        $removed = -not (Test-Path $WindowsOldPath)
                        if ($removed) {
                            return $true
                        }
                    }
                    else {
                        if (-not $completed) {
                            $process.Kill()
                            Write-SimpleLog "Cleanmgr timed out after $($script:CleanupTimeoutSeconds) seconds"
                        }
                        else {
                            Write-SimpleLog "Cleanmgr completed with exit code: $($process.ExitCode)"
                        }
                    }
                }
            }
            catch {
                Write-SimpleLog "Cleanmgr method failed: $($_.Exception.Message)"
            }
            
            # Method 2: Robocopy mirror method (faster and more reliable)
            if (Test-RobocopyAvailable) {
                try {
                    Write-SimpleLog "Attempting Robocopy removal method"
                    $tempDirName = "EmptyForRobocopy_$($script:JobId)_$(Get-Random)"
                    $emptyDir = Join-Path $env:TEMP $tempDirName
                    
                    if (Test-Path $WindowsOldPath) {
                        New-Item -Path $emptyDir -ItemType Directory -Force | Out-Null
                        
                        $robocopyArgs = @(
                            $emptyDir,
                            $WindowsOldPath,
                            "/MIR",
                            "/R:0",
                            "/W:0",
                            "/NJH",
                            "/NJS", 
                            "/NP",
                            "/NFL",
                            "/NDL"
                        )
                        
                        $robocopyProcess = Start-Process -FilePath "robocopy.exe" -ArgumentList $robocopyArgs -WindowStyle Hidden -PassThru -ErrorAction Stop
                        $robocopyCompleted = $robocopyProcess.WaitForExit(($script:CleanupTimeoutSeconds / 2) * 1000)
                        
                        if ($robocopyCompleted) {
                            # Robocopy exit codes 0-7 are considered successful
                            $exitCode = $robocopyProcess.ExitCode
                            Write-SimpleLog "Robocopy completed with exit code: $exitCode"
                            
                            if ($exitCode -le 7) {
                                Remove-Item $emptyDir -Force -Recurse -ErrorAction SilentlyContinue
                                Remove-Item $WindowsOldPath -Force -Recurse -ErrorAction SilentlyContinue
                                
                                if (-not (Test-Path $WindowsOldPath)) {
                                    Write-SimpleLog "Windows.old removed successfully via Robocopy method"
                                    return $true
                                }
                            }
                            else {
                                Write-SimpleLog "Robocopy failed with exit code: $exitCode"
                            }
                        }
                        else {
                            $robocopyProcess.Kill()
                            Write-SimpleLog "Robocopy timed out"
                        }
                        
                        # Cleanup temp directory
                        Remove-Item $emptyDir -Force -Recurse -ErrorAction SilentlyContinue
                    }
                }
                catch {
                    Write-SimpleLog "Robocopy removal method failed: $($_.Exception.Message)"
                }
            }
            else {
                Write-SimpleLog "Robocopy not available, skipping Method 2"
            }
            
            # Method 3: PowerShell removal method (fallback)
            try {
                Write-SimpleLog "Attempting PowerShell removal method"
                
                $removed = $false
                for ($attempt = 1; $attempt -le 3; $attempt++) {
                    try {
                        if (Test-Path $WindowsOldPath) {
                            Write-SimpleLog "PowerShell removal attempt $attempt"
                            
                            Get-ChildItem -Path $WindowsOldPath -Recurse -Force -ErrorAction SilentlyContinue |
                            Where-Object { -not $_.PSIsContainer } |
                            Remove-Item -Force -ErrorAction SilentlyContinue
                            
                            Get-ChildItem -Path $WindowsOldPath -Recurse -Force -ErrorAction SilentlyContinue |
                            Where-Object { $_.PSIsContainer } |
                            Sort-Object FullName -Descending |
                            Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                            
                            Remove-Item -Path $WindowsOldPath -Force -Recurse -ErrorAction SilentlyContinue
                            
                            if (-not (Test-Path $WindowsOldPath)) {
                                Write-SimpleLog "Windows.old removed successfully on attempt $attempt"
                                $removed = $true
                                break
                            }
                        }
                        else {
                            Write-SimpleLog "Windows.old no longer exists"
                            $removed = $true
                            break
                        }
                    }
                    catch {
                        Write-SimpleLog "PowerShell attempt $attempt failed: $($_.Exception.Message)"
                    }
                    
                    if ($attempt -lt 3) {
                        Start-Sleep -Seconds 5
                    }
                }
                
                if ($removed) {
                    return $true
                }
            }
            catch {
                Write-SimpleLog "PowerShell removal method failed: $($_.Exception.Message)"
            }
            
            # Check for partial success based on size reduction instead of file count
            try {
                if (Test-Path $WindowsOldPath) {
                    $remainingSize = (Get-ChildItem -Path $WindowsOldPath -Recurse -Force -ErrorAction SilentlyContinue | 
                        Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                    
                    if ($null -eq $remainingSize) {
                        $remainingSize = 0
                    }
                    
                    $remainingSizeMB = [Math]::Round($remainingSize / 1MB, 1)
                    
                    Write-SimpleLog "Windows.old still exists with $remainingSizeMB MB remaining"
                    
                    # Consider it a success if less than 100MB remains (likely just locked files)
                    if ($remainingSizeMB -lt 100) {
                        Write-SimpleLog "Windows.old significantly reduced - considering partial success"
                        return $true
                    }
                }
            }
            catch {
                Write-SimpleLog "Could not check remaining Windows.old content: $($_.Exception.Message)"
            }
            
            Write-SimpleLog "All Windows.old removal methods completed - folder may still exist"
            return $false
        }
        catch {
            Write-SimpleLog "Critical error in Windows.old removal: $($_.Exception.Message)"
            return $false
        }
    }

    function Clear-DefenderFiles {
        try {
            Write-SimpleLog "Note: Skipping Defender file cleanup to avoid antivirus conflicts"
            Write-SimpleLog "Use Windows Disk Cleanup manually for Defender files if needed"
            return @{ Files = 0; Size = 0 }
        }
        catch {
            Write-SimpleLog "Error in Defender cleanup: $($_.Exception.Message)"
            return @{ Files = 0; Size = 0 }
        }
    }

    function Clear-DeliveryOptimization {
        try {
            $totalSize = 0
            $totalFiles = 0
            
            $cacheLocations = @()
            
            try {
                $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
                if (Test-Path $regPath) {
                    $customCache = Get-ItemProperty -Path $regPath -Name "DOModifyCacheDrive" -ErrorAction SilentlyContinue
                    if ($customCache -and $customCache.DOModifyCacheDrive) {
                        $customPath = $customCache.DOModifyCacheDrive
                        if ($customPath -notlike "*:*") {
                            $customPath = "${customPath}\DeliveryOptimization"
                        }
                        else {
                            $customPath = "${customPath}\DeliveryOptimization"
                        }
                        $cacheLocations += $customPath
                        Write-SimpleLog "Found custom DO cache location: $customPath"
                    }
                }
            }
            catch {
                Write-SimpleLog "Could not read DO registry settings: $($_.Exception.Message)"
            }
            
            if ($cacheLocations.Count -eq 0) {
                $cacheLocations = @(
                    "$env:SYSTEMDRIVE\DeliveryOptimization",
                    "$env:WINDIR\SoftwareDistribution\DeliveryOptimization",
                    "$env:WINDIR\SoftwareDistribution\Download",
                    "$env:ProgramData\Microsoft\Windows\DeliveryOptimization"
                )
                Write-SimpleLog "Using default DO cache locations: $($cacheLocations -join ', ')"
            }
            
            foreach ($drive in (Get-PSDrive -PSProvider FileSystem)) {
                $driveLetter = $drive.Name
                $alternatePaths = @(
                    "${driveLetter}:\DeliveryOptimization",
                    "${driveLetter}:\Windows.old\Windows\SoftwareDistribution\DeliveryOptimization"
                )
                foreach ($alternatePath in $alternatePaths) {
                    if ((Test-Path $alternatePath) -and ($alternatePath -notin $cacheLocations)) {
                        $cacheLocations += $alternatePath
                        Write-SimpleLog "Found additional DO cache: $alternatePath"
                    }
                }
            }
            
            foreach ($location in $cacheLocations) {
                if (Test-Path $location) {
                    try {
                        Write-SimpleLog "Processing DO cache location: $location"
                        $cacheFiles = Get-ChildItem -Path $location -Recurse -Force -ErrorAction SilentlyContinue |
                        Where-Object { 
                            -not $_.PSIsContainer -and 
                            $_.Length -gt 0 -and
                            $_.Length -lt 15GB  # Increased from 10GB for very large legitimate caches
                        }
                        
                        $locationSize = 0
                        $locationFiles = 0
                        
                        if ($cacheFiles) {
                            foreach ($file in $cacheFiles) {
                                try {
                                    $fileSize = $file.Length
                                    Remove-Item $file.FullName -Force -ErrorAction Stop
                                    $locationFiles++
                                    $locationSize += $fileSize
                                    $totalFiles++
                                    $totalSize += $fileSize
                                }
                                catch {
                                    Write-SimpleLog "Could not remove DO file: $($file.Name)"
                                }
                            }
                        }
                        
                        if ($locationFiles -gt 0) {
                            $locationSizeMB = [Math]::Round($locationSize / 1MB, 1)
                            Write-SimpleLog "Delivery Optimization from ${location} $locationFiles files, $locationSizeMB MB"
                        }
                        else {
                            Write-SimpleLog "No Delivery Optimization files found in $location"
                        }
                    }
                    catch {
                        Write-SimpleLog "Error processing DO location ${location} $($_.Exception.Message)"
                    }
                }
                else {
                    Write-SimpleLog "Delivery Optimization path does not exist: $location"
                }
            }
            
            $sizeMB = [Math]::Round($totalSize / 1MB, 1)
            Write-SimpleLog "Delivery Optimization cleanup: $totalFiles files, $sizeMB MB"
            return @{ Files = $totalFiles; Size = $totalSize }
        }
        catch {
            Write-SimpleLog "Error in Delivery Optimization cleanup: $($_.Exception.Message)"
            return @{ Files = 0; Size = 0 }
        }
    }

    function Clear-InternetTemporaryFiles {
        try {
            $totalSize = 0
            $totalFiles = 0
            
            $currentUserPaths = @(
                @{ Path = "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"; Name = "IE/Edge Cache" },
                @{ Path = "$env:LOCALAPPDATA\Microsoft\Windows\INetCookies"; Name = "IE/Edge Cookies" },
                @{ Path = "$env:LOCALAPPDATA\Microsoft\Windows\WebCache"; Name = "Web Cache" },
                @{ Path = "$env:LOCALAPPDATA\Temp\IEDownloadHistory"; Name = "IE Download History" },
                @{ Path = "$env:APPDATA\Microsoft\Windows\Cookies"; Name = "Legacy Cookies" }
            )
            
            # Enhanced browser cache detection - enumerate all profiles
            $browserBasePaths = @(
                @{ Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"; Name = "Edge Chromium" },
                @{ Path = "$env:LOCALAPPDATA\Google\Chrome\User Data"; Name = "Chrome" },
                @{ Path = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"; Name = "Brave" }
            )
            
            foreach ($browserBase in $browserBasePaths) {
                if (Test-Path $browserBase.Path) {
                    try {
                        # Enhanced profile regex to handle more edge cases
                        $profiles = Get-ChildItem -Path $browserBase.Path -Directory -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match "^(Default|Profile \d+|System Profile|Guest Profile)$" }
                        
                        if ($profiles) {
                            foreach ($userProfile in $profiles) {
                                $cachePaths = @(
                                    @{ Path = (Join-Path $userProfile.FullName "Cache"); Name = "$($browserBase.Name) Cache ($($userProfile.Name))" },
                                    @{ Path = (Join-Path $userProfile.FullName "Code Cache"); Name = "$($browserBase.Name) Code Cache ($($userProfile.Name))" },
                                    @{ Path = (Join-Path $userProfile.FullName "GPUCache"); Name = "$($browserBase.Name) GPU Cache ($($userProfile.Name))" }
                                )
                                
                                # Safe array concatenation
                                if ($cachePaths -and $cachePaths.Count -gt 0) {
                                    $currentUserPaths += $cachePaths
                                }
                            }
                        }
                    }
                    catch {
                        Write-SimpleLog "Error enumerating $($browserBase.Name) profiles: $($_.Exception.Message)"
                    }
                }
            }
            
            # Firefox cache detection
            $firefoxProfilesPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
            if (Test-Path $firefoxProfilesPath) {
                try {
                    $firefoxProfiles = Get-ChildItem -Path $firefoxProfilesPath -Directory -ErrorAction SilentlyContinue
                    if ($firefoxProfiles) {
                        foreach ($firefoxUserProfile in $firefoxProfiles) {
                            $firefoxCache = Join-Path $firefoxUserProfile.FullName "cache2"
                            if (Test-Path $firefoxCache) {
                                $currentUserPaths += @{ Path = $firefoxCache; Name = "Firefox Cache ($($firefoxUserProfile.Name))" }
                            }
                        }
                    }
                }
                catch {
                    Write-SimpleLog "Error enumerating Firefox profiles: $($_.Exception.Message)"
                }
            }
            
            foreach ($pathInfo in $currentUserPaths) {
                if ($pathInfo -and $pathInfo.Path -and (Test-Path $pathInfo.Path)) {
                    try {
                        $ageThreshold = (Get-Date).AddHours(-2)  # Reduced from 1 day to 2 hours for more thorough cleaning
                        
                        $files = Get-ChildItem -Path $pathInfo.Path -Recurse -Force -ErrorAction SilentlyContinue |
                        Where-Object { 
                            -not $_.PSIsContainer -and 
                            $_.Length -gt 0 -and 
                            $_.Length -lt 500MB -and
                            $_.LastWriteTime -lt $ageThreshold
                        }
                        
                        $pathSize = 0
                        $pathFiles = 0
                        $lockedFiles = 0
                        
                        if ($files) {
                            foreach ($file in $files) {
                                try {
                                    $fileSize = $file.Length
                                    Remove-Item $file.FullName -Force -ErrorAction Stop
                                    $pathFiles++
                                    $pathSize += $fileSize
                                }
                                catch {
                                    $lockedFiles++
                                    # Reduced logging noise for locked files
                                }
                            }
                        }
                        
                        if ($pathFiles -gt 0) {
                            $pathSizeMB = [Math]::Round($pathSize / 1MB, 1)
                            $lockedMessage = if ($lockedFiles -gt 0) { " ($lockedFiles locked)" } else { "" }
                            Write-SimpleLog "$($pathInfo.Name): $pathFiles files, $pathSizeMB MB$lockedMessage"
                        }
                        
                        $totalFiles += $pathFiles
                        $totalSize += $pathSize
                    }
                    catch {
                        Write-SimpleLog "Error processing $($pathInfo.Name): $($_.Exception.Message)"
                    }
                }
            }
            
            # Legacy IE cache cleanup
            try {
                $ieCachePath = "$env:USERPROFILE\AppData\Local\Microsoft\Windows\Temporary Internet Files"
                if (Test-Path $ieCachePath) {
                    $ieFiles = Get-ChildItem -Path $ieCachePath -Recurse -Force -ErrorAction SilentlyContinue |
                    Where-Object { 
                        -not $_.PSIsContainer -and 
                        $_.Length -gt 0 -and 
                        $_.Length -lt 100MB
                    }
                    
                    $ieSize = 0
                    $ieCount = 0
                    
                    if ($ieFiles) {
                        foreach ($file in $ieFiles) {
                            try {
                                $fileSize = $file.Length
                                Remove-Item $file.FullName -Force -ErrorAction Stop
                                $ieCount++
                                $ieSize += $fileSize
                            }
                            catch {
                                # Use centralized locked file logging
                                Write-LockedFileLog -FileName $file.Name -Category "Additional Temp Files"
                            }
                        }
                    }
                    
                    if ($ieCount -gt 0) {
                        $ieSizeMB = [Math]::Round($ieSize / 1MB, 1)
                        Write-SimpleLog "Legacy IE Cache: $ieCount files, $ieSizeMB MB"
                        $totalFiles += $ieCount
                        $totalSize += $ieSize
                    }
                }
            }
            catch {
                Write-SimpleLog "Error cleaning legacy IE cache: $($_.Exception.Message)"
            }
            
            $sizeMB = [Math]::Round($totalSize / 1MB, 1)
            Write-SimpleLog "Internet temporary files cleanup: $totalFiles files, $sizeMB MB"
            return @{ Files = $totalFiles; Size = $totalSize }
        }
        catch {
            Write-SimpleLog "Error in Internet temporary files cleanup: $($_.Exception.Message)"
            return @{ Files = 0; Size = 0 }
        }
    }

    function Clear-RecycleBinSafely {
        try {
            $recyclerStats = @{ Files = 0; Size = 0 }
            
            # Get current recycle bin size for reporting using modern approach
            try {
                $currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                $recyclerPath = "$env:SYSTEMDRIVE\`$Recycle.Bin\$currentUserSid"
                
                if (Test-Path $recyclerPath) {
                    $recyclerFiles = Get-ChildItem -Path $recyclerPath -Force -ErrorAction SilentlyContinue |
                    Where-Object { -not $_.PSIsContainer -and $_.Length -gt 0 }
                    
                    if ($recyclerFiles) {
                        $recyclerStats.Files = $recyclerFiles.Count
                        $recyclerStats.Size = ($recyclerFiles | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                        if ($null -eq $recyclerStats.Size) {
                            $recyclerStats.Size = 0
                        }
                    }
                }
            }
            catch {
                Write-SimpleLog "Could not measure Recycle Bin size: $($_.Exception.Message)"
            }
            
            # Use modern Clear-RecycleBin if available (PowerShell 5.0+)
            if (Test-PowerShellVersion -MinimumVersion 5) {
                try {
                    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
                    
                    # Verify the operation succeeded (less strict check)
                    Start-Sleep -Milliseconds 500  # Give it a moment to complete
                    try {
                        $currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                        $recyclerPath = "$env:SYSTEMDRIVE\`$Recycle.Bin\$currentUserSid"
                        
                        if (Test-Path $recyclerPath) {
                            $remainingFiles = Get-ChildItem -Path $recyclerPath -Force -ErrorAction SilentlyContinue
                            # Only consider it failed if there are many files remaining (not just info2 or desktop.ini)
                            if ($remainingFiles -and $remainingFiles.Count -gt 3) {
                                Write-SimpleLog "Clear-RecycleBin may not have completed fully ($($remainingFiles.Count) items remain), trying manual method"
                                throw "Clear-RecycleBin verification failed"
                            }
                        }
                    }
                    catch {
                        # If we can't verify, assume it worked unless proven otherwise
                        Write-SimpleLog "Could not verify Recycle Bin cleanup, assuming success"
                    }
                    
                    if ($recyclerStats.Files -gt 0) {
                        $recyclerSizeMB = [Math]::Round($recyclerStats.Size / 1MB, 1)
                        Write-SimpleLog "Recycle Bin (modern): $($recyclerStats.Files) files, $recyclerSizeMB MB"
                    }
                    else {
                        Write-SimpleLog "Recycle Bin was already empty"
                    }
                }
                catch {
                    Write-SimpleLog "Modern Clear-RecycleBin failed: $($_.Exception.Message)"
                    # Fall through to manual method
                    throw
                }
            }
            else {
                Write-SimpleLog "PowerShell version < 5.0, using manual Recycle Bin cleanup"
                throw "PowerShell version too old"
            }
            
            return $recyclerStats
        }
        catch {
            # Fallback to manual method
            try {
                Write-SimpleLog "Falling back to manual Recycle Bin cleanup"
                $currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                $recyclerPath = "$env:SYSTEMDRIVE\`$Recycle.Bin\$currentUserSid"
                
                $recyclerStats = @{ Files = 0; Size = 0 }
                
                if (Test-Path $recyclerPath) {
                    $recyclerFiles = Get-ChildItem -Path $recyclerPath -Force -ErrorAction SilentlyContinue |
                    Where-Object { -not $_.PSIsContainer -and $_.Length -gt 0 }
                    
                    $recyclerSize = 0
                    $recyclerCount = 0
                    
                    if ($recyclerFiles) {
                        foreach ($file in $recyclerFiles) {
                            try {
                                $fileSize = $file.Length
                                Remove-Item $file.FullName -Force -ErrorAction Stop
                                $recyclerCount++
                                $recyclerSize += $fileSize
                            }
                            catch {
                                # Silent failure for locked files
                            }
                        }
                    }
                    
                    if ($recyclerCount -gt 0) {
                        $recyclerSizeMB = [Math]::Round($recyclerSize / 1MB, 1)
                        Write-SimpleLog "Recycle Bin (manual): $recyclerCount files, $recyclerSizeMB MB"
                    }
                    
                    $recyclerStats.Files = $recyclerCount
                    $recyclerStats.Size = $recyclerSize
                }
                
                return $recyclerStats
            }
            catch {
                Write-SimpleLog "Manual Recycle Bin cleanup also failed: $($_.Exception.Message)"
                return @{ Files = 0; Size = 0 }
            }
        }
    }

    function Clear-SystemTemporaryFiles {
        try {
            $tempPaths = @(
                @{ Path = $env:TEMP; Name = "User Temp"; AgeDays = 0; MaxSize = 1GB },
                @{ Path = $env:TMP; Name = "User TMP"; AgeDays = 0; MaxSize = 1GB },
                @{ Path = "$env:WINDIR\Temp"; Name = "Windows Temp"; AgeDays = 0; MaxSize = 5GB },
                @{ Path = "$env:WINDIR\Logs\CBS"; Name = "CBS Logs"; AgeDays = 0; MaxSize = 30GB },
                @{ Path = "$env:WINDIR\Logs\DISM"; Name = "DISM Logs"; AgeDays = 0; MaxSize = 2GB },
                @{ Path = "$env:WINDIR\Logs\DPX"; Name = "Device Setup Logs"; AgeDays = 0; MaxSize = 2GB },
                @{ Path = "$env:WINDIR\Logs\WindowsUpdate"; Name = "Windows Update Logs"; AgeDays = 0; MaxSize = 2GB },
                @{ Path = "$env:WINDIR\SoftwareDistribution\Download"; Name = "Update Downloads"; AgeDays = 0; MaxSize = 20GB },
                @{ Path = "$env:LOCALAPPDATA\Temp"; Name = "Local App Temp"; AgeDays = 0; MaxSize = 2GB },
                @{ Path = "$env:WINDIR\Prefetch"; Name = "Prefetch Files"; AgeDays = 0; MaxSize = 500MB }
            )
            
            $totalSize = 0
            $totalFiles = 0
            
            foreach ($pathInfo in $tempPaths) {
                if ($pathInfo -and $pathInfo.Path -and (Test-Path $pathInfo.Path)) {
                    try {
                        if ($pathInfo.Name -eq "CBS Logs") {
                            $cbsLogPath = Join-Path $pathInfo.Path "CBS.log"
                            if (Test-Path $cbsLogPath) {
                                try {
                                    $cbsLog = Get-Item $cbsLogPath -Force
                                    if ($cbsLog.Length -gt 50MB -and $cbsLog.LastWriteTime -lt (Get-Date).AddHours(-1)) {
                                        $fileSize = $cbsLog.Length
                                        Remove-Item $cbsLogPath -Force -ErrorAction Stop
                                        $totalFiles++
                                        $totalSize += $fileSize
                                        $cbsSizeMB = [Math]::Round($fileSize / 1MB, 1)
                                        Write-SimpleLog "Removed large CBS.log: $cbsSizeMB MB"
                                    }
                                }
                                catch {
                                    Write-SimpleLog "Could not remove CBS.log: File may be actively in use by Component Store"
                                }
                            }
                        }
                        
                        $files = Get-ChildItem -Path $pathInfo.Path -Force -ErrorAction SilentlyContinue |
                        Where-Object { 
                            -not $_.PSIsContainer -and 
                            $_.Length -gt 0 -and 
                            $_.Length -lt $pathInfo.MaxSize
                        }
                        
                        if ($pathInfo.Name -eq "Update Downloads") {
                            $files = $files | Where-Object { $_.Extension -in @('.cab', '.msu', '.exe', '.tmp', '.psf', '.esd') }
                        }
                        elseif ($pathInfo.Name -like "*Logs") {
                            $files = $files | Where-Object { 
                                $_.Extension -in @('.log', '.cab', '.etl', '.tmp', '.old', '.bak') -and 
                                $_.Name -ne "CBS.log" -and
                                $_.LastWriteTime -lt (Get-Date).AddMinutes(-30)
                            }
                        }
                        elseif ($pathInfo.Name -eq "Prefetch Files") {
                            $files = $files | Where-Object { 
                                $_.Extension -eq '.pf' -and 
                                $_.LastWriteTime -lt (Get-Date).AddDays(-30)
                            }
                        }
                        else {
                            $files = $files | Where-Object { 
                                $_.Extension -in @('.tmp', '.temp', '.bak', '.old', '.chk', '.gid', '.fts', '.ftg', '.log') -or
                                $_.Name -like "~*" -or
                                $_.Name -like "*tmp*" -or
                                $_.Name -like "*.old"
                            }
                        }
                        
                        $pathSize = 0
                        $pathFiles = 0
                        $lockedFiles = 0
                        
                        if ($files) {
                            foreach ($file in $files) {
                                try {
                                    $fileSize = $file.Length
                                    Remove-Item $file.FullName -Force -ErrorAction Stop
                                    $pathFiles++
                                    $pathSize += $fileSize
                                }
                                catch {
                                    $lockedFiles++
                                    # Use centralized locked file logging to reduce noise
                                    Write-LockedFileLog -FileName $file.Name -Category $pathInfo.Name
                                }
                            }
                        }
                        
                        if ($pathFiles -gt 0) {
                            $pathSizeMB = [Math]::Round($pathSize / 1MB, 1)
                            $lockedMessage = if ($lockedFiles -gt 0) { " ($lockedFiles files locked)" } else { "" }
                            Write-SimpleLog "$($pathInfo.Name): $pathFiles files, $pathSizeMB MB$lockedMessage"
                        }
                        
                        $totalFiles += $pathFiles
                        $totalSize += $pathSize
                    }
                    catch {
                        Write-SimpleLog "Error cleaning $($pathInfo.Name): $($_.Exception.Message)"
                    }
                }
            }
            
            # Modern Recycle Bin cleanup
            try {
                Write-SimpleLog "Emptying Recycle Bin using best available method"
                $recyclerResult = Clear-RecycleBinSafely
                $totalFiles += $recyclerResult.Files
                $totalSize += $recyclerResult.Size
            }
            catch {
                Write-SimpleLog "Error cleaning Recycle Bin: $($_.Exception.Message)"
            }
            
            # Additional temp paths cleanup
            try {
                $additionalTempPaths = @(
                    "$env:WINDIR\system32\tmp",
                    "$env:WINDIR\SysWOW64\tmp",
                    "$env:APPDATA\temp",
                    "$env:LOCALAPPDATA\Microsoft\Windows\WebCache\*.log",
                    "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\*.dat"
                )
                
                foreach ($tempPath in $additionalTempPaths) {
                    if ([string]::IsNullOrWhiteSpace($tempPath)) {
                        continue
                    }
                    
                    if ($tempPath -like "*\*.*") {
                        $parentPath = Split-Path $tempPath -Parent
                        $filePattern = Split-Path $tempPath -Leaf
                        if (Test-Path $parentPath) {
                            $tempFiles = Get-ChildItem -Path $parentPath -Filter $filePattern -Force -ErrorAction SilentlyContinue |
                            Where-Object { -not $_.PSIsContainer -and $_.Length -gt 0 -and $_.Length -lt 100MB }
                            
                            if ($tempFiles) {
                                foreach ($file in $tempFiles) {
                                    try {
                                        $fileSize = $file.Length
                                        Remove-Item $file.FullName -Force -ErrorAction Stop
                                        $totalFiles++
                                        $totalSize += $fileSize
                                    }
                                    catch {
                                        # Use centralized locked file logging
                                        Write-LockedFileLog -FileName $file.Name -Category "Additional Temp Files"
                                    }
                                }
                            }
                        }
                    }
                    elseif (Test-Path $tempPath) {
                        $tempFiles = Get-ChildItem -Path $tempPath -Force -ErrorAction SilentlyContinue |
                        Where-Object { 
                            -not $_.PSIsContainer -and 
                            $_.Length -gt 0 -and 
                            $_.Length -lt 100MB
                        }
                        
                        if ($tempFiles) {
                            foreach ($file in $tempFiles) {
                                try {
                                    $fileSize = $file.Length
                                    Remove-Item $file.FullName -Force -ErrorAction Stop
                                    $totalFiles++
                                    $totalSize += $fileSize
                                }
                                catch {
                                    # Use centralized locked file logging
                                    Write-LockedFileLog -FileName $file.Name -Category $pathInfo.Name
                                }
                            }
                        }
                    }
                }
            }
            catch {
                Write-SimpleLog "Error cleaning additional temp paths: $($_.Exception.Message)"
            }
            
            return @{ Files = $totalFiles; Size = $totalSize }
        }
        catch {
            Write-SimpleLog "Error in system temp file cleanup: $($_.Exception.Message)"
            return @{ Files = 0; Size = 0 }
        }
    }

    function Clear-ThumbnailFiles {
        try {
            # Note: Main thumbnail cache deletion is moved to Explorer restart section
            # This function now handles non-Explorer-locked caches only
            
            $thumbnailPaths = @(
                "$env:LOCALAPPDATA\Thumbnails",
                "$env:LOCALAPPDATA\Microsoft\Media Player",
                "$env:APPDATA\Microsoft\Windows\Themes\CachedFiles",
                "$env:LOCALAPPDATA\Microsoft\Windows\Caches"
            )
            
            $totalSize = 0
            $totalFiles = 0
            
            foreach ($path in $thumbnailPaths) {
                if ([string]::IsNullOrWhiteSpace($path)) {
                    continue
                }
                
                if (Test-Path $path) {
                    try {
                        $allThumbnails = Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
                        Where-Object { 
                            -not $_.PSIsContainer -and 
                            (
                                $_.Extension -in @('.db', '.tmp', '.cache') -or
                                $_.Name -like "thumb*" -or
                                $_.Name -like "Thumb*" -or
                                $_.Name -like "*cache*"
                            ) -and
                            $_.Length -gt 0 -and 
                            $_.Length -lt 100MB
                        }
                        
                        $pathSize = 0
                        $pathFiles = 0
                        
                        if ($allThumbnails) {
                            foreach ($file in $allThumbnails) {
                                try {
                                    $fileSize = $file.Length
                                    Remove-Item $file.FullName -Force -ErrorAction Stop
                                    $pathFiles++
                                    $pathSize += $fileSize
                                    $totalFiles++
                                    $totalSize += $fileSize
                                }
                                catch {
                                    # Silent failure for locked files
                                }
                            }
                        }
                        
                        if ($pathFiles -gt 0) {
                            $pathSizeMB = [Math]::Round($pathSize / 1MB, 1)
                            Write-SimpleLog "Thumbnails from $path`: $pathFiles files, $pathSizeMB MB"
                        }
                    }
                    catch {
                        Write-SimpleLog "Error processing thumbnails in $path`: $($_.Exception.Message)"
                    }
                }
            }
            
            $sizeMB = [Math]::Round($totalSize / 1MB, 1)
            Write-SimpleLog "Thumbnail cleanup (non-Explorer): $totalFiles files, $sizeMB MB"
            return @{ Files = $totalFiles; Size = $totalSize }
        }
        catch {
            Write-SimpleLog "Error in thumbnail cleanup: $($_.Exception.Message)"
            return @{ Files = 0; Size = 0 }
        }
    }

    function Clear-WindowsUpgradeLogs {
        try {
            if (-not $script:AggressiveLogCleanup) {
                Write-SimpleLog "Aggressive log cleanup disabled - skipping Windows upgrade logs"
                return @{ Files = 0; Size = 0 }
            }
            
            Write-SimpleLog "Targeting Windows upgrade logs with aggressive cleanup (enabled)"
            
            $totalSize = 0
            $totalFiles = 0
            
            $upgradeLogPaths = @(
                @{ Path = "$env:WINDIR\Logs\DPX"; Name = "Device Driver Install Logs"; AgeDays = 0; MaxSize = 10GB },
                @{ Path = "$env:WINDIR\Logs\MoSetup"; Name = "Modern Setup Logs"; AgeDays = 0; MaxSize = 10GB },
                @{ Path = "$env:WINDIR\Panther"; Name = "Setup Panther Logs"; AgeDays = 0; MaxSize = 20GB },
                @{ Path = "$env:WINDIR\Logs\SetupPlatform"; Name = "Setup Platform Logs"; AgeDays = 0; MaxSize = 5GB },
                @{ Path = "$env:WINDIR\Logs\DISM"; Name = "DISM Logs"; AgeDays = 0; MaxSize = 5GB },
                @{ Path = "$env:WINDIR\Logs\waasmedic"; Name = "WAAS Medic Logs"; AgeDays = 0; MaxSize = 2GB },
                @{ Path = "$env:WINDIR\Logs\CBS"; Name = "CBS Setup Logs"; AgeDays = 0; MaxSize = 30GB },
                @{ Path = "$env:WINDIR\Logs\WindowsUpdate"; Name = "Windows Update Logs"; AgeDays = 0; MaxSize = 5GB },
                @{ Path = "$env:WINDIR\System32\LogFiles\Srt"; Name = "System Restore Logs"; AgeDays = 0; MaxSize = 2GB },
                @{ Path = "$env:WINDIR\inf"; Name = "INF Setup Logs"; AgeDays = 0; MaxSize = 5GB }
            )
            
            foreach ($pathInfo in $upgradeLogPaths) {
                if ($pathInfo -and $pathInfo.Path -and (Test-Path $pathInfo.Path)) {
                    try {
                        $logFiles = Get-ChildItem -Path $pathInfo.Path -Recurse -Force -ErrorAction SilentlyContinue |
                        Where-Object { 
                            -not $_.PSIsContainer -and 
                            (
                                ($_.Extension -in @('.log', '.txt', '.cab', '.xml', '.old', '.etl', '.evtx', '.bak', '.tmp')) -or 
                                ($_.Name -like "*.log.*") -or
                                ($_.Name -like "setupact*") -or
                                ($_.Name -like "setuperr*") -or
                                ($_.Name -like "*setup*") -or
                                ($_.Name -like "*install*") -or
                                ($_.Name -like "*upgrade*")
                            ) -and
                            $_.Length -gt 100 -and 
                            $_.Length -lt $pathInfo.MaxSize
                        }
                        
                        if ($pathInfo.Name -eq "INF Setup Logs") {
                            $logFiles = $logFiles | Where-Object { 
                                $_.Extension -in @('.log', '.txt') -and
                                ($_.Name -like "*setup*" -or $_.Name -like "*install*" -or $_.Name -like "*oem*")
                            }
                        }
                        
                        $pathSize = 0
                        $pathFiles = 0
                        
                        if ($logFiles) {
                            foreach ($file in $logFiles) {
                                try {
                                    $fileSize = $file.Length
                                    Remove-Item $file.FullName -Force -ErrorAction Stop
                                    $pathFiles++
                                    $pathSize += $fileSize
                                    $totalFiles++
                                    $totalSize += $fileSize
                                }
                                catch {
                                    Write-SimpleLog "Could not remove upgrade log: $($file.Name)"
                                }
                            }
                        }
                        
                        if ($pathFiles -gt 0) {
                            $pathSizeMB = [Math]::Round($pathSize / 1MB, 1)
                            Write-SimpleLog "$($pathInfo.Name): $pathFiles files, $pathSizeMB MB"
                        }
                        else {
                            Write-SimpleLog "No upgrade logs found in $($pathInfo.Name) ($($pathInfo.Path))"
                        }
                    }
                    catch {
                        Write-SimpleLog "Error processing $($pathInfo.Name) in $($pathInfo.Path): $($_.Exception.Message)"
                    }
                }
                else {
                    if ($pathInfo -and $pathInfo.Path) {
                        Write-SimpleLog "Upgrade log path does not exist: $($pathInfo.Path)"
                    }
                }
            }
            
            # Cleanup standalone setup files
            try {
                $setupFiles = @(
                    @{ Name = "setupact.log"; MaxSize = 2GB },
                    @{ Name = "setuperr.log"; MaxSize = 2GB },
                    @{ Name = "setupapi.log"; MaxSize = 2GB },
                    @{ Name = "setupapi.dev.log"; MaxSize = 2GB },
                    @{ Name = "setupapi.offline.log"; MaxSize = 2GB },
                    @{ Name = "setupapi.app.log"; MaxSize = 1GB }
                )
                
                foreach ($setupFileInfo in $setupFiles) {
                    if ($setupFileInfo -and $setupFileInfo.Name) {
                        $filePath = Join-Path $env:WINDIR $setupFileInfo.Name
                        if (Test-Path $filePath) {
                            try {
                                $file = Get-Item $filePath -Force
                                if ($file.Length -gt 1MB -and $file.Length -lt $setupFileInfo.MaxSize) {
                                    $fileSize = $file.Length
                                    Remove-Item $filePath -Force -ErrorAction Stop
                                    $totalFiles++
                                    $totalSize += $fileSize
                                    Write-SimpleLog "Removed setup log: $($setupFileInfo.Name) ($([Math]::Round($fileSize/1MB, 1)) MB)"
                                }
                            }
                            catch {
                                Write-SimpleLog "Could not remove $($setupFileInfo.Name): File may be in use"
                            }
                        }
                    }
                }
            }
            catch {
                Write-SimpleLog "Error cleaning setup logs: $($_.Exception.Message)"
            }
            
            # Cleanup additional old logs
            try {
                $additionalLogPaths = @(
                    "$env:WINDIR\Logs",
                    "$env:WINDIR\System32\LogFiles",
                    "$env:WINDIR\SoftwareDistribution\DataStore\Logs"
                )
                
                foreach ($logPath in $additionalLogPaths) {
                    if ([string]::IsNullOrWhiteSpace($logPath)) {
                        continue
                    }
                    
                    if (Test-Path $logPath) {
                        $oldLogs = Get-ChildItem -Path $logPath -Recurse -Force -ErrorAction SilentlyContinue |
                        Where-Object { 
                            -not $_.PSIsContainer -and 
                            $_.Extension -in @('.log', '.old', '.bak', '.cab', '.zip', '.gz', '.etl') -and
                            $_.Length -gt 1MB -and 
                            $_.Length -lt 10GB -and
                            $_.LastWriteTime -lt (Get-Date).AddDays(-7)
                        }
                        
                        $logSize = 0
                        $logCount = 0
                        
                        if ($oldLogs) {
                            foreach ($file in $oldLogs) {
                                try {
                                    $fileSize = $file.Length
                                    Remove-Item $file.FullName -Force -ErrorAction Stop
                                    $logCount++
                                    $logSize += $fileSize
                                    $totalFiles++
                                    $totalSize += $fileSize
                                }
                                catch {
                                    # Silent failure for locked files
                                }
                            }
                        }
                        
                        if ($logCount -gt 0) {
                            $logSizeMB = [Math]::Round($logSize / 1MB, 1)
                            Write-SimpleLog "Additional logs from $logPath`: $logCount files, $logSizeMB MB"
                        }
                    }
                }
            }
            catch {
                Write-SimpleLog "Error cleaning additional logs: $($_.Exception.Message)"
            }
            
            $sizeMB = [Math]::Round($totalSize / 1MB, 1)
            if ($totalFiles -gt 0) {
                Write-SimpleLog "Windows upgrade logs cleanup: $totalFiles files, $sizeMB MB"
            }
            else {
                Write-SimpleLog "Windows upgrade logs: No files found to clean"
            }
            
            return @{ Files = $totalFiles; Size = $totalSize }
        }
        catch {
            Write-SimpleLog "Error in Windows upgrade logs cleanup: $($_.Exception.Message)"
            return @{ Files = 0; Size = 0 }
        }
    }

    function Clear-ExplorerCaches {
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$JobId
        )
        
        try {
            Write-SimpleLog "Clearing Explorer-locked caches during Explorer restart"
            
            $totalSize = 0
            $totalFiles = 0
            
            # Primary icon and thumbnail caches that are locked by Explorer
            $explorerCacheFiles = @(
                "$env:LOCALAPPDATA\IconCache.db"
            )
            
            # Add Explorer thumbnail cache files
            try {
                $additionalCaches = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\*.db" -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match "(thumbcache|iconcache)_.*\.db$" }
                
                if ($additionalCaches) {
                    $explorerCacheFiles += $additionalCaches.FullName
                }
            }
            catch {
                Write-SimpleLog "Could not enumerate additional Explorer caches: $($_.Exception.Message)"
            }
            
            $cachesCleaned = 0
            foreach ($cacheFile in $explorerCacheFiles) {
                if ([string]::IsNullOrWhiteSpace($cacheFile)) {
                    continue
                }
                
                try {
                    if (Test-Path $cacheFile) {
                        $file = Get-Item $cacheFile -Force
                        $fileSize = $file.Length
                        Remove-Item $cacheFile -Force -ErrorAction Stop
                        $cachesCleaned++
                        $totalFiles++
                        $totalSize += $fileSize
                        $fileSizeMB = [Math]::Round($fileSize / 1MB, 1)
                        Write-SimpleLog "Removed Explorer cache: $(Split-Path $cacheFile -Leaf) ($fileSizeMB MB)"
                    }
                }
                catch {
                    Write-SimpleLog "Could not remove cache: $(Split-Path $cacheFile -Leaf)"
                }
            }
            
            Write-SimpleLog "Explorer cache cleanup: $cachesCleaned caches cleared, $([Math]::Round($totalSize / 1MB, 1)) MB"
            return @{ Files = $totalFiles; Size = $totalSize }
        }
        catch {
            Write-SimpleLog "Error in Explorer cache cleanup: $($_.Exception.Message)"
            return @{ Files = 0; Size = 0 }
        }
    }

    # Copy parameters to script scope for access by functions
    $script:LogPath = $LogPath
    $script:JobId = $JobId
    $script:CleanupTimeoutSeconds = $CleanupTimeoutSeconds
    $script:AggressiveLogCleanup = $AggressiveLogCleanup
    
    # Track logged locked files globally to reduce noise
    $script:loggedLockedFiles = @{}

    # Main execution starts here
    try {
        Write-SimpleLog "Enhanced Windows 11 disk cleanup started with Job ID: $JobId"
        Write-SimpleLog "Configuration: CleanupTimeout=$CleanupTimeoutSeconds seconds, AggressiveLogCleanup=$AggressiveLogCleanup"
        Update-Progress -Percent 0 -Message "Starting enhanced cleanup with improved methods..."
        
        Update-Progress -Percent 5 -Message "Detecting available cleanup categories..."
        
        try {
            $availableCategories = Get-AvailableCleanupCategories
            Write-SimpleLog "Available categories: $($availableCategories -join ', ')"
        }
        catch {
            Write-SimpleLog "Category detection failed, using fallback list: $($_.Exception.Message)"
            $availableCategories = @("Temporary Files", "Recycle Bin", "Temporary Internet Files", "Thumbnails", "Downloaded Program Files")
        }
        
        Update-Progress -Percent 10 -Message "Configuring $($availableCategories.Count) cleanup categories..."
        
        $cleanupSuccess = $false
        try {
            $cleanupSuccess = Invoke-EnhancedCleanup -Categories $availableCategories -SageSet 65
        }
        catch {
            Write-SimpleLog "Enhanced cleanup failed: $($_.Exception.Message)"
        }
        
        Update-Progress -Percent 20 -Message "Registry cleanup configuration completed"
        
        # Windows.old handling
        $windowsOldPath = "C:\Windows.old"
        $windowsOldExists = Test-Path $windowsOldPath
        $windowsOldRemoved = $false
        
        if ($windowsOldExists) {
            Update-Progress -Percent 25 -Message "Windows.old folder detected - requesting user decision..."
            Write-Output "WINDOWS_OLD_EXISTS:True"
            Write-Output "WINDOWS_OLD_PATH:$windowsOldPath"
            
            $timeout = (Get-Date).AddSeconds(90)
            $decision = $null
            $checkCount = 0
            
            while ((Get-Date) -lt $timeout -and $null -eq $decision) {
                $userTempPath = [System.IO.Path]::GetTempPath()
                $decisionFile = [System.IO.Path]::Combine($userTempPath, "RepairToolkit_${JobId}_WINDOWSOLD_DECISION.tmp")
                
                if (Test-Path $decisionFile) {
                    try {
                        $decision = Get-Content $decisionFile -Raw -ErrorAction SilentlyContinue
                        Remove-Item $decisionFile -Force -ErrorAction SilentlyContinue
                        if ($null -ne $decision) {
                            $decision = $decision.Trim()
                        }
                        Write-SimpleLog "User decision received: '$decision'"
                        break
                    }
                    catch {
                        Write-SimpleLog "Error reading decision file: $($_.Exception.Message)"
                    }
                }
                
                $checkCount++
                if ($checkCount % 10 -eq 0) {
                    Write-SimpleLog "Waiting for Windows.old decision... (check $checkCount)"
                }
                Start-Sleep -Seconds 2
            }
            
            if ($decision -eq "YES") {
                Update-Progress -Percent 30 -Message "Removing Windows.old folder using enhanced methods..."
                try {
                    $windowsOldRemoved = Remove-WindowsOld -WindowsOldPath $windowsOldPath
                    
                    if ($windowsOldRemoved) {
                        Update-Progress -Percent 35 -Message "Windows.old folder successfully removed"
                    }
                    else {
                        Update-Progress -Percent 35 -Message "Windows.old removal attempted - may require manual cleanup"
                    }
                }
                catch {
                    Write-SimpleLog "Windows.old removal failed: $($_.Exception.Message)"
                    Update-Progress -Percent 35 -Message "Windows.old removal encountered errors"
                }
            }
            else {
                Update-Progress -Percent 35 -Message "Windows.old folder preserved per user choice"
            }
        }
        else {
            Update-Progress -Percent 35 -Message "No Windows.old folder detected"
        }
        
        Update-Progress -Percent 40 -Message "Windows.old processing completed"
        
        # Run all cleanup functions
        Update-Progress -Percent 45 -Message "Running Microsoft Defender cleanup..."
        $defenderResult = Clear-DefenderFiles
        
        Update-Progress -Percent 50 -Message "Running Delivery Optimization cleanup..."
        $deliveryResult = Clear-DeliveryOptimization
        
        Update-Progress -Percent 55 -Message "Running Internet temporary files cleanup..."
        $internetResult = Clear-InternetTemporaryFiles
        
        Update-Progress -Percent 60 -Message "Running system temporary files cleanup..."
        $tempResult = Clear-SystemTemporaryFiles
        
        Update-Progress -Percent 65 -Message "Running thumbnails cleanup..."
        $thumbResult = Clear-ThumbnailFiles
        
        Update-Progress -Percent 67 -Message "Running Windows upgrade logs cleanup..."
        $upgradeResult = Clear-WindowsUpgradeLogs
        
        $customCleanupTotal = $defenderResult.Size + $deliveryResult.Size + $internetResult.Size + $tempResult.Size + $thumbResult.Size + $upgradeResult.Size
        $customCleanupMB = [Math]::Round($customCleanupTotal / 1MB, 1)
        
        # Run native cleanup as fallback if custom cleanup was insufficient
        if ($customCleanupMB -lt 50 -and $cleanupSuccess) {
            Update-Progress -Percent 68 -Message "Running native Windows cleanup as fallback..."
            try {
                Write-SimpleLog "Custom cleanup only freed $customCleanupMB MB (threshold: 50MB), running native cleanmgr as fallback"
                
                $cleanmgrProcess = Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/SAGERUN:65" -WindowStyle Hidden -PassThru -ErrorAction Stop
                $cleanmgrCompleted = $cleanmgrProcess.WaitForExit(($CleanupTimeoutSeconds / 2) * 1000)
                
                if ($cleanmgrCompleted) {
                    Write-SimpleLog "Native cleanup completed with exit code: $($cleanmgrProcess.ExitCode)"
                    if ($cleanmgrProcess.ExitCode -eq 0) {
                        Write-SimpleLog "Native cleanup completed successfully - should have cleaned remaining files"
                    }
                }
                else {
                    Write-SimpleLog "Native cleanup timed out after $($CleanupTimeoutSeconds / 2) seconds, terminating"
                    $cleanmgrProcess.Kill()
                }
            }
            catch {
                Write-SimpleLog "Native cleanup fallback failed: $($_.Exception.Message)"
            }
        }
        else {
            Write-SimpleLog "Custom cleanup freed $customCleanupMB MB (threshold: 50MB) - skipping native fallback"
        }
        
        Update-Progress -Percent 70 -Message "Targeted cleanup phases completed"
        
        # Network optimization
        Update-Progress -Percent 75 -Message "Optimizing system performance..."
        
        try {
            $dnsResult = & ipconfig /flushdns 2>&1
            $winsockResult = & netsh winsock reset 2>&1
            
            if ($dnsResult -match "Successfully flushed") {
                Write-SimpleLog "DNS cache flushed successfully"
            }
            else {
                Write-SimpleLog "DNS flush result: $dnsResult"
            }
            
            if ($winsockResult -match "Successfully reset") {
                Write-SimpleLog "Winsock reset result: $winsockResult"
            }
            
            Write-SimpleLog "Network optimization completed: DNS flushed, Winsock reset"
        }
        catch {
            Write-SimpleLog "Network optimization failed: $($_.Exception.Message)"
        }
        
        # Explorer restart for visual optimization
        Update-Progress -Percent 85 -Message "Preparing visual performance optimization..."
        Write-Output "EXPLORER_RESTART_REQUEST:True"
        
        $timeout = (Get-Date).AddSeconds(120)
        $explorerDecision = $null
        
        while ((Get-Date) -lt $timeout -and $null -eq $explorerDecision) {
            $userTempPath = [System.IO.Path]::GetTempPath()
            $explorerFile = [System.IO.Path]::Combine($userTempPath, "RepairToolkit_${JobId}_EXPLORER_RESTART.tmp")
            
            if (Test-Path $explorerFile) {
                try {
                    $explorerDecision = Get-Content $explorerFile -Raw -ErrorAction SilentlyContinue
                    Remove-Item $explorerFile -Force -ErrorAction SilentlyContinue
                    if ($null -ne $explorerDecision) {
                        $explorerDecision = $explorerDecision.Trim()
                    }
                    break
                }
                catch {
                    Write-SimpleLog "Error reading Explorer decision: $($_.Exception.Message)"
                }
            }
            Start-Sleep -Seconds 1
        }
        
        $explorerCacheResult = @{ Files = 0; Size = 0 }
        
        if ($explorerDecision -eq "YES") {
            Update-Progress -Percent 87 -Message "Restarting Explorer for visual optimization..."
            try {
                # Stop Explorer
                Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
                
                # Wait for Explorer to stop with longer timeout for Explorer specifically
                $explorerStopped = Wait-ProcessStop -ProcessName "explorer" -TimeoutSeconds 15
                if ($explorerStopped) {
                    Write-SimpleLog "Explorer stopped successfully"
                }
                else {
                    Write-SimpleLog "Explorer may not have stopped completely, proceeding anyway"
                }
                
                # Give additional time for file handles to release
                Start-Sleep -Seconds 2
                
                # Clear Explorer-locked caches while Explorer is stopped
                $explorerCacheResult = Clear-ExplorerCaches -JobId $JobId
                
                # Restart Explorer
                Start-Process "explorer.exe" -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                
                $explorerRunning = Get-Process -Name "explorer" -ErrorAction SilentlyContinue
                if ($explorerRunning) {
                    Update-Progress -Percent 90 -Message "Visual performance optimized - Explorer restarted successfully"
                    Write-SimpleLog "Explorer restarted successfully. Explorer caches cleared."
                }
                else {
                    Update-Progress -Percent 90 -Message "Explorer restart attempted - desktop should recover automatically"
                }
            }
            catch {
                Write-SimpleLog "Explorer restart failed: $($_.Exception.Message)"
                Update-Progress -Percent 90 -Message "Visual optimization completed with issues"
                
                try {
                    Start-Process "explorer.exe" -ErrorAction SilentlyContinue
                }
                catch {
                    Write-SimpleLog "Explorer fallback restart failed"
                }
            }
        }
        else {
            Update-Progress -Percent 90 -Message "Visual optimization skipped per user choice"
        }
        
        # Final reporting
        $jobDuration = (Get-Date) - $jobStartTime
        Update-Progress -Percent 100 -Message "Enhanced cleanup and optimization completed!"
        
        $totalFiles = $defenderResult.Files + $deliveryResult.Files + $internetResult.Files + $tempResult.Files + $thumbResult.Files + $upgradeResult.Files + $explorerCacheResult.Files
        $totalSize = $defenderResult.Size + $deliveryResult.Size + $internetResult.Size + $tempResult.Size + $thumbResult.Size + $upgradeResult.Size + $explorerCacheResult.Size
        $totalSizeMB = [Math]::Round($totalSize / 1MB, 1)
        
        Write-SimpleLog "=== TARGETED CLEANUP SUMMARY ==="
        Write-SimpleLog "Registry cleanup success: $cleanupSuccess"
        Write-SimpleLog "Microsoft Defender cleanup: $($defenderResult.Files) files, $([Math]::Round($defenderResult.Size / 1MB, 1)) MB"
        Write-SimpleLog "Delivery Optimization cleanup: $($deliveryResult.Files) files, $([Math]::Round($deliveryResult.Size / 1MB, 1)) MB"
        Write-SimpleLog "Internet temporary files cleanup: $($internetResult.Files) files, $([Math]::Round($internetResult.Size / 1MB, 1)) MB"
        Write-SimpleLog "System temporary files cleanup: $($tempResult.Files) files, $([Math]::Round($tempResult.Size / 1MB, 1)) MB"
        Write-SimpleLog "Thumbnails cleanup: $($thumbResult.Files) files, $([Math]::Round($thumbResult.Size / 1MB, 1)) MB"
        Write-SimpleLog "Windows upgrade logs cleanup: $($upgradeResult.Files) files, $([Math]::Round($upgradeResult.Size / 1MB, 1)) MB"
        Write-SimpleLog "Explorer cache cleanup: $($explorerCacheResult.Files) files, $([Math]::Round($explorerCacheResult.Size / 1MB, 1)) MB"
        Write-SimpleLog "Windows.old removed: $windowsOldRemoved"
        Write-SimpleLog "TOTAL TARGETED CLEANUP: $totalFiles files, $totalSizeMB MB freed"
        $durationText = "{0:D2}:{1:D2}" -f [int][Math]::Floor($jobDuration.TotalMinutes), [int]$jobDuration.Seconds
        Write-SimpleLog "Targeted cleanup completed in $durationText"
        
        $windowsOldFinallyRemoved = $windowsOldExists -and $windowsOldRemoved -and (-not (Test-Path $windowsOldPath))
        if ($windowsOldExists -and $windowsOldRemoved -and (Test-Path $windowsOldPath)) {
            try {
                $remainingSize = (Get-ChildItem $windowsOldPath -Recurse -Force -ErrorAction SilentlyContinue | 
                    Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                
                if ($null -eq $remainingSize) {
                    $remainingSize = 0
                }
                
                $remainingSizeMB = [Math]::Round($remainingSize / 1MB, 1)
                Write-SimpleLog "Windows.old still exists with $remainingSizeMB MB remaining"
            }
            catch {
                Write-SimpleLog "Could not check Windows.old final status"
            }
        }
        
        Write-Output "FINAL_RESULT_START"
        Write-Output ([PSCustomObject]@{
                ExitCode                  = 0
                StandardError             = ""
                WindowsOldExists          = $windowsOldExists
                WindowsOldRemoved         = $windowsOldRemoved
                WindowsOldActuallyRemoved = $windowsOldFinallyRemoved
                JobType                   = "TARGETED_CATEGORY_CLEANUP"
                TotalFilesRemoved         = $totalFiles
                TotalSpaceFreedMB         = $totalSizeMB
                DefenderCleanupMB         = [Math]::Round($defenderResult.Size / 1MB, 1)
                DeliveryOptimizationMB    = [Math]::Round($deliveryResult.Size / 1MB, 1)
                InternetTempFilesMB       = [Math]::Round($internetResult.Size / 1MB, 1)
                SystemTempFilesMB         = [Math]::Round($tempResult.Size / 1MB, 1)
                ThumbnailsMB              = [Math]::Round($thumbResult.Size / 1MB, 1)
                WindowsUpgradeLogsMB      = [Math]::Round($upgradeResult.Size / 1MB, 1)
                ExplorerCacheMB           = [Math]::Round($explorerCacheResult.Size / 1MB, 1)
                RegistryCleanupSuccess    = $cleanupSuccess
                AggressiveLogCleanup      = $AggressiveLogCleanup
                Duration                  = $jobDuration
                AvailableCategories       = $availableCategories.Count
                CompletedTasks            = "Registry cleanup configuration, Windows.old removal, targeted Defender cleanup, Delivery Optimization cleanup, Internet temporary files cleanup, system temporary files cleanup, thumbnails cleanup, Windows upgrade logs cleanup, Explorer cache cleanup, network optimization, visual optimization"
            })
        Write-Output "FINAL_RESULT_END"
        
        Write-SimpleLog "Targeted cleanup job completed successfully"
        
    }
    catch {
        $jobDuration = (Get-Date) - $jobStartTime
        $errorMessage = "Critical error in targeted cleanup: $($_.Exception.Message)"
        Write-SimpleLog $errorMessage
        Write-Output "PROGRESS_LINE:ERROR: $errorMessage"
        
        Write-Output "FINAL_RESULT_START"
        Write-Output ([PSCustomObject]@{ 
                ExitCode      = -999
                StandardError = $errorMessage
                JobType       = "TARGETED_CATEGORY_CLEANUP"
                Duration      = $jobDuration
            })
        Write-Output "FINAL_RESULT_END"
    }
}
#endregion

#region Enhanced Job Management Functions
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
    if ($null -ne $script:currentRepairJob) {
        $message = "Another repair operation is already in progress. Please wait for it to complete before starting a new one."
        Show-WarningMessage -Message $message
        Write-RepairLog -Message "Job start blocked: Another job is running ($($script:currentRepairJob.Name))" -Category "WARNING"
        return $false
    }
    
    $executableFound = $false
    if (Test-Path $Executable -PathType Leaf) {
        $executableFound = $true
    }
    else {
        try {
            $null = Get-Command $Executable -ErrorAction Stop
            $executableFound = $true
        }
        catch {
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
    
    $script:operationStartTime = Get-Date
    $script:progressMessageCount = 0
    $script:capturedJobResult = $null
    $script:fallbackProgressEnabled = $false
    $script:progressCommunicationFailures = 0
    $script:lastFallbackLogTime = $null
    
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
    
    Update-UiForJobStart -StatusMessage "System Optimization in progress... 0%"
    
    $script:operationStartTime = Get-Date
    $script:progressMessageCount = 0
    $script:capturedJobResult = $null
    $script:currentJobId = [System.Guid]::NewGuid().ToString("N").Substring(0, 12)
    $script:lastUiUpdate = $null
    $script:fallbackProgressEnabled = $false
    $script:progressCommunicationFailures = 0
    $script:lastProgressUpdate = Get-Date
    $script:lastFallbackLogTime = $null
    
    Write-RepairLog -Message "Cleanup operation initialized with Job ID: $script:currentJobId" -Category "JOB" -Operation "CLEANUP"
    Write-RepairLog -Message "Log path for background job: $script:logPath" -Category "JOB" -Operation "CLEANUP"
    
    if ([string]::IsNullOrWhiteSpace($script:logPath)) {
        Write-RepairLog -Message "WARNING: Log path is empty, job may have logging issues" -Category "WARNING" -Operation "CLEANUP"
    }
    
    try {
        $script:currentRepairJob = Start-Job -Name "DiskCleanupJob" -ScriptBlock $script:diskCleanupScriptBlock -ArgumentList $script:logPath, $script:currentJobId
        
        Start-ProgressTimer
        Write-RepairLog -Message "Cleanup background job started successfully with PID: $($script:currentRepairJob.Id)" -Category "JOB" -Operation "CLEANUP"
        
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
function Start-ProgressTimer {
    [CmdletBinding()]
    param()
    
    try {
        Stop-ProgressTimer
        
        if ($form.IsDisposed -or $form.Disposing) {
            Write-RepairLog -Message "Cannot start timer - form is disposed" -Category "WARNING"
            return
        }
        
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
            try {
                $script:progressUpdateTimer.Stop()
            }
            catch {
            }
            
            try {
                $script:progressUpdateTimer.Remove_Tick($script:progressTimerAction)
            }
            catch {
            }
            
            try {
                $script:progressUpdateTimer.Dispose()
            }
            catch {
            }
            
            $script:progressUpdateTimer = $null
            Write-RepairLog -Message "Progress timer stopped and disposed successfully" -Category "JOB"
        }
    }
    catch {
        Write-RepairLog -Message "Error stopping progress timer: $($_.Exception.Message)" -Category "WARNING"
        $script:progressUpdateTimer = $null
    }
}
#endregion

#region Enhanced Progress Timer and Job Processing
$script:progressTimerAction = {
    if ($form.IsDisposed -or $form.Disposing) {
        return
    }
    
    if (-not [System.Threading.Monitor]::TryEnter($script:timerLock, 100)) { 
        return 
    }
    
    try {
        if ($null -eq $script:currentRepairJob -or $form.IsDisposed -or $form.Disposing) {
            Stop-ProgressTimer
            return
        }
        if ($progressBar.IsDisposed) {
            Stop-ProgressTimer
            return
        }
        if ($script:currentRepairJob.State -ne [System.Management.Automation.JobState]::Running) {
            Write-RepairLog -Message "Job state changed to: $($script:currentRepairJob.State)" -Category "JOB"
            Complete-JobExecution
            return
        }
        try {
            $hasNewProgress = $false
            
            # Try multiple times to get job output
            for ($attempt = 1; $attempt -le 3; $attempt++) {
                if ($script:currentRepairJob.HasMoreData) {
                    $outputReceived = Receive-JobOutput
                    if ($outputReceived) {
                        $hasNewProgress = $true
                        break
                    }
                }
                if ($attempt -lt 3) {
                    Start-Sleep -Milliseconds 50
                }
            }
            
            $jobRuntime = if ($script:operationStartTime) { 
                (Get-Date) - $script:operationStartTime 
            }
            else { 
                New-TimeSpan 
            }
            
            if (-not $hasNewProgress -and $jobRuntime.TotalSeconds -gt 30) {
                $script:progressCommunicationFailures++
                if ($script:progressCommunicationFailures -ge $script:CONSTANTS.PROGRESS_COMM_FAILURE_LIMIT -and 
                    -not $script:fallbackProgressEnabled) {
                    Enable-FallbackProgress
                }
            }
            else {
                if ($hasNewProgress) {
                    $script:progressCommunicationFailures = 0
                }
            }
            
            if ($script:fallbackProgressEnabled) {
                Update-FallbackProgress
            }
            
            Update-SfcProgress
            Update-StatusDisplay
        }
        catch [System.ObjectDisposedException] {
            Write-RepairLog -Message "UI object disposed during timer execution - stopping timer" -Category "WARNING"
            Stop-ProgressTimer
            return
        }
        catch {
            Write-RepairLog -Message "Error in timer job processing: $($_.Exception.Message)" -Category "WARNING"
        }
        
    }
    catch [System.ObjectDisposedException] {
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
        }
    }
    finally {
        try {
            [System.Threading.Monitor]::Exit($script:timerLock)
        }
        catch {
        }
    }
}
function Enable-FallbackProgress {
    $script:fallbackProgressEnabled = $true
    $elapsed = if ($script:operationStartTime) { (Get-Date) - $script:operationStartTime } else { New-TimeSpan }
    Write-RepairLog -Message "Enabling fallback progress estimation after $($script:progressCommunicationFailures) communication failures (elapsed: $($elapsed.ToString('mm\:ss')))" -Category "WARNING"
}
function Update-FallbackProgress {
    if ($null -eq $script:operationStartTime) { return }
    
    $elapsed = (Get-Date) - $script:operationStartTime
    $jobDisplayName = Get-JobDisplayName -JobName $script:currentRepairJob.Name
    
    $estimatedProgress = switch ($jobDisplayName) {
        "DISM Repair" {
            [Math]::Min(($elapsed.TotalMinutes / 10) * 90, 90)
        }
        "SFC Scan" {
            [Math]::Min(($elapsed.TotalMinutes / 20) * 90, 90)
        }
        "System Optimization" {
            [Math]::Min(($elapsed.TotalMinutes / 5) * 90, 90)
        }
        default {
            [Math]::Min(($elapsed.TotalMinutes / 10) * 90, 90)
        }
    }
    
    $timeSinceLastUpdate = if ($script:lastProgressUpdate) { 
        (Get-Date) - $script:lastProgressUpdate 
    }
    else { 
        $elapsed 
    }
    
    if ($timeSinceLastUpdate.TotalSeconds -gt 45 -and $estimatedProgress -gt $progressBar.Value) {
        try {
            if (-not $progressBar.IsDisposed) {
                $progressBar.Value = [int]$estimatedProgress
                $progressBar.Refresh()
                
                $lastFallbackLog = $script:lastFallbackLogTime
                if ($null -eq $lastFallbackLog -or ((Get-Date) - $lastFallbackLog).TotalSeconds -gt 30) {
                    Write-RepairLog -Message "Fallback progress: $([int]$estimatedProgress)% (elapsed: $($elapsed.ToString('mm\:ss')), no updates for $([int]$timeSinceLastUpdate.TotalSeconds)s)" -Category "INFO"
                    $script:lastFallbackLogTime = Get-Date
                }
            }
        }
        catch {
        }
    }
}
function Test-JobCompletion {
    return ($script:currentRepairJob.State -ne [System.Management.Automation.JobState]::Running)
}
function Complete-JobExecution {
    try {
        Stop-ProgressTimer
        if ($form.IsDisposed -or $form.Disposing) {
            return
        }
        $jobToProcess = $script:currentRepairJob
        $script:currentRepairJob = $null
        if ($null -eq $jobToProcess) {
            Write-RepairLog -Message "Job completion called but no job reference found" -Category "WARNING"
            return
        }
        Write-RepairLog -Message "Job '$($jobToProcess.Name)' completed with state: $($jobToProcess.State)" -Category "JOB"
        
        $jobResult = $script:capturedJobResult
        if ($null -eq $jobResult) {
            Write-RepairLog -Message "Result not captured during monitoring, retrieving from job output" -Category "WARNING" -Operation "JOB"
            $jobResult = Get-JobResult -Job $jobToProcess
        }
        
        try {
            if ($null -ne $jobResult -and $jobResult.ExitCode -eq 0 -and -not $progressBar.IsDisposed -and -not $form.IsDisposed) { 
                $progressBar.Value = 100 
                $progressBar.Refresh()
            }
        }
        catch [System.ObjectDisposedException] {
        }
        catch {
        }
        
        Complete-RepairJob -Job $jobToProcess -JobResult $jobResult
        try {
            if ($jobToProcess.State -eq 'Running') {
                $jobToProcess | Stop-Job -ErrorAction SilentlyContinue
            }
            Remove-Job $jobToProcess -ErrorAction SilentlyContinue
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
        }
    }
}
function Receive-JobOutput {
    $jobOutput = @()
    
    try {
        if ($script:currentRepairJob.HasMoreData) {
            $jobOutput = @(Receive-Job -Job $script:currentRepairJob -ErrorAction Stop)
            
            if ($jobOutput.Count -gt 0) {
                Write-RepairLog -Message "Timer received $($jobOutput.Count) job output items" -Category "JOB"
            }
        }
    }
    catch {
        Write-RepairLog -Message "Error receiving job output in timer: $($_.Exception.Message)" -Category "ERROR"
        return $false
    }
    
    if ($jobOutput.Count -eq 0) {
        return $false
    }
    
    Write-RepairLog -Message "Processing $($jobOutput.Count) job items" -Category "JOB"
    # Simplified logging - no longer log every individual item for cleaner logs
    if ($null -eq $script:capturedJobResult) {
        $resultObject = $jobOutput | Where-Object { 
            $_ -is [PSCustomObject] -and $_.PSObject.Properties['JobType'] 
        } | Select-Object -First 1
        
        if ($null -ne $resultObject) {
            Write-RepairLog -Message "Progress timer captured final job result object" -Category "JOB"
            $script:capturedJobResult = $resultObject
        }
    }
    $progressFound = $false
    foreach ($item in $jobOutput) {
        if ($null -eq $item) {
            Write-RepairLog -Message "Skipping null item" -Category "DEBUG"
            continue
        }
        
        # FIXED: Correct type detection - only skip actual job result objects
        if ($item -is [PSCustomObject] -and $null -ne $item.PSObject.Properties['JobType']) {
            Write-RepairLog -Message "Skipping job result PSCustomObject with JobType: $($item.JobType)" -Category "DEBUG"
            continue
        }
        
        # Process all other items (strings, wrapped strings, etc.)
        Write-RepairLog -Message "Processing item: Type=$($item.GetType().Name), Value='$item'" -Category "DEBUG"
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
    
    try { 
        if ($null -eq $Item) {
            return $false
        }
        
        # Convert to string and clean
        $itemStr = $Item.ToString()
        
        if ([string]::IsNullOrWhiteSpace($itemStr) -or $itemStr.Length -gt 2000) { 
            return $false
        }
        
        # Clean the string
        $itemStr = $itemStr.Trim()
        $itemStr = $itemStr -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+', ''
        
        if ($itemStr.Length -lt 3) { 
            return $false
        }
        
        # Process based on content (simplified logging)
        if ($itemStr.StartsWith("PROGRESS_LINE:", [System.StringComparison]::OrdinalIgnoreCase)) {
            Update-ProgressLine -Line $itemStr
            return $true
        }
        elseif ($itemStr.StartsWith("WINDOWS_OLD_EXISTS:", [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-RepairLog -Message "Windows.old folder detected - showing removal dialog" -Category "USER"
            try {
                Show-WindowsOldPrompt
                Write-RepairLog -Message "Windows.old prompt completed successfully" -Category "USER"
            }
            catch {
                Write-RepairLog -Message "Error showing Windows.old prompt: $($_.Exception.Message)" -Category "ERROR"
            }
            return $false
        }
        elseif ($itemStr.StartsWith("EXPLORER_RESTART_REQUEST:", [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-RepairLog -Message "Explorer restart requested - showing confirmation dialog" -Category "USER"
            try {
                Show-ExplorerRestartPrompt
                Write-RepairLog -Message "Explorer restart prompt completed successfully" -Category "USER"
            }
            catch {
                Write-RepairLog -Message "Error showing Explorer restart prompt: $($_.Exception.Message)" -Category "ERROR"
            }
            return $false
        }
        
        return $false
    } 
    catch {
        Write-RepairLog -Message "Failed to process job output item: $($_.Exception.Message)" -Category "ERROR"
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
    
    $script:lastProgressUpdate = Get-Date
    
    Update-ProgressBar -Line $progressLine
    
    try {
        if (-not $form.IsDisposed -and -not $statusLabel.IsDisposed -and $null -ne $script:currentRepairJob) {
            $jobDisplayName = Get-JobDisplayName -JobName $script:currentRepairJob.Name
            $newStatusText = "$jobDisplayName in progress... $($progressBar.Value)%"
            
            if ($statusLabel.Text -ne $newStatusText) {
                $statusLabel.Text = $newStatusText
                $statusLabel.Refresh()
            }
        }
    }
    catch {
        Write-RepairLog -Message "Error in immediate status update: $($_.Exception.Message)" -Category "WARNING"
    }
    
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
    
    $shouldLog = $false
    
    # Always log first message
    if ($null -eq $script:lastProgressLogTime) { 
        $shouldLog = $true 
    }
    # Log major milestones
    elseif ($currentPercent -in @(0, 25, 50, 75, 100) -and $currentPercent -ne $script:lastLoggedPercent) { 
        $shouldLog = $true 
    }
    # Log significant progress changes (but less frequently)
    elseif ($currentPercent -ge 0) {
        $operation = Get-JobOperation
        $threshold = switch ($operation) {
            "DISM" { 20 }      # Less frequent for DISM
            "SFC" { 25 }       # Less frequent for SFC  
            "CLEANUP" { 10 }   # Moderate for cleanup
            default { 20 }
        }
        if (($currentPercent - $script:lastLoggedPercent) -ge $threshold) {
            $shouldLog = $true
        }
    }
    # Log important events (but not debug info)
    elseif (($Line -replace '\d+%', 'X%') -ne ($script:lastLoggedProgress -replace '\d+%', 'X%')) {
        if ($Line -match '(Starting|Completed|Successfully|Failed|Error|removed)' -and 
            $Line -notmatch '(RAW JOB OUTPUT|CLEANED|Processing|Timer received)') {
            $shouldLog = $true
        }
    }
    # Reduce timeout logging frequency
    elseif ($null -ne $script:lastProgressLogTime -and ($currentTime - $script:lastProgressLogTime).TotalSeconds -ge 300) { 
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
function Update-ProgressBar {
    [CmdletBinding()]
    param([string]$Line)
    
    try {
        if ($progressBar.IsDisposed) {
            return
        }
        
        $percentMatch = $null
        
        if ($Line -match '(\d{1,3})%\s*-') {
            $percentMatch = $matches[1]
        }
        elseif ($Line -match '(?:Progress[:\s]*)?(\d{1,3})%') {
            $percentMatch = $matches[1]
        }
        elseif ($Line -match '^(\d{1,3})%') {
            $percentMatch = $matches[1]
        }
        
        if ($null -ne $percentMatch) {
            $currentPercent = [int]$percentMatch
            
            if ($currentPercent -ge 0 -and $currentPercent -le 100) {
                $progressBar.Value = $currentPercent
                
                try {
                    $progressBar.Refresh()
                }
                catch {
                }
            }
        }
    }
    catch {
        Write-RepairLog -Message "Error updating progress bar: $($_.Exception.Message)" -Category "WARNING"
    }
}
function Show-WindowsOldPrompt {
    try {
        Write-RepairLog -Message "=== WINDOWS.OLD PROMPT STARTING ===" -Category "USER"
        
        if ($null -eq $form -or $form.IsDisposed) {
            Write-RepairLog -Message "ERROR: Form is null or disposed - cannot show dialog" -Category "ERROR"
            return
        }
        
        try {
            $form.TopMost = $true
            $form.BringToFront()
            $form.Activate()
            $form.Focus()
            [System.Windows.Forms.Application]::DoEvents()
        }
        catch {
            Write-RepairLog -Message "Warning: Could not set form focus: $($_.Exception.Message)" -Category "WARNING"
        }
        
        $timerWasRunning = $false
        if ($null -ne $script:progressUpdateTimer) {
            try {
                $timerWasRunning = $script:progressUpdateTimer.Enabled
                $script:progressUpdateTimer.Stop()
                Write-RepairLog -Message "Progress timer stopped for modal dialog (was running: $timerWasRunning)" -Category "USER"
            }
            catch {
                Write-RepairLog -Message "Error stopping timer: $($_.Exception.Message)" -Category "WARNING"
            }
        }
        
        $sizeInfo = ""
        try {
            $windowsOldPath = "C:\Windows.old"
            if (Test-Path $windowsOldPath) {
                $sizeCheckStart = Get-Date
                $size = (Get-ChildItem $windowsOldPath -Recurse -ErrorAction SilentlyContinue | 
                    Select-Object -First 20 | 
                    Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                    
                $sizeCheckDuration = ((Get-Date) - $sizeCheckStart).TotalSeconds
                if ($size -gt 0 -and $sizeCheckDuration -lt 3) {
                    $sizeGB = [Math]::Round($size / 1GB, 2)
                    $sizeInfo = "`n`nApproximate size: $sizeGB GB (quick scan)"
                }
                Write-RepairLog -Message "Size calculation took $sizeCheckDuration seconds" -Category "USER"
            }
        }
        catch {
            Write-RepairLog -Message "Size calculation failed: $($_.Exception.Message)" -Category "WARNING"
        }
        
        $message = "The Windows.old folder contains your previous Windows installation.$sizeInfo`n`nRemoving it will free up disk space but will prevent you from rolling back to your previous Windows version if needed.`n`nDo you want to remove the Windows.old folder as part of the cleanup?`n`n⚠️ This action cannot be undone!"
        
        Write-RepairLog -Message "Displaying Windows.old removal dialog to user" -Category "USER"
        
        $dialogResult = $null
        try {
            [System.Windows.Forms.Application]::DoEvents()
            
            # FIXED: Remove DefaultDesktopOnly parameter that conflicts with owner window
            $dialogResult = [System.Windows.Forms.MessageBox]::Show(
                $form,
                $message, 
                "Windows.old Folder Detected - System Repair Toolkit", 
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question,
                [System.Windows.Forms.MessageBoxDefaultButton]::Button2
            )
        }
        catch {
            Write-RepairLog -Message "Error showing message box: $($_.Exception.Message)" -Category "ERROR"
            # FIXED: Fallback without owner window
            $dialogResult = [System.Windows.Forms.MessageBox]::Show(
                $message, 
                "Windows.old Folder Detected", 
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
        }
        
        $decision = if ($dialogResult -eq [System.Windows.Forms.DialogResult]::Yes) { "YES" } else { "NO" }
        
        Write-RepairLog -Message "User selected: $decision for Windows.old removal" -Category "USER"
        
        $communicationSuccess = $false
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                Write-RepairLog -Message "Communication attempt $attempt for Windows.old decision" -Category "USER"
                
                Set-JobCommunication -JobId $script:currentJobId -Key "WINDOWSOLD_DECISION" -Value $decision
                
                $userTempPath = [System.IO.Path]::GetTempPath()
                $expectedFile = [System.IO.Path]::Combine($userTempPath, "$($script:CONSTANTS.COMMUNICATION_PREFIX)_$($script:currentJobId)_WINDOWSOLD_DECISION.tmp")
                
                Start-Sleep -Milliseconds 100
                
                if (Test-Path $expectedFile) {
                    $fileContent = Get-Content $expectedFile -Raw -ErrorAction SilentlyContinue
                    if ($fileContent.Trim() -eq $decision) {
                        $communicationSuccess = $true
                        Write-RepairLog -Message "Communication verified on attempt ${attempt}: $expectedFile contains '$decision'" -Category "USER"
                        break
                    }
                    else {
                        Write-RepairLog -Message "Communication content mismatch on attempt ${attempt}: expected '$decision', got '$fileContent'" -Category "WARNING"
                    }
                }
                else {
                    Write-RepairLog -Message "Communication file not found on attempt ${attempt}: $expectedFile" -Category "WARNING"
                }
            }
            catch {
                Write-RepairLog -Message "Communication attempt $attempt failed: $($_.Exception.Message)" -Category "ERROR"
            }
            
            if ($attempt -lt 3) {
                Start-Sleep -Milliseconds 200
            }
        }
        
        if (-not $communicationSuccess) {
            Write-RepairLog -Message "❌ WARNING: All communication attempts failed - background job may timeout" -Category "ERROR"
            
            # Show user warning about communication failure
            try {
                [System.Windows.Forms.MessageBox]::Show(
                    "Warning: Unable to communicate your choice to the background cleanup process. The operation will continue but may preserve the Windows.old folder regardless of your selection.",
                    "Communication Warning - System Repair Toolkit",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
            }
            catch {
                Write-RepairLog -Message "Could not show communication warning dialog: $($_.Exception.Message)" -Category "WARNING"
            }
        }
        
        Write-RepairLog -Message "=== WINDOWS.OLD PROMPT COMPLETED ===" -Category "USER"
    }
    finally {
        try {
            if ($null -ne $form -and -not $form.IsDisposed) {
                $form.TopMost = $false
            }
        }
        catch {
            Write-RepairLog -Message "Error restoring form state: $($_.Exception.Message)" -Category "WARNING"
        }
        
        if ($timerWasRunning -and $null -ne $script:progressUpdateTimer) {
            try {
                $script:progressUpdateTimer.Start()
                Write-RepairLog -Message "Progress timer resumed after modal dialog" -Category "USER"
            }
            catch {
                Write-RepairLog -Message "Error resuming timer: $($_.Exception.Message)" -Category "WARNING"
            }
        }
    }
}
function Show-ExplorerRestartPrompt {
    try {
        Write-RepairLog -Message "=== EXPLORER RESTART PROMPT STARTING ===" -Category "USER"
        
        if ($null -eq $form -or $form.IsDisposed) {
            Write-RepairLog -Message "ERROR: Form is null or disposed - cannot show Explorer restart dialog" -Category "ERROR"
            return
        }
        
        $timerWasRunning = $false
        if ($null -ne $script:progressUpdateTimer) {
            try {
                $timerWasRunning = $script:progressUpdateTimer.Enabled
                $script:progressUpdateTimer.Stop()
                Write-RepairLog -Message "Progress timer stopped for Explorer restart dialog" -Category "USER"
            }
            catch {
                Write-RepairLog -Message "Error stopping timer for Explorer dialog: $($_.Exception.Message)" -Category "WARNING"
            }
        }
        
        $message = "To complete the icon cache refresh, Windows Explorer needs to be restarted.`n`nThis will temporarily close all File Explorer windows and make the desktop/taskbar disappear for a few seconds.`n`nDo you want to proceed with the Explorer restart?"
        
        Write-RepairLog -Message "Displaying Explorer restart dialog to user" -Category "USER"
        
        $dialogResult = $null
        try {
            # FIXED: Remove DefaultDesktopOnly parameter that conflicts with owner window
            $dialogResult = [System.Windows.Forms.MessageBox]::Show(
                $form,
                $message, 
                "Explorer Restart Required - System Repair Toolkit", 
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question,
                [System.Windows.Forms.MessageBoxDefaultButton]::Button2
            )
        }
        catch {
            Write-RepairLog -Message "Error showing Explorer restart dialog: $($_.Exception.Message)" -Category "ERROR"
            # FIXED: Fallback without owner window
            $dialogResult = [System.Windows.Forms.MessageBox]::Show(
                $message, 
                "Explorer Restart Required", 
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
        }
        
        $decision = if ($dialogResult -eq [System.Windows.Forms.DialogResult]::Yes) { "YES" } else { "NO" }
        
        Write-RepairLog -Message "User selected: $decision for Explorer restart" -Category "USER"
        
        $communicationSuccess = $false
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                Set-JobCommunication -JobId $script:currentJobId -Key "EXPLORER_RESTART" -Value $decision
                
                $userTempPath = [System.IO.Path]::GetTempPath()
                $expectedFile = [System.IO.Path]::Combine($userTempPath, "$($script:CONSTANTS.COMMUNICATION_PREFIX)_$($script:currentJobId)_EXPLORER_RESTART.tmp")
                
                Start-Sleep -Milliseconds 100
                
                if (Test-Path $expectedFile) {
                    $fileContent = Get-Content $expectedFile -Raw -ErrorAction SilentlyContinue
                    if ($fileContent.Trim() -eq $decision) {
                        $communicationSuccess = $true
                        Write-RepairLog -Message "Explorer restart communication verified: $expectedFile" -Category "USER"
                        break
                    }
                }
            }
            catch {
                Write-RepairLog -Message "Explorer restart communication attempt $attempt failed: $($_.Exception.Message)" -Category "ERROR"
            }
        }
        
        if (-not $communicationSuccess) {
            Write-RepairLog -Message "❌ WARNING: Explorer restart communication failed" -Category "ERROR"
            
            # Show user warning about communication failure
            try {
                [System.Windows.Forms.MessageBox]::Show(
                    "Warning: Unable to communicate your Explorer restart choice to the background process. The visual optimization step may be skipped.",
                    "Communication Warning - System Repair Toolkit",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
            }
            catch {
                Write-RepairLog -Message "Could not show Explorer communication warning: $($_.Exception.Message)" -Category "WARNING"
            }
        }
        
        Write-RepairLog -Message "=== EXPLORER RESTART PROMPT COMPLETED ===" -Category "USER"
    }
    finally {
        if ($timerWasRunning -and $null -ne $script:progressUpdateTimer) {
            try {
                $script:progressUpdateTimer.Start()
                Write-RepairLog -Message "Progress timer resumed after Explorer restart dialog" -Category "USER"
            }
            catch {
                Write-RepairLog -Message "Error resuming timer after Explorer dialog: $($_.Exception.Message)" -Category "WARNING"
            }
        }
    }
}
function Update-SfcProgress {
    if ($script:currentRepairJob.Name -like "*SFCRepairJob*" -and $null -ne $script:operationStartTime) {
        if ($progressBar.Value -eq 0 -and -not $script:fallbackProgressEnabled) {
            $progressBar.Value = 5
        }
    }
}
function Get-JobDisplayName {
    [CmdletBinding()]
    param([string]$JobName)
    
    if ([string]::IsNullOrWhiteSpace($JobName)) {
        return "Operation"
    }
    
    $lowerJobName = $JobName.ToLower()
    
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
        if ($lowerJobName -match "(disk|clean|optimize|maintenance)") {
            return "System Optimization"
        }
        return "Operation"
    }
}
function Update-StatusDisplay {
    try {
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
            
            if ($statusLabel.Text -ne $newStatusText -and -not $statusLabel.IsDisposed) {
                $statusLabel.Text = $newStatusText
                $statusLabel.Refresh()
            }
            
            $script:lastUiUpdate = $currentTime
        }
    }
    catch [System.ObjectDisposedException] {
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
    $script:fallbackProgressEnabled = $false
    $script:progressCommunicationFailures = 0
    $script:lastProgressUpdate = $null
    $script:lastFallbackLogTime = $null
}
#endregion

#region Enhanced Job Result Processing
function Get-JobResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Job]$Job
    )
    
    try {
        Write-RepairLog -Message "Retrieving results for job: $($Job.Name) (State: $($Job.State))" -Category "JOB"
        
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
        
        $finalResult = Get-ResultBetweenMarkers -Output $allOutput -StartMarker "FINAL_RESULT_START" -EndMarker "FINAL_RESULT_END"
        if ($null -ne $finalResult) {
            Write-RepairLog -Message "Found cleanup job result with exit code: $($finalResult.ExitCode)" -Category "JOB"
            return $finalResult
        }
        
        $commandResult = Get-ResultBetweenMarkers -Output $allOutput -StartMarker "COMMAND_RESULT_START" -EndMarker "COMMAND_RESULT_END"
        if ($null -ne $commandResult) {
            Write-RepairLog -Message "Found command job result with exit code: $($commandResult.ExitCode)" -Category "JOB"
            return $commandResult
        }
        
        $anyResult = $allOutput | Where-Object { 
            $_ -is [PSCustomObject] -and 
            $null -ne $_.PSObject.Properties['ExitCode'] 
        } | Select-Object -First 1
        
        if ($null -ne $anyResult) {
            Write-RepairLog -Message "Found generic result object with exit code: $($anyResult.ExitCode)" -Category "JOB"
            return $anyResult
        }
        
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
        
        $additionalInfo = @()
        if ($JobResult.WindowsOldExists) { 
            if ($JobResult.WindowsOldRemoved) {
                if ($JobResult.WindowsOldActuallyRemoved) {
                    $additionalInfo += "Windows.old folder was successfully removed to free disk space."
                }
                else {
                    $additionalInfo += "Windows.old folder removal was approved but folder may have been already removed."
                }
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
            
            if ($JobResult.WindowsOldActuallyRemoved) {
                $message += "`n• Windows.old folder removal (significant disk space freed)"
            }
            
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
        $displayName = Get-JobDisplayName -JobName $Job.Name
        Write-RepairLog -Message "Processing completion for $displayName (job: $($Job.Name))" -Category "JOB"
        
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
$form = New-Object System.Windows.Forms.Form
$form.Text = "System Repair Toolkit"
$form.Size = New-Object System.Drawing.Size(480, 400)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false
$form.MinimizeBox = $true
$form.BackColor = $script:CONSTANTS.UI.BACKGROUND_COLOR
$secondaryFont = $null
$titleFont = $null
try {
    $titleFont = New-Object System.Drawing.Font("Segoe UI Variable Display", 16, [System.Drawing.FontStyle]::Bold)
    $secondaryFont = New-Object System.Drawing.Font("Segoe UI Variable", 10)
}
catch {
    try {
        $titleFont = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
        $secondaryFont = New-Object System.Drawing.Font("Segoe UI", 10)
    }
    catch {
        $titleFont = New-Object System.Drawing.Font("Microsoft Sans Serif", 16, [System.Drawing.FontStyle]::Bold)
        $secondaryFont = New-Object System.Drawing.Font("Microsoft Sans Serif", 10)
    }
}
$buttonLeftMargin = ($form.ClientSize.Width - $script:CONSTANTS.UI.MAIN_BUTTON_WIDTH) / 2
$currentY = $script:CONSTANTS.UI.TOP_MARGIN
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
$toolTip.InitialDelay = 500
$toolTip.ReshowDelay = 100
$toolTip.AutoPopDelay = 10000
$titleLabel.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
$titleLabel.Size = New-Object System.Drawing.Size($script:CONSTANTS.UI.MAIN_BUTTON_WIDTH, 32)
$titleLabel.Text = "System Repair Toolkit"
$titleLabel.Font = $titleFont
$titleLabel.ForeColor = $script:CONSTANTS.UI.TEXT_PRIMARY
$titleLabel.TextAlign = "MiddleCenter"
$currentY += $titleLabel.Height + 4
$instructionLabel.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
$instructionLabel.Size = New-Object System.Drawing.Size($script:CONSTANTS.UI.MAIN_BUTTON_WIDTH, 18)
$instructionLabel.Text = "Recommended sequence: DISM → SFC → Optimize"
$instructionLabel.Font = New-Object System.Drawing.Font($secondaryFont.FontFamily, 9)
$instructionLabel.ForeColor = $script:CONSTANTS.UI.TEXT_SECONDARY
$instructionLabel.TextAlign = "MiddleCenter"
$currentY += $instructionLabel.Height + 20
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
    
    $Button.Tag = if ($IsPrimary) { "Primary" } else { "Secondary" }
    
    if ($IsPrimary) {
        $Button.BackColor = $script:CONSTANTS.UI.PRIMARY_COLOR
        $Button.ForeColor = [System.Drawing.Color]::White
        $Button.FlatAppearance.BorderSize = 0
        
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
    
    $Button.Add_EnabledChanged({
            try {
                if (-not $this.Enabled) {
                    $this.ForeColor = [System.Drawing.Color]::FromArgb(160, 160, 160)
                    $this.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
                }
                else {
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
                    $this.Refresh()
                    $this.Invalidate()
                    $this.Update()
                }
            }
            catch {
            }
        })
}
$dismButton.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
Set-Windows11ButtonStyle -Button $dismButton -Text "STEP 1: Repair System Image (DISM)" -IsPrimary $true
$dismButton.Add_Click({ Start-DISMRepair })
$toolTip.SetToolTip($dismButton, "Repairs Windows component store and system image")
$currentY += $dismButton.Height + $script:CONSTANTS.UI.CONTROL_SPACING
$sfcButton.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
Set-Windows11ButtonStyle -Button $sfcButton -Text "STEP 2: Scan & Fix System Files (SFC)"
$sfcButton.Add_Click({ Start-SFCRepair })
$toolTip.SetToolTip($sfcButton, "Scans and repairs corrupted system files")
$currentY += $sfcButton.Height + $script:CONSTANTS.UI.CONTROL_SPACING
$cleanupButton.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
Set-Windows11ButtonStyle -Button $cleanupButton -Text "STEP 3: Disk Cleanup && Performance"
$cleanupButton.Add_Click({ Start-DiskCleanup })
$toolTip.SetToolTip($cleanupButton, "Cleans temporary files and optimizes performance")
$currentY += $cleanupButton.Height + 8
$progressBar.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
$progressBar.Size = New-Object System.Drawing.Size($script:CONSTANTS.UI.MAIN_BUTTON_WIDTH, 6)
$progressBar.Style = 'Continuous'
$progressBar.ForeColor = $script:CONSTANTS.UI.PRIMARY_COLOR
$progressBar.BackColor = [System.Drawing.Color]::FromArgb(235, 235, 235)
$progressBar.Visible = $false
$currentY += $progressBar.Height + 6
$statusLabel.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
$statusLabel.Size = New-Object System.Drawing.Size($script:CONSTANTS.UI.MAIN_BUTTON_WIDTH, 28)
$statusLabel.Font = New-Object System.Drawing.Font($secondaryFont.FontFamily, 9.5)
$statusLabel.TextAlign = "MiddleCenter"
$statusLabel.ForeColor = $script:CONSTANTS.UI.TEXT_SECONDARY
$currentY += $statusLabel.Height + 8
$formWidth = [int]$form.ClientSize.Width
$panelWidth = [int]$formWidth
$buttonGroupWidth = 3 * $script:CONSTANTS.UI.SMALL_BUTTON_WIDTH + 2 * 8
$leftPadding = [int](($formWidth - $buttonGroupWidth) / 2)
$bottomPanel.Location = New-Object System.Drawing.Point(0, $currentY)
$bottomPanel.Size = New-Object System.Drawing.Size($panelWidth, 36)
$bottomPanel.FlowDirection = 'LeftToRight'
$bottomPanel.Anchor = 'None'
$bottomPanel.WrapContents = $false
$bottomPanel.AutoSize = $false
$bottomPanel.Padding = New-Object System.Windows.Forms.Padding($leftPadding, 3, 0, 0)
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
Set-UtilityButtonStyle -Button $helpButton -Text "Help"
$helpButton.Add_Click({
        $helpMsg = "System Repair Toolkit`n" +
        "Windows 11 Compatible • PowerShell 5.0+`n`n" +
        "FIXES IN v3.0:`n" +
        "• CRITICAL FIX: Added comprehensive cleanup categories (20+ types including Windows Defender, Delivery Optimization, DirectX caches)`n" +
        "• CRITICAL FIX: Enhanced manual cleanup for Windows Defender scan history, update downloads, and thumbnail caches`n" +
        "• IMPROVED: Much cleaner, user-friendly logging with reduced technical clutter`n" +
        "• IMPROVED: Removed verbose debug messages for better log readability`n" +
        "• IMPROVED: Smarter file filtering (only removes files older than 7 days for safety)`n" +
        "• VERIFIED: Now cleans all the file types shown in Windows Disk Cleanup dialog`n`n" +
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
$bottomPanel.Controls.AddRange(@($helpButton, $viewLogButton, $closeButton))
$form.Controls.AddRange(@(
        $titleLabel, $instructionLabel, $dismButton, $sfcButton, $cleanupButton,
        $progressBar, $statusLabel, $bottomPanel
    ))
$dismButton.TabIndex = 0
$sfcButton.TabIndex = 1
$cleanupButton.TabIndex = 2
$helpButton.TabIndex = 3
$viewLogButton.TabIndex = 4
$closeButton.TabIndex = 5
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
function Update-UiForJobStart {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StatusMessage
    )
    
    try {
        $statusLabel.Text = $StatusMessage
        $statusLabel.ForeColor = $script:CONSTANTS.UI.TEXT_PRIMARY
        
        $dismButton.Enabled = $false
        $sfcButton.Enabled = $false  
        $cleanupButton.Enabled = $false
        
        $progressBar.Value = 0
        $progressBar.Visible = $true
        $progressBar.Refresh()
        
        $form.Text = "System Repair Toolkit - Operation in Progress"
        
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
        if ($form.IsDisposed -or $form.Disposing) {
            return
        }
        if (-not $progressBar.IsDisposed) {
            $progressBar.Visible = $false
        }
        
        if (-not $statusLabel.IsDisposed) {
            $statusLabel.Text = $StatusMessage
            if ($IsSuccess) {
                $statusLabel.ForeColor = $script:CONSTANTS.UI.SUCCESS_COLOR
            }
            else {
                $statusLabel.ForeColor = $script:CONSTANTS.UI.ERROR_COLOR
            }
        }
        
        if (-not $dismButton.IsDisposed) { $dismButton.Enabled = $true }
        if (-not $sfcButton.IsDisposed) { $sfcButton.Enabled = $true }
        if (-not $cleanupButton.IsDisposed) { $cleanupButton.Enabled = $true }
        
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
        }
        catch {
        }
        
        if (-not $form.IsDisposed) {
            $form.Text = "System Repair Toolkit"
        }
        
        if (-not $statusLabel.IsDisposed) { $statusLabel.Refresh() }
        if (-not $form.IsDisposed) { $form.Refresh() }
        
        Write-RepairLog -Message "UI updated for job end: $StatusMessage (Success: $IsSuccess)" -Category "SYSTEM"
    }
    catch [System.ObjectDisposedException] {
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
$form.Add_FormClosing({
        param($formSender, $closeEventArgs)
    
        try {
            Write-RepairLog -Message "Application shutdown initiated by user" -Category "SYSTEM"
        
            Stop-ProgressTimer
        
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
                            Start-ProgressTimer
                            return
                        }
                    }
                
                    Write-RepairLog -Message "Stopping active repair job due to application shutdown" -Category "JOB"
                    try {
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
        
            $script:currentRepairJob = $null
        
            if ($script:currentJobId) {
                try {
                    $userTempPath = [System.IO.Path]::GetTempPath()
                    $tempFiles = Get-ChildItem -Path $userTempPath -Filter "$($script:CONSTANTS.COMMUNICATION_PREFIX)_$script:currentJobId*" -ErrorAction SilentlyContinue
                    foreach ($file in $tempFiles) {
                        Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue
                    }
                }
                catch {
                }
            }
        
            try {
                if ($null -ne $toolTip -and -not $toolTip.IsDisposed) { $toolTip.Dispose() }
                if ($null -ne $titleFont) { $titleFont.Dispose() }
                if ($null -ne $secondaryFont) { $secondaryFont.Dispose() }
            }
            catch {
            }
        
            Close-RepairLog
        
            Write-RepairLog -Message "Application shutdown completed successfully" -Category "SYSTEM"
        }
        catch {
            Write-Warning "Error during application shutdown: $($_.Exception.Message)"
        }
    })
$form.Add_Load({
        try {
            Write-RepairLog -Message "Main application window loaded successfully" -Category "SYSTEM"
        
            $isAdmin = Test-IsAdministrator
            Set-ReadyStatus -IsAdministrator $isAdmin
        
            $osInfo = [System.Environment]::OSVersion
            $psVersion = if ($PSVersionTable.PSVersion) { $PSVersionTable.PSVersion.ToString() } else { "Unknown" }
        
            Write-RepairLog -Message "System Information - OS: $($osInfo.VersionString), PowerShell: $psVersion" -Category "SYSTEM"
            Write-RepairLog -Message "UI Language: $([System.Globalization.CultureInfo]::CurrentUICulture.Name)" -Category "SYSTEM"
        
            $dismButton.Focus()
        
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
$form.Add_Shown({
        try {
            Write-RepairLog -Message "Application interface displayed to user" -Category "SYSTEM"
        
            if (Test-IsAdministrator) {
                Write-RepairLog -Message "Toolkit started with full Administrator privileges - all functions available" -Category "SYSTEM"
            }
            else {
                Write-RepairLog -Message "Toolkit started in standard user mode - functionality limited to information and logging" -Category "WARNING"
            }
        
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
try {
    [System.AppDomain]::CurrentDomain.add_UnhandledException({
            param($exceptionSender, $exceptionEventArgs)
            try {
                $exception = $exceptionEventArgs.ExceptionObject
                Write-RepairLog -Message "Unhandled exception occurred: $($exception.ToString())" -Category "ERROR"
            
                [System.Windows.Forms.MessageBox]::Show(
                    "An unexpected error occurred. The application will attempt to close safely.`n`nError: $($exception.Message)",
                    "System Repair Toolkit - Unexpected Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
            }
            catch {
                Write-Error "Critical unhandled exception: $($exceptionEventArgs.ExceptionObject.ToString())"
            }
        })
    if (-not $script:isInitialized) {
        Write-Warning "Logging system failed to initialize. Some functionality may be limited."
        Initialize-RepairLog
    }
    
    Write-RepairLog -Message "=== SYSTEM REPAIR TOOLKIT STARTUP ===" -Category "SYSTEM"
    Write-RepairLog -Message "Application startup initiated with enhanced error handling and fixes applied" -Category "SYSTEM"
    
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -lt 10) {
        Write-RepairLog -Message "Warning: Running on pre-Windows 10 system. Some features may not work optimally." -Category "WARNING"
    }
    
    try {
        $netVersion = [System.Environment]::Version
        Write-RepairLog -Message ".NET Runtime Version: $netVersion" -Category "SYSTEM"
    }
    catch {
        Write-RepairLog -Message "Could not determine .NET version" -Category "WARNING"
    }
    
    Write-RepairLog -Message "Displaying main application window" -Category "SYSTEM"
    
    [void]$form.ShowDialog()
    
    Write-RepairLog -Message "Main application window closed by user" -Category "SYSTEM"
}
catch {
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
    try {
        Write-RepairLog -Message "Application execution completed - starting final cleanup" -Category "SYSTEM"
        
        Stop-ProgressTimer
        
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
        
        try {
            $userTempPath = [System.IO.Path]::GetTempPath()
            $tempFiles = Get-ChildItem -Path $userTempPath -Filter "$($script:CONSTANTS.COMMUNICATION_PREFIX)*" -ErrorAction SilentlyContinue
            foreach ($file in $tempFiles) {
                Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
        }
        
        Write-RepairLog -Message "=== SYSTEM REPAIR TOOLKIT SESSION END ===" -Category "SYSTEM"
        Close-RepairLog
    }
    catch {
        Write-Warning "Error during final cleanup: $($_.Exception.Message)"
    }
}
#endregion
