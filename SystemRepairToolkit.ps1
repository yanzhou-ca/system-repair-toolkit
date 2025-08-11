#requires -Version 5.0
#requires -RunAsAdministrator

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
    Version: 4.0 (Fully Revised - Complete Feature Parity)
    Author: Yan Zhou
    Requirements: PowerShell 5.0+, Windows 10/11, Administrator privileges for full functionality.
    
    ==============================
    SYSTEM REPAIR TOOLKIT v4.0
    ==============================
    Major Changes in v4.0:
    - Fixed all automatic variable usage ($PID, $PSVersionTable, $matches)
    - Removed all unused variables
    - All functions use approved verbs from Get-Verb
    - Maintained ALL original functionality
    - Enhanced error handling and thread safety
    - Optimized performance while keeping all features
#>

#region 1. Script Initialization - Assembly Loading and PowerShell Requirements
# Load required .NET assemblies for Windows Forms GUI
try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    Add-Type -AssemblyName System.Drawing -ErrorAction Stop
} catch {
    Write-Error "Failed to load required assemblies: $($_.Exception.Message)"
    Write-Error "Ensure .NET Framework is properly installed"
    exit 1
}

# Initialize critical state flags early
$script:isInitialized = $false
$script:lastUiUpdate = [DateTime]::MinValue
$script:progressCommunicationFailures = 0
$script:disposedObjects = [System.Collections.Generic.HashSet[object]]::new()
#endregion

#region 2. Global Configuration - Constants and Settings
$script:CONSTANTS = @{
    # Timer and timeout settings
    TIMER_INTERVAL_MS             = 500     # Optimized from 1000ms
    USER_DECISION_TIMEOUT_SECONDS = 90      # Timeout for user prompts
    CLEANMGR_TIMEOUT_MINUTES      = 3       # Disk cleanup timeout
    MAX_ESTIMATED_PROGRESS        = 95      # Maximum estimated progress percentage
    UI_UPDATE_THROTTLE_MS         = 250     # UI update throttling
    PROGRESS_COMM_FAILURE_LIMIT   = 8       # Max communication failures before fallback
    
    # Cleanup configuration
    SAGESET_VALUE                 = 64      # Registry sageset value for cleanup
    LOG_FILENAME                  = "SystemRepairLog.txt"
    LOG_MAX_SIZE_MB               = 10      # Maximum log file size before rotation
    COMMUNICATION_PREFIX          = "RepairToolkit"  # Prefix for IPC files
}

# Windows 11 Fluent Design constants
$script:FLUENT_DESIGN = @{
    # Windows 11 Official Colors
    Colors = @{
        PRIMARY_BLUE        = [System.Drawing.Color]::FromArgb(0, 120, 212)    # #0078D4
        PRIMARY_HOVER       = [System.Drawing.Color]::FromArgb(16, 110, 190)   # #106EBE  
        PRIMARY_PRESSED     = [System.Drawing.Color]::FromArgb(0, 90, 158)     # #005A9E
        SECONDARY_BG        = [System.Drawing.Color]::FromArgb(243, 242, 241)  # #F3F2F1
        SECONDARY_HOVER     = [System.Drawing.Color]::FromArgb(237, 235, 233)  # #EDEBE9
        SECONDARY_PRESSED   = [System.Drawing.Color]::FromArgb(225, 223, 221)  # #E1DFDD
        TEXT_PRIMARY        = [System.Drawing.Color]::FromArgb(50, 49, 48)     # #323130
        TEXT_SECONDARY      = [System.Drawing.Color]::FromArgb(96, 94, 92)     # #605E5C
        TEXT_TERTIARY       = [System.Drawing.Color]::FromArgb(150, 148, 146)  # #969492
        SUCCESS_GREEN       = [System.Drawing.Color]::FromArgb(16, 124, 16)    # #107C10
        WARNING_ORANGE      = [System.Drawing.Color]::FromArgb(255, 140, 0)    # #FF8C00
        ERROR_RED           = [System.Drawing.Color]::FromArgb(209, 52, 56)    # #D13438
        BACKGROUND          = [System.Drawing.Color]::FromArgb(250, 250, 250)  # #FAFAFA
        CARD_BACKGROUND     = [System.Drawing.Color]::FromArgb(255, 255, 255)  # #FFFFFF
        BORDER_LIGHT        = [System.Drawing.Color]::FromArgb(225, 225, 225)  # #E1E1E1
        BORDER_MEDIUM       = [System.Drawing.Color]::FromArgb(200, 198, 196)  # #C8C6C4
    }
    
    # 8px Grid System (Windows 11 standard)
    Spacing = @{
        GRID_UNIT    = 8      # Base unit
        TINY         = 4      # 0.5x
        SMALL        = 8      # 1x  
        MEDIUM       = 16     # 2x
        LARGE        = 24     # 3x
        XLARGE       = 32     # 4x
        XXLARGE      = 48     # 6x
    }
    
    # Typography Scale
    Typography = @{
        TITLE_SIZE       = 20    # Large titles
        SUBTITLE_SIZE    = 16    # Section headers  
        BODY_SIZE        = 14    # Main text
        CAPTION_SIZE     = 12    # Small text
        BUTTON_SIZE      = 14    # Button text
    }
    
    # Button Dimensions
    ButtonDimensions = @{
        MAIN_WIDTH   = 350
        MAIN_HEIGHT  = 44
        UTIL_WIDTH   = 90
        UTIL_HEIGHT  = 28
    }
}
#endregion

#region 3. State Management - Script Variables and Runtime State
# Job management variables
$script:currentRepairJob = $null                    # Current running background job
$script:progressUpdateTimer = $null                 # Timer for progress updates
$script:operationStartTime = [DateTime]::MinValue  # Start time of current operation
$script:timerLock = [System.Threading.Mutex]::new($false, "RepairToolkitTimer")
$script:currentJobId = [String]::Empty              # Unique ID for current job
$script:capturedJobResult = $null                   # Cached job result
$script:jobCollection = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()

# Logging state
$script:logPath = [String]::Empty                   # Full path to log file
$script:lastLoggedProgress = [String]::Empty       # Last logged progress message
$script:lastLoggedPercent = -1                      # Last logged percentage
$script:lastProgressLogTime = [DateTime]::MinValue # Last time progress was logged
$script:progressMessageCount = 0                    # Total progress messages

# Progress tracking
$script:fallbackProgressEnabled = $false            # Whether to use estimated progress
$script:lastProgressUpdate = [DateTime]::MinValue  # Last actual progress update
$script:lastFallbackLogTime = [DateTime]::MinValue # Last fallback progress log

# Output processing state
$script:lastOutputCount = 0                         # Track processed output count for timer
$script:lastProcessedOutputCount = 0                # Track processed output count for receive function

# UI elements (will be initialized in GUI region)
$script:form = $null
$script:titleLabel = $null
$script:instructionLabel = $null
$script:dismButton = $null
$script:sfcButton = $null
$script:cleanupButton = $null
$script:progressBar = $null
$script:statusLabel = $null
$script:bottomPanel = $null
$script:helpButton = $null
$script:viewLogButton = $null
$script:closeButton = $null
$script:toolTip = $null
$script:titleFont = $null
$script:secondaryFont = $null

# Initialize logging early to capture all events
function Initialize-ScriptLogging {
    try {
        $desktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
        if ([string]::IsNullOrEmpty($desktopPath)) {
            $desktopPath = Join-Path $env:USERPROFILE "Desktop"
        }
        
        $script:logPath = [System.IO.Path]::Combine($desktopPath, $script:CONSTANTS.LOG_FILENAME)
        
        # Check if log exists and rotate if needed
        if (Test-Path $script:logPath) {
            try {
                $logFile = Get-Item $script:logPath -ErrorAction Stop
                $logSizeMB = [Math]::Round($logFile.Length / 1MB, 2)
                
                if ($logFile.Length -gt ($script:CONSTANTS.LOG_MAX_SIZE_MB * 1MB)) {
                    $backupPath = [System.IO.Path]::Combine($desktopPath, "SystemRepairLog_backup.txt")
                    
                    if (Test-Path $backupPath) {
                        Remove-Item $backupPath -Force -ErrorAction SilentlyContinue
                    }
                    
                    Move-Item $script:logPath $backupPath -Force -ErrorAction SilentlyContinue
                    Write-Host "Log file rotated (was $logSizeMB MB)" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Warning "Could not check log file size: $($_.Exception.Message)"
            }
        }
        
        # Write session header - FIXED: No automatic variables
        $separator = "=" * 80
        $adminStatus = if (Test-IsAdministrator) { 'Yes' } else { 'No' }
        # FIXED: Replaced $PSVersionTable with $Host.Version
        $psVersion = $Host.Version.ToString()
        # FIXED: Replaced $PID with Process.GetCurrentProcess()
        $processId = [System.Diagnostics.Process]::GetCurrentProcess().Id
        
        $header = @"
$separator
SYSTEM REPAIR TOOLKIT - SESSION LOG
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
PowerShell Version: $psVersion
OS Version: $([System.Environment]::OSVersion.VersionString)
User: $([System.Environment]::UserName)
Computer: $([System.Environment]::MachineName)
Administrator Mode: $adminStatus
Process ID: $processId
Log Path: $script:logPath
$separator
"@
        
        Add-Content -Path $script:logPath -Value $header -Encoding UTF8
        $script:isInitialized = $true
        
        # Log successful initialization
        Write-SimpleLog -Message "System Repair Toolkit session started"
        
    }
    catch {
        Write-Warning "Failed to initialize repair log: $($_.Exception.Message)"
        $script:isInitialized = $false
    }
}

# Simple logging function for early initialization
function Write-SimpleLog {
    param([string]$Message)
    
    if ($script:isInitialized -and -not [string]::IsNullOrEmpty($script:logPath)) {
        try {
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $logEntry = "[$timestamp] [INFO] [System Repair Toolkit] $Message"
            Add-Content -Path $script:logPath -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
        }
        catch {
            # Silently fail if logging doesn't work
        }
    }
}

# Helper function for early initialization
function Test-IsAdministrator {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        if ($null -eq $identity) {
            return $false
        }
        
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

# Initialize logging immediately
Initialize-ScriptLogging
#endregion

#region 4. Logging Infrastructure - Comprehensive Logging System
# Logging configuration with categories and operations
$script:LOG_CONFIG = @{
    Categories = @{
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
    Operations = @{
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
    
    # Early validation
    if (-not $script:isInitialized -or [string]::IsNullOrEmpty($script:logPath)) {
        return
    }
    
    try {
        # Simple message cleaning
        $cleanMessage = if ([string]::IsNullOrWhiteSpace($Message)) { 
            "[Empty message]" 
        } else { 
            $Message.Trim() 
        }
        
        # Truncate very long messages
        if ($cleanMessage.Length -gt 1000) {
            $cleanMessage = $cleanMessage.Substring(0, 997) + "..."
        }
        
        # Get category and operation info
        $categoryInfo = $script:LOG_CONFIG.Categories[$Category]
        $operationName = $script:LOG_CONFIG.Operations[$Operation]
        
        # Simple log entry format
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$($categoryInfo.Display)] [$operationName] $cleanMessage"
        
        # Simplified file writing without complex locking
        try {
            # Use a simple approach with retry
            $attempts = 0
            $maxAttempts = 2
            
            do {
                try {
                    [System.IO.File]::AppendAllText($script:logPath, "$logEntry`r`n", [System.Text.Encoding]::UTF8)
                    break
                }
                catch {
                    $attempts++
                    if ($attempts -lt $maxAttempts) {
                        Start-Sleep -Milliseconds 10
                    }
                }
            } while ($attempts -lt $maxAttempts)
        }
        catch {
            # Final fallback - write to console
            if ($IncludeInConsole) {
                Write-Host $logEntry -ForegroundColor $categoryInfo.Color
            }
        }
        
        # Console output if requested
        if ($IncludeInConsole) {
            try {
                Write-Host $logEntry -ForegroundColor $categoryInfo.Color
            }
            catch {
                Write-Host $logEntry
            }
        }
    }
    catch {
        # Simplified fallback logging
        try {
            $fallbackEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERR!] [TOOLKIT] Logging failed: $($_.Exception.Message)"
            [System.IO.File]::AppendAllText($script:logPath, "$fallbackEntry`r`n", [System.Text.Encoding]::UTF8)
        }
        catch {
            # Final fallback
            if ($IncludeInConsole) {
                Write-Warning "Complete logging failure for message: $Message"
            }
        }
    }
}

function Write-OperationStart {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("DISM", "SFC", "CLEANUP")]
        [string]$OperationType,
        
        [ValidateNotNullOrEmpty()]
        [string]$Description = ""
    )
    
    try {
        if ([string]::IsNullOrEmpty($Description)) {
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
        
        [Parameter()]
        [TimeSpan]$Duration = [TimeSpan]::Zero,
        
        [Parameter()]
        [bool]$Success = $true,
        
        [Parameter()]
        [int]$ExitCode = 0,
        
        [Parameter()]
        [string]$AdditionalInfo = ""
    )
    
    try {
        $durationText = if ($Duration -ne [TimeSpan]::Zero) { 
            "in {0:mm\:ss} (mm:ss)" -f $Duration 
        }
        else { 
            "duration unknown" 
        }
        
        $resultText = if ($Success) { "COMPLETED SUCCESSFULLY" } else { "COMPLETED WITH ISSUES" }
        $category = if ($Success) { "SUCCESS" } else { "WARNING" }
        
        Write-RepairLog -Message "=== $resultText $($script:LOG_CONFIG.OperationDescriptions[$OperationType]) $durationText ===" -Category $category -Operation $OperationType
        
        if ($ExitCode -ne 0) {
            Write-RepairLog -Message "Exit code: $ExitCode" -Category "INFO" -Operation $OperationType
        }
        
        if (-not [string]::IsNullOrEmpty($AdditionalInfo)) {
            Write-RepairLog -Message "Additional info: $AdditionalInfo" -Category "INFO" -Operation $OperationType
        }
    }
    catch {
        Write-RepairLog -Message "Error logging operation end: $($_.Exception.Message)" -Category "ERROR"
    }
}

function Initialize-RepairLog {
    # This is now called from Initialize-ScriptLogging
    # Kept for compatibility but now just writes a log entry
    if ($script:isInitialized) {
        Write-RepairLog -Message "Logging system already initialized" -Category "SYSTEM"
    }
    else {
        Initialize-ScriptLogging
    }
}

function Close-RepairLog {
    [CmdletBinding()]
    param()
    
    try {
        if ($script:isInitialized -and -not [string]::IsNullOrEmpty($script:logPath)) {
            $separator = "=" * 80
            $footer = @"
$separator
SESSION COMPLETED: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Total Progress Messages: $script:progressMessageCount
Communication Failures: $script:progressCommunicationFailures
$separator
"@
            Write-RepairLog -Message "System Repair Toolkit session ending" -Category "SYSTEM"
            
            # Direct write for footer to avoid recursion
            $logLock = [System.Threading.Mutex]::new($false, "RepairToolkitLog")
            try {
                $acquired = $logLock.WaitOne(1000)
                if ($acquired) {
                    Add-Content -Path $script:logPath -Value $footer -Encoding UTF8
                }
            }
            finally {
                if ($acquired) {
                    $logLock.ReleaseMutex()
                }
                $logLock.Dispose()
            }
        }
    }
    catch {
        Write-Warning "Failed to close repair log properly: $($_.Exception.Message)"
    }
}
#endregion

#region 5. Core Utility Functions - Common Helper Functions
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

function Invoke-WithErrorHandling {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OperationName,
        
        [Parameter()]
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

function Show-InfoMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        
        [Parameter()]
        [string]$Title = "System Repair Toolkit",
        
        [Parameter()]
        [System.Windows.Forms.MessageBoxButtons]$Buttons = 'OK',
        
        [Parameter()]
        [System.Windows.Forms.MessageBoxIcon]$Icon = 'Information'
    )
    
    try {
        # Check if form exists and is not disposed
        if ($null -ne $script:form -and -not $script:form.IsDisposed) {
            return [System.Windows.Forms.MessageBox]::Show($script:form, $Message, $Title, $Buttons, $Icon)
        }
        else {
            return [System.Windows.Forms.MessageBox]::Show($Message, $Title, $Buttons, $Icon)
        }
    }
    catch {
        Write-RepairLog -Message "Error showing message box: $($_.Exception.Message)" -Category "ERROR"
        # Fallback to simple message box
        try {
            return [System.Windows.Forms.MessageBox]::Show($Message, $Title, $Buttons, $Icon)
        }
        catch {
            Write-Warning "Could not show message: $Message"
            return [System.Windows.Forms.DialogResult]::None
        }
    }
}

function Show-ErrorMessage { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message, 
        
        [Parameter()]
        [string]$Title = "System Repair Toolkit - Error"
    )
    
    Show-InfoMessage -Message $Message -Title $Title -Icon 'Error'
}

function Show-WarningMessage { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message, 
        
        [Parameter()]
        [string]$Title = "System Repair Toolkit - Warning"
    )
    
    Show-InfoMessage -Message $Message -Title $Title -Icon 'Warning'
}

function Show-QuestionMessage { 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message, 
        
        [Parameter()]
        [string]$Title = "System Repair Toolkit - Confirmation"
    )
    
    Show-InfoMessage -Message $Message -Title $Title -Buttons 'YesNo' -Icon 'Question'
}
#endregion

#region 6. Job Communication Functions - Inter-Process Communication
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
        [ValidateNotNull()]
        [string]$Value
    )
    
    try {
        # Get safe temp path
        $userTempPath = [System.IO.Path]::GetTempPath()
        
        # Sanitize inputs to prevent path injection
        $safeJobId = $JobId -replace '[^\w\-]', ''
        $safeKey = $Key -replace '[^\w\-]', ''
        
        # Build communication file path
        $communicationPath = [System.IO.Path]::Combine($userTempPath, "$($script:CONSTANTS.COMMUNICATION_PREFIX)_${safeJobId}_${safeKey}.tmp")
        
        Write-RepairLog -Message "Creating communication file: $communicationPath" -Category "JOB"
        
        # Thread-safe file writing
        $fileLock = [System.Threading.Mutex]::new($false, "RepairToolkit_${safeJobId}_${safeKey}")
        try {
            $acquired = $fileLock.WaitOne(1000)
            if ($acquired) {
                # Write value to file
                Set-Content -Path $communicationPath -Value $Value -Encoding UTF8 -Force
                
                # Verify file was created
                if (Test-Path $communicationPath) {
                    $fileSize = (Get-Item $communicationPath).Length
                    Write-RepairLog -Message "Communication file created successfully: $Key = $Value (Size: $fileSize bytes)" -Category "JOB"
                }
                else {
                    Write-RepairLog -Message "ERROR: Communication file was not created: $communicationPath" -Category "ERROR"
                }
            }
            else {
                Write-RepairLog -Message "Could not acquire lock for communication file" -Category "WARNING"
            }
        }
        finally {
            if ($acquired) {
                $fileLock.ReleaseMutex()
            }
            $fileLock.Dispose()
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
        
        [Parameter()]
        [ValidateRange(1, 3600)]
        [int]$TimeoutSeconds = 90
    )
    
    try {
        # Get safe temp path
        $userTempPath = [System.IO.Path]::GetTempPath()
        
        # Sanitize inputs
        $safeJobId = $JobId -replace '[^\w\-]', ''
        $safeKey = $Key -replace '[^\w\-]', ''
        
        # Build communication file path
        $communicationPath = [System.IO.Path]::Combine($userTempPath, "$($script:CONSTANTS.COMMUNICATION_PREFIX)_${safeJobId}_${safeKey}.tmp")
        
        # Set timeout
        $timeout = (Get-Date).AddSeconds($TimeoutSeconds)
        $checkCount = 0
        
        Write-RepairLog -Message "Waiting for communication file: $communicationPath (timeout: $TimeoutSeconds seconds)" -Category "JOB"
        
        # Poll for file
        while ((Get-Date) -lt $timeout) {
            if (Test-Path $communicationPath) {
                $fileLock = [System.Threading.Mutex]::new($false, "RepairToolkit_${safeJobId}_${safeKey}")
                try {
                    $acquired = $fileLock.WaitOne(100)
                    if ($acquired) {
                        # Read and delete file
                        $value = Get-Content $communicationPath -Raw -ErrorAction SilentlyContinue
                        Remove-Item $communicationPath -Force -ErrorAction SilentlyContinue
                        
                        if ($null -ne $value) { 
                            Write-RepairLog -Message "Communication received: $Key = $($value.Trim())" -Category "JOB"
                            return $value.Trim() 
                        }
                    }
                }
                finally {
                    if ($acquired) {
                        $fileLock.ReleaseMutex()
                    }
                    $fileLock.Dispose()
                }
            }
            
            # Log periodic status
            $checkCount++
            if ($checkCount % 20 -eq 0) {
                Write-RepairLog -Message "Still waiting for communication: $Key (check $checkCount)" -Category "JOB"
            }
            
            Start-Sleep -Milliseconds 500
        }
        
        Write-RepairLog -Message "Job communication timeout for key: $Key after $TimeoutSeconds seconds" -Category "WARNING"
        return $null
    }
    catch {
        Write-RepairLog -Message "Error retrieving job communication: $($_.Exception.Message)" -Category "ERROR"
        return $null
    }
}

function Clear-JobCommunicationFiles {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$JobId = ""
    )
    
    try {
        $userTempPath = [System.IO.Path]::GetTempPath()
        
        if ([string]::IsNullOrEmpty($JobId)) {
            # Clear all communication files
            $pattern = "$($script:CONSTANTS.COMMUNICATION_PREFIX)_*.tmp"
        }
        else {
            # Clear specific job files
            $safeJobId = $JobId -replace '[^\w\-]', ''
            $pattern = "$($script:CONSTANTS.COMMUNICATION_PREFIX)_${safeJobId}_*.tmp"
        }
        
        $files = Get-ChildItem -Path $userTempPath -Filter $pattern -ErrorAction SilentlyContinue
        $fileCount = 0
        
        foreach ($file in $files) {
            try {
                Remove-Item $file.FullName -Force -ErrorAction Stop
                $fileCount++
            }
            catch {
                Write-RepairLog -Message "Could not remove communication file: $($file.Name)" -Category "WARNING"
            }
        }
        
        if ($fileCount -gt 0) {
            Write-RepairLog -Message "Cleared $fileCount communication files" -Category "JOB"
        }
    }
    catch {
        Write-RepairLog -Message "Error clearing communication files: $($_.Exception.Message)" -Category "WARNING"
    }
}
#endregion

#region 7. Command Runner ScriptBlock - DISM and SFC Execution
$script:commandRunnerScriptBlock = {
    param(
        [string]$ExecutablePath, 
        [string]$Arguments
    )
    
    $jobStartTime = Get-Date
    $lastProgressPercent = 0
    $outputBuffer = [System.Collections.Generic.List[string]]::new()
    $lastRealProgress = Get-Date  # Track when we last got real progress
    
    # Configure timeouts based on executable type
    $progressTimeoutSeconds = 600   # Default 10 minutes
    $estimateProgressAfter = 120    # Default 2 minutes
    
    if ($ExecutablePath -like "*DISM.exe*") {
        # DISM can go silent for long periods during component store operations
        $progressTimeoutSeconds = 1800  # 30 minutes
        $estimateProgressAfter = 300    # 5 minutes before starting estimates
    }
    elseif ($ExecutablePath -like "*sfc.exe*") {
        # SFC also can have long silent periods
        $progressTimeoutSeconds = 1200  # 20 minutes
        $estimateProgressAfter = 180    # 3 minutes
    }
    
    function Get-CleanOutputLine {
        param([string]$RawLine)
        
        if ([string]::IsNullOrWhiteSpace($RawLine)) { 
            return $null 
        }
        
        $cleanLine = $RawLine -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+', '' -replace '\s+', ' '
        $cleanLine = $cleanLine.Trim()
        
        if ($cleanLine.Length -lt 2 -or $cleanLine.Length -gt 500) {
            return $null
        }
        
        return $cleanLine
    }
    
    function Get-ProgressPercent {
        param([string]$Line)
        
        # Enhanced pattern for DISM's unique format [===== 62.3% =====]
        # Try multiple patterns in order of specificity
        
        # Pattern 1: DISM bracket format with equals signs
        $dismPattern = '\[=*\s*(\d{1,3})(?:\.\d+)?%\s*=*\]'
        $regexResult = [regex]::Match($Line, $dismPattern)
        if ($regexResult.Success) {
            return [int]$regexResult.Groups[1].Value
        }
        
        # Pattern 2: Standard percentage with optional decimal
        $percentPattern = '(\d{1,3})(?:\.\d+)?%'
        $regexResult = [regex]::Match($Line, $percentPattern)
        if ($regexResult.Success) {
            return [int]$regexResult.Groups[1].Value
        }
        
        # Pattern 3: Progress: prefix format
        $progressPattern = 'Progress:\s*(\d{1,3})'
        $regexResult = [regex]::Match($Line, $progressPattern)
        if ($regexResult.Success) {
            return [int]$regexResult.Groups[1].Value
        }
        
        # Pattern 4: Simple bracket format
        $bracketPattern = '\[(\d{1,3})%\]'
        $regexResult = [regex]::Match($Line, $bracketPattern)
        if ($regexResult.Success) {
            return [int]$regexResult.Groups[1].Value
        }
        
        # Pattern 5: Verification/Scan format (for SFC)
        $verifyPattern = 'Verification\s+(\d{1,3})%\s+complete'
        $regexResult = [regex]::Match($Line, $verifyPattern)
        if ($regexResult.Success) {
            return [int]$regexResult.Groups[1].Value
        }
        
        return -1
    }
    
    function Send-ProgressUpdate {
        param([string]$Message)
        Write-Output "PROGRESS_LINE:$Message"
    }
    
    try {
        Send-ProgressUpdate "Starting $ExecutablePath with arguments: $Arguments"
        
        # Create process with proper configuration
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo.FileName = $ExecutablePath
        $process.StartInfo.Arguments = $Arguments
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        $process.StartInfo.CreateNoWindow = $true
        
        # Set proper encoding based on executable
        if ($ExecutablePath -like "*sfc.exe*") {
            try {
                $oemCP = [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
                $process.StartInfo.StandardOutputEncoding = $oemCP
                $process.StartInfo.StandardErrorEncoding = $oemCP
            }
            catch {
                $process.StartInfo.StandardOutputEncoding = [System.Text.Encoding]::Default
                $process.StartInfo.StandardErrorEncoding = [System.Text.Encoding]::Default
            }
        }
        else {
            $process.StartInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
            $process.StartInfo.StandardErrorEncoding = [System.Text.Encoding]::UTF8
        }
        
        # Start the process
        $processStarted = $process.Start()
        if (-not $processStarted) {
            throw "Failed to start process $ExecutablePath"
        }
        
        Send-ProgressUpdate "Process started successfully with PID: $($process.Id)"
        
        # Track progress updates
        $lastProgressUpdate = Get-Date
        $standardErrorText = ""
        $noProgressCounter = 0
        $lastEstimatedProgress = 0
        
        # Read output in a simple loop
        while (-not $process.HasExited) {
            try {
                if (-not $process.StandardOutput.EndOfStream) {
                    $line = $process.StandardOutput.ReadLine()
                    if ($null -ne $line) {
                        $cleanLine = Get-CleanOutputLine -RawLine $line
                        
                        if ($null -ne $cleanLine) {
                            $outputBuffer.Add($cleanLine)
                            
                            # Extract percentage if present
                            $percent = Get-ProgressPercent -Line $cleanLine
                            if ($percent -ge 0 -and $percent -le 100) {
                                # We got real progress
                                $lastProgressPercent = $percent
                                $lastRealProgress = Get-Date
                                $lastProgressUpdate = Get-Date
                                $noProgressCounter = 0  # Reset counter
                                Send-ProgressUpdate "$percent% - $cleanLine"
                            }
                            else {
                                # Send line with current percentage if we have one
                                if ($lastProgressPercent -gt 0) {
                                    Send-ProgressUpdate "$lastProgressPercent% - $cleanLine"
                                }
                                else {
                                    Send-ProgressUpdate $cleanLine
                                }
                            }
                        }
                    }
                }
                else {
                    # No output available - check if we should provide estimated progress
                    $timeSinceProgress = ((Get-Date) - $lastProgressUpdate).TotalSeconds
                    $timeSinceRealProgress = ((Get-Date) - $lastRealProgress).TotalSeconds
                    $elapsedTotal = ((Get-Date) - $jobStartTime).TotalSeconds
                    
                    # Only provide estimated progress under specific conditions
                    if ($timeSinceRealProgress -gt $estimateProgressAfter -and 
                        $timeSinceProgress -gt 30 -and 
                        $elapsedTotal -lt $progressTimeoutSeconds) {
                        
                        $noProgressCounter++
                        
                        # Provide conservative estimates based on executable type
                        if ($ExecutablePath -like "*DISM.exe*") {
                            # DISM estimation - very conservative during silent periods
                            if ($lastProgressPercent -lt 60) {
                                # Early phase - can increment slowly
                                $increment = [Math]::Min(1, [Math]::Floor($noProgressCounter / 4))
                            }
                            else {
                                # Later phase - DISM often stalls at 62% during cleanup
                                $increment = [Math]::Min(1, [Math]::Floor($noProgressCounter / 8))
                            }
                            
                            $newEstimate = [Math]::Min($lastProgressPercent + $increment, 95)
                            
                            if ($newEstimate -gt $lastEstimatedProgress -and ($noProgressCounter % 4) -eq 0) {
                                $lastEstimatedProgress = $newEstimate
                                Send-ProgressUpdate "$newEstimate% - DISM operation continuing (estimated)..."
                                $lastProgressUpdate = Get-Date
                            }
                        }
                        elseif ($ExecutablePath -like "*sfc.exe*") {
                            # SFC estimation - based on typical scan duration
                            $elapsedMinutes = $elapsedTotal / 60
                            $conservativeEstimate = [Math]::Min([int]($elapsedMinutes * 3), 95)
                            
                            if ($conservativeEstimate -gt $lastProgressPercent -and 
                                $conservativeEstimate -gt $lastEstimatedProgress) {
                                $lastEstimatedProgress = $conservativeEstimate
                                Send-ProgressUpdate "$conservativeEstimate% - System file scan continuing (estimated)..."
                                $lastProgressUpdate = Get-Date
                            }
                        }
                    }
                    
                    # Short sleep to prevent busy waiting
                    Start-Sleep -Milliseconds 250
                }
            }
            catch {
                # Continue on read errors
                Start-Sleep -Milliseconds 500
            }
        }
        
        # Process has exited, read any remaining output
        try {
            while (-not $process.StandardOutput.EndOfStream) {
                $line = $process.StandardOutput.ReadLine()
                if ($null -ne $line) {
                    $cleanLine = Get-CleanOutputLine -RawLine $line
                    if ($null -ne $cleanLine) {
                        $outputBuffer.Add($cleanLine)
                        
                        # Check for final percentage
                        $percent = Get-ProgressPercent -Line $cleanLine
                        if ($percent -ge 0 -and $percent -le 100) {
                            $lastProgressPercent = $percent
                        }
                    }
                }
            }
        }
        catch {
            # Error reading remaining output, continue
        }
        
        # Read standard error
        try {
            if (-not $process.StandardError.EndOfStream) {
                $standardErrorText = $process.StandardError.ReadToEnd()
                if (-not [string]::IsNullOrWhiteSpace($standardErrorText)) {
                    $standardErrorText = Get-CleanOutputLine -RawLine $standardErrorText
                    if ($null -eq $standardErrorText) { 
                        $standardErrorText = "Error output contained invalid characters" 
                    }
                }
            }
        }
        catch {
            $standardErrorText = "Failed to read standard error: $($_.Exception.Message)"
        }
        
        # Wait for process to fully exit
        $process.WaitForExit()
        $actualExitCode = $process.ExitCode
        
        # Send completion progress
        if ($actualExitCode -eq 0) {
            Send-ProgressUpdate "100% - Operation completed successfully"
        }
        else {
            Send-ProgressUpdate "$lastProgressPercent% - Process completed with exit code: $actualExitCode"
        }
        
        # Calculate duration
        $jobDuration = (Get-Date) - $jobStartTime
        
        # Output result object
        Write-Output "COMMAND_RESULT_START"
        Write-Output ([PSCustomObject]@{
            ExitCode       = $actualExitCode
            StandardError  = if ([string]::IsNullOrWhiteSpace($standardErrorText)) { "" } else { $standardErrorText }
            JobType        = "COMMAND"
            OutputLines    = $outputBuffer.Count
            Duration       = $jobDuration
            ProcessId      = $process.Id
            ExecutablePath = $ExecutablePath
            FinalProgress  = if ($actualExitCode -eq 0) { 100 } else { $lastProgressPercent }
        })
        Write-Output "COMMAND_RESULT_END"
        
        # Cleanup
        $process.Close()
        $process.Dispose()
        Send-ProgressUpdate "100% - Job completed successfully"
    }
    catch {
        $jobDuration = (Get-Date) - $jobStartTime
        $errorMessage = "Failed to start or monitor process: $($_.Exception.Message)"
        Send-ProgressUpdate "ERROR: $errorMessage"
        
        Write-Output "COMMAND_RESULT_START"
        Write-Output ([PSCustomObject]@{
            ExitCode       = -999
            StandardError  = $errorMessage
            JobType        = "COMMAND"
            OutputLines    = 0
            Duration       = $jobDuration
            ProcessId      = 0
            ExecutablePath = $ExecutablePath
            FinalProgress  = $lastProgressPercent
        })
        Write-Output "COMMAND_RESULT_END"
    }
}
#endregion

#region 8. Disk Cleanup ScriptBlock - Comprehensive System Cleanup (COMPLETE)
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
    $script:loggedLockedFiles = @{}

    function Write-LockedFileLog {
        param(
            [Parameter(Mandatory = $true)]
            [string]$FileName,
            
            [Parameter(Mandatory = $true)]
            [string]$Category
        )
        
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
            if (-not [string]::IsNullOrWhiteSpace($LogPath) -and (Test-Path (Split-Path $LogPath -Parent))) {
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $logEntry = "[$timestamp] [PROG] [System Cleanup] $message"
                
                $logMutex = [System.Threading.Mutex]::new($false, "RepairToolkitCleanupLog")
                try {
                    $acquired = $logMutex.WaitOne(1000)
                    if ($acquired) {
                        Add-Content -Path $LogPath -Value $logEntry -Encoding UTF8 -ErrorAction Stop
                    }
                }
                finally {
                    if ($acquired) {
                        $logMutex.ReleaseMutex()
                    }
                    $logMutex.Dispose()
                }
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
            # Return default categories
            return @(
                "Temporary Files",
                "Recycle Bin",
                "Temporary Internet Files",
                "Thumbnails",
                "Downloaded Program Files",
                "Windows Error Reporting Files",
                "Delivery Optimization Files",
                "Windows Update Cleanup"
            )
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
        # FIXED: Use $Host.Version instead of $PSVersionTable
        return $Host.Version.Major -ge $MinimumVersion
    }

    function Wait-ProcessStop {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ProcessName,
            
            [Parameter()]
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
        
        if (-not (Test-Path $WindowsOldPath)) {
            Write-SimpleLog "Windows.old path does not exist: $WindowsOldPath"
            return $true
        }
        
        try {
            Write-SimpleLog "Attempting Windows.old removal using multiple methods"
            
            # Method 1: Use cleanmgr with Previous Installations
            try {
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Previous Installations"
                if (Test-Path $regPath) {
                    Set-ItemProperty -Path $regPath -Name "StateFlags0099" -Value 2 -Type DWord -Force -ErrorAction Stop
                    Write-SimpleLog "Configured Previous Installations cleanup category"
                    
                    $process = Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/SAGERUN:0099" -WindowStyle Hidden -PassThru -ErrorAction Stop
                    $completed = $process.WaitForExit($CleanupTimeoutSeconds * 1000)
                    
                    if ($completed -and $process.ExitCode -eq 0) {
                        Write-SimpleLog "Windows.old cleanup completed via cleanmgr"
                        if (-not (Test-Path $WindowsOldPath)) {
                            return $true
                        }
                    }
                    else {
                        if (-not $completed) {
                            try {
                                $process.Kill()
                            }
                            catch {
                                Write-SimpleLog "Could not kill cleanmgr process: $($_.Exception.Message)"
                            }
                        }
                    }
                }
            }
            catch {
                Write-SimpleLog "Cleanmgr method failed: $($_.Exception.Message)"
            }
            
            # Method 2: Robocopy mirror method
            if (Test-RobocopyAvailable) {
                try {
                    Write-SimpleLog "Attempting Robocopy removal method"
                    $tempDirName = "EmptyForRobocopy_$($JobId)_$(Get-Random)"
                    $emptyDir = Join-Path $env:TEMP $tempDirName
                    
                    New-Item -Path $emptyDir -ItemType Directory -Force | Out-Null
                    
                    $robocopyArgs = @(
                        "`"$emptyDir`"",
                        "`"$WindowsOldPath`"",
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
                    $robocopyCompleted = $robocopyProcess.WaitForExit(($CleanupTimeoutSeconds / 2) * 1000)
                    
                    if ($robocopyCompleted) {
                        $exitCode = $robocopyProcess.ExitCode
                        Write-SimpleLog "Robocopy completed with exit code: $exitCode"
                        
                        # Robocopy exit codes 0-7 are success codes
                        if ($exitCode -le 7) {
                            Remove-Item $emptyDir -Force -Recurse -ErrorAction SilentlyContinue
                            Remove-Item $WindowsOldPath -Force -Recurse -ErrorAction SilentlyContinue
                            
                            if (-not (Test-Path $WindowsOldPath)) {
                                Write-SimpleLog "Windows.old removed successfully via Robocopy method"
                                return $true
                            }
                        }
                    }
                    else {
                        try {
                            $robocopyProcess.Kill()
                        }
                        catch {
                            Write-SimpleLog "Could not kill robocopy process: $($_.Exception.Message)"
                        }
                    }
                    
                    Remove-Item $emptyDir -Force -Recurse -ErrorAction SilentlyContinue
                }
                catch {
                    Write-SimpleLog "Robocopy removal method failed: $($_.Exception.Message)"
                }
            }
            
            # Method 3: PowerShell removal with retries
            try {
                Write-SimpleLog "Attempting PowerShell removal method"
                
                $removed = $false
                for ($attempt = 1; $attempt -le 3; $attempt++) {
                    try {
                        if (Test-Path $WindowsOldPath) {
                            Write-SimpleLog "PowerShell removal attempt $attempt"
                            
                            # First, try to remove files
                            Get-ChildItem -Path $WindowsOldPath -Recurse -Force -ErrorAction SilentlyContinue |
                            Where-Object { -not $_.PSIsContainer } |
                            Remove-Item -Force -ErrorAction SilentlyContinue
                            
                            # Then remove directories from deepest to shallowest
                            Get-ChildItem -Path $WindowsOldPath -Recurse -Force -ErrorAction SilentlyContinue |
                            Where-Object { $_.PSIsContainer } |
                            Sort-Object FullName -Descending |
                            Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                            
                            # Finally, remove the root directory
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
            
            # Check remaining content
            try {
                if (Test-Path $WindowsOldPath) {
                    $remainingSize = (Get-ChildItem -Path $WindowsOldPath -Recurse -Force -ErrorAction SilentlyContinue | 
                        Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                    
                    if ($null -eq $remainingSize) {
                        $remainingSize = 0
                    }
                    
                    $remainingSizeMB = [Math]::Round($remainingSize / 1MB, 1)
                    
                    Write-SimpleLog "Windows.old still exists with $remainingSizeMB MB remaining"
                    
                    # Consider partial success if significantly reduced
                    if ($remainingSizeMB -lt 100) {
                        Write-SimpleLog "Windows.old significantly reduced - considering partial success"
                        return $true
                    }
                }
            }
            catch {
                Write-SimpleLog "Could not check remaining Windows.old content: $($_.Exception.Message)"
            }
            
            Write-SimpleLog "All Windows.old removal methods completed"
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
            
            $cacheLocations = [System.Collections.Generic.List[string]]::new()
            
            # Check for custom cache location in registry
            try {
                $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
                if (Test-Path $regPath) {
                    $customCache = Get-ItemProperty -Path $regPath -Name "DOModifyCacheDrive" -ErrorAction SilentlyContinue
                    if ($customCache -and $customCache.DOModifyCacheDrive) {
                        $customPath = $customCache.DOModifyCacheDrive
                        if ($customPath -notlike "*:*") {
                            $customPath = "${customPath}:\DeliveryOptimization"
                        }
                        else {
                            $customPath = "${customPath}\DeliveryOptimization"
                        }
                        $cacheLocations.Add($customPath)
                        Write-SimpleLog "Found custom DO cache location: $customPath"
                    }
                }
            }
            catch {
                Write-SimpleLog "Could not read DO registry settings: $($_.Exception.Message)"
            }
            
            # Add default locations
            if ($cacheLocations.Count -eq 0) {
                $defaultLocations = @(
                    "$env:SYSTEMDRIVE\DeliveryOptimization",
                    "$env:WINDIR\SoftwareDistribution\DeliveryOptimization",
                    "$env:WINDIR\SoftwareDistribution\Download",
                    "$env:ProgramData\Microsoft\Windows\DeliveryOptimization"
                )
                foreach ($loc in $defaultLocations) {
                    $cacheLocations.Add($loc)
                }
            }
            
            # Check all drives for additional DO caches
            foreach ($drive in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
                if ($null -eq $drive) { continue }
                
                $driveLetter = $drive.Name
                $alternatePaths = @(
                    "${driveLetter}:\DeliveryOptimization",
                    "${driveLetter}:\Windows.old\Windows\SoftwareDistribution\DeliveryOptimization"
                )
                foreach ($alternatePath in $alternatePaths) {
                    if ((Test-Path $alternatePath) -and -not $cacheLocations.Contains($alternatePath)) {
                        $cacheLocations.Add($alternatePath)
                        Write-SimpleLog "Found additional DO cache: $alternatePath"
                    }
                }
            }
            
            # Process each location
            foreach ($location in $cacheLocations) {
                if (Test-Path $location) {
                    try {
                        Write-SimpleLog "Processing DO cache location: $location"
                        $cacheFiles = Get-ChildItem -Path $location -Recurse -Force -ErrorAction SilentlyContinue |
                        Where-Object { 
                            -not $_.PSIsContainer -and 
                            $_.Length -gt 0 -and
                            $_.Length -lt 15GB
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
                            Write-SimpleLog "Delivery Optimization from ${location}: $locationFiles files, $locationSizeMB MB"
                        }
                    }
                    catch {
                        Write-SimpleLog "Error processing DO location ${location}: $($_.Exception.Message)"
                    }
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
            
            $currentUserPaths = [System.Collections.Generic.List[hashtable]]::new()
            
            # Internet Explorer / Edge paths
            $basePaths = @(
                @{ Path = "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"; Name = "IE/Edge Cache" },
                @{ Path = "$env:LOCALAPPDATA\Microsoft\Windows\INetCookies"; Name = "IE/Edge Cookies" },
                @{ Path = "$env:LOCALAPPDATA\Microsoft\Windows\WebCache"; Name = "Web Cache" },
                @{ Path = "$env:LOCALAPPDATA\Temp\IEDownloadHistory"; Name = "IE Download History" },
                @{ Path = "$env:APPDATA\Microsoft\Windows\Cookies"; Name = "Legacy Cookies" }
            )
            
            foreach ($pathInfo in $basePaths) {
                $currentUserPaths.Add($pathInfo)
            }
            
            # Browser-specific paths
            $browserBasePaths = @(
                @{ Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"; Name = "Edge Chromium" },
                @{ Path = "$env:LOCALAPPDATA\Google\Chrome\User Data"; Name = "Chrome" },
                @{ Path = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"; Name = "Brave" }
            )
            
            foreach ($browserBase in $browserBasePaths) {
                if (Test-Path $browserBase.Path) {
                    try {
                        $profiles = Get-ChildItem -Path $browserBase.Path -Directory -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match "^(Default|Profile \d+|System Profile|Guest Profile)$" }
                        
                        if ($profiles) {
                            foreach ($userProfile in $profiles) {
                                $cachePaths = @(
                                    @{ Path = (Join-Path $userProfile.FullName "Cache"); Name = "$($browserBase.Name) Cache ($($userProfile.Name))" },
                                    @{ Path = (Join-Path $userProfile.FullName "Code Cache"); Name = "$($browserBase.Name) Code Cache ($($userProfile.Name))" },
                                    @{ Path = (Join-Path $userProfile.FullName "GPUCache"); Name = "$($browserBase.Name) GPU Cache ($($userProfile.Name))" }
                                )
                                
                                foreach ($cachePath in $cachePaths) {
                                    if ($null -ne $cachePath) {
                                        $currentUserPaths.Add($cachePath)
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        Write-SimpleLog "Error enumerating $($browserBase.Name) profiles: $($_.Exception.Message)"
                    }
                }
            }
            
            # Firefox profiles
            $firefoxProfilesPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
            if (Test-Path $firefoxProfilesPath) {
                try {
                    $firefoxProfiles = Get-ChildItem -Path $firefoxProfilesPath -Directory -ErrorAction SilentlyContinue
                    if ($firefoxProfiles) {
                        foreach ($firefoxUserProfile in $firefoxProfiles) {
                            $firefoxCache = Join-Path $firefoxUserProfile.FullName "cache2"
                            if (Test-Path $firefoxCache) {
                                $currentUserPaths.Add(@{ Path = $firefoxCache; Name = "Firefox Cache ($($firefoxUserProfile.Name))" })
                            }
                        }
                    }
                }
                catch {
                    Write-SimpleLog "Error enumerating Firefox profiles: $($_.Exception.Message)"
                }
            }
            
            # Process all paths
            foreach ($pathInfo in $currentUserPaths) {
                if ($null -ne $pathInfo -and $pathInfo.Path -and (Test-Path $pathInfo.Path)) {
                    try {
                        $ageThreshold = (Get-Date).AddHours(-2)
                        
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
            
            # Legacy IE cache
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
            
            # Try to measure recycle bin size first
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
            
            # Try modern Clear-RecycleBin cmdlet first
            if (Test-PowerShellVersion -MinimumVersion 5) {
                try {
                    Clear-RecycleBin -Force -ErrorAction Stop
                    
                    Start-Sleep -Milliseconds 500
                    
                    if ($recyclerStats.Files -gt 0) {
                        $recyclerSizeMB = [Math]::Round($recyclerStats.Size / 1MB, 1)
                        Write-SimpleLog "Recycle Bin (modern): $($recyclerStats.Files) files, $recyclerSizeMB MB"
                    }
                    else {
                        Write-SimpleLog "Recycle Bin was already empty"
                    }
                    
                    return $recyclerStats
                }
                catch {
                    Write-SimpleLog "Modern Clear-RecycleBin failed: $($_.Exception.Message)"
                }
            }
            
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
                                # Silently continue
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
        catch {
            Write-SimpleLog "Error in Recycle Bin cleanup: $($_.Exception.Message)"
            return @{ Files = 0; Size = 0 }
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
                if ($null -eq $pathInfo -or [string]::IsNullOrEmpty($pathInfo.Path) -or -not (Test-Path $pathInfo.Path)) {
                    continue
                }
                
                try {
                    # Special handling for CBS logs
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
                                Write-SimpleLog "Could not remove CBS.log: File may be in use"
                            }
                        }
                    }
                    
                    # Get files based on path type
                    $files = Get-ChildItem -Path $pathInfo.Path -Force -ErrorAction SilentlyContinue |
                    Where-Object { 
                        -not $_.PSIsContainer -and 
                        $_.Length -gt 0 -and 
                        $_.Length -lt $pathInfo.MaxSize
                    }
                    
                    # Apply specific filters based on path type
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
            
            # Empty Recycle Bin
            try {
                Write-SimpleLog "Emptying Recycle Bin"
                $recyclerResult = Clear-RecycleBinSafely
                $totalFiles += $recyclerResult.Files
                $totalSize += $recyclerResult.Size
            }
            catch {
                Write-SimpleLog "Error cleaning Recycle Bin: $($_.Exception.Message)"
            }
            
            # Additional temp paths
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
                                    Write-LockedFileLog -FileName $file.Name -Category "Additional Temp Files"
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
            $thumbnailPaths = @(
                "$env:LOCALAPPDATA\Thumbnails",
                "$env:LOCALAPPDATA\Microsoft\Media Player",
                "$env:APPDATA\Microsoft\Windows\Themes\CachedFiles",
                "$env:LOCALAPPDATA\Microsoft\Windows\Caches"
            )
            
            $totalSize = 0
            $totalFiles = 0
            
            foreach ($path in $thumbnailPaths) {
                if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path $path)) {
                    continue
                }
                
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
                                # Silently continue
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
            if (-not $AggressiveLogCleanup) {
                Write-SimpleLog "Aggressive log cleanup disabled - skipping Windows upgrade logs"
                return @{ Files = 0; Size = 0 }
            }
            
            Write-SimpleLog "Targeting Windows upgrade logs with aggressive cleanup"
            
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
                if ($null -eq $pathInfo -or [string]::IsNullOrEmpty($pathInfo.Path) -or -not (Test-Path $pathInfo.Path)) {
                    continue
                }
                
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
                    
                    # Special filters for specific paths
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
                }
                catch {
                    Write-SimpleLog "Error processing $($pathInfo.Name): $($_.Exception.Message)"
                }
            }
            
            # Clean specific setup files
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
                    if ($null -ne $setupFileInfo -and -not [string]::IsNullOrEmpty($setupFileInfo.Name)) {
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
            
            # Clean additional log paths
            try {
                $additionalLogPaths = @(
                    "$env:WINDIR\Logs",
                    "$env:WINDIR\System32\LogFiles",
                    "$env:WINDIR\SoftwareDistribution\DataStore\Logs"
                )
                
                foreach ($logPath in $additionalLogPaths) {
                    if ([string]::IsNullOrWhiteSpace($logPath) -or -not (Test-Path $logPath)) {
                        continue
                    }
                    
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
                                # Silently continue
                            }
                        }
                    }
                    
                    if ($logCount -gt 0) {
                        $logSizeMB = [Math]::Round($logSize / 1MB, 1)
                        Write-SimpleLog "Additional logs from $logPath`: $logCount files, $logSizeMB MB"
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
            
            $explorerCacheFiles = [System.Collections.Generic.List[string]]::new()
            $explorerCacheFiles.Add("$env:LOCALAPPDATA\IconCache.db")
            
            # Find additional Explorer caches
            try {
                $additionalCaches = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\*.db" -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match "(thumbcache|iconcache)_.*\.db$" }
                
                if ($additionalCaches) {
                    foreach ($cache in $additionalCaches) {
                        $explorerCacheFiles.Add($cache.FullName)
                    }
                }
            }
            catch {
                Write-SimpleLog "Could not enumerate additional Explorer caches: $($_.Exception.Message)"
            }
            
            # Remove cache files
            $cachesCleaned = 0
            foreach ($cacheFile in $explorerCacheFiles) {
                if ([string]::IsNullOrWhiteSpace($cacheFile) -or -not (Test-Path $cacheFile)) {
                    continue
                }
                
                try {
                    $file = Get-Item $cacheFile -Force
                    $fileSize = $file.Length
                    Remove-Item $cacheFile -Force -ErrorAction Stop
                    $cachesCleaned++
                    $totalFiles++
                    $totalSize += $fileSize
                    $fileSizeMB = [Math]::Round($fileSize / 1MB, 1)
                    Write-SimpleLog "Removed Explorer cache: $(Split-Path $cacheFile -Leaf) ($fileSizeMB MB)"
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

    # Initialize script variables for the job
    $script:LogPath = $LogPath
    $script:JobId = $JobId
    $script:CleanupTimeoutSeconds = $CleanupTimeoutSeconds
    $script:AggressiveLogCleanup = $AggressiveLogCleanup
    
    $script:loggedLockedFiles = @{}

    # Main cleanup execution
    try {
        Write-SimpleLog "Enhanced Windows 11 disk cleanup started with Job ID: $JobId"
        Write-SimpleLog "Configuration: CleanupTimeout=$CleanupTimeoutSeconds seconds, AggressiveLogCleanup=$AggressiveLogCleanup"
        Update-Progress -Percent 0 -Message "Starting enhanced cleanup..."
        
        # Step 1: Detect available cleanup categories
        Update-Progress -Percent 5 -Message "Detecting available cleanup categories..."
        
        try {
            $availableCategories = Get-AvailableCleanupCategories
            Write-SimpleLog "Available categories: $($availableCategories -join ', ')"
        }
        catch {
            Write-SimpleLog "Category detection failed: $($_.Exception.Message)"
            $availableCategories = @("Temporary Files", "Recycle Bin", "Temporary Internet Files", "Thumbnails", "Downloaded Program Files")
        }
        
        # Step 2: Configure cleanup categories
        Update-Progress -Percent 10 -Message "Configuring $($availableCategories.Count) cleanup categories..."
        
        $cleanupSuccess = $false
        try {
            $cleanupSuccess = Invoke-EnhancedCleanup -Categories $availableCategories -SageSet 65
        }
        catch {
            Write-SimpleLog "Enhanced cleanup failed: $($_.Exception.Message)"
        }
        
        Update-Progress -Percent 20 -Message "Registry cleanup configuration completed"
        
        # Step 3: Windows.old handling
        $windowsOldPath = "C:\Windows.old"
        $windowsOldExists = Test-Path $windowsOldPath
        $windowsOldRemoved = $false
        
        if ($windowsOldExists) {
            Update-Progress -Percent 25 -Message "Windows.old folder detected - requesting user decision..."
            Write-Output "WINDOWS_OLD_EXISTS:True"
            Write-Output "WINDOWS_OLD_PATH:$windowsOldPath"
            
            # Wait for user decision
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
                Update-Progress -Percent 30 -Message "Removing Windows.old folder..."
                try {
                    $windowsOldRemoved = Remove-WindowsOld -WindowsOldPath $windowsOldPath
                    
                    if ($windowsOldRemoved) {
                        Update-Progress -Percent 35 -Message "Windows.old folder successfully removed"
                    }
                    else {
                        Update-Progress -Percent 35 -Message "Windows.old removal attempted"
                    }
                }
                catch {
                    Write-SimpleLog "Windows.old removal failed: $($_.Exception.Message)"
                    Update-Progress -Percent 35 -Message "Windows.old removal encountered errors"
                }
            }
            else {
                Update-Progress -Percent 35 -Message "Windows.old folder preserved"
            }
        }
        else {
            Update-Progress -Percent 35 -Message "No Windows.old folder detected"
        }
        
        Update-Progress -Percent 40 -Message "Windows.old processing completed"
        
        # Step 4: Run targeted cleanup operations
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
        
        # Calculate total cleaned
        $customCleanupTotal = $defenderResult.Size + $deliveryResult.Size + $internetResult.Size + 
                              $tempResult.Size + $thumbResult.Size + $upgradeResult.Size
        $customCleanupMB = [Math]::Round($customCleanupTotal / 1MB, 1)
        
        # Step 5: Run native Windows cleanup as fallback if needed
        if ($customCleanupMB -lt 50 -and $cleanupSuccess) {
            Update-Progress -Percent 68 -Message "Running native Windows cleanup as fallback..."
            try {
                Write-SimpleLog "Custom cleanup only freed $customCleanupMB MB, running native cleanmgr"
                
                $cleanmgrProcess = Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/SAGERUN:65" -WindowStyle Hidden -PassThru -ErrorAction Stop
                $cleanmgrCompleted = $cleanmgrProcess.WaitForExit(($CleanupTimeoutSeconds / 2) * 1000)
                
                if ($cleanmgrCompleted) {
                    Write-SimpleLog "Native cleanup completed with exit code: $($cleanmgrProcess.ExitCode)"
                }
                else {
                    Write-SimpleLog "Native cleanup timed out"
                    try {
                        $cleanmgrProcess.Kill()
                    }
                    catch {
                        Write-SimpleLog "Could not kill cleanmgr process: $($_.Exception.Message)"
                    }
                }
            }
            catch {
                Write-SimpleLog "Native cleanup fallback failed: $($_.Exception.Message)"
            }
        }
        
        Update-Progress -Percent 70 -Message "Targeted cleanup phases completed"
        
        # Step 6: Network optimization
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
            
            if ($winsockResult -match "successfully") {
                Write-SimpleLog "Winsock reset completed successfully"
            }
            else {
                Write-SimpleLog "Winsock reset result: $winsockResult"
            }
            
            Write-SimpleLog "Network optimization completed"
        }
        catch {
            Write-SimpleLog "Network optimization failed: $($_.Exception.Message)"
        }
        
        # Step 7: Explorer restart for visual optimization
        Update-Progress -Percent 85 -Message "Preparing visual performance optimization..."
        Write-Output "EXPLORER_RESTART_REQUEST:True"
        
        # Wait for Explorer restart decision
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
                
                $explorerStopped = Wait-ProcessStop -ProcessName "explorer" -TimeoutSeconds 15
                if ($explorerStopped) {
                    Write-SimpleLog "Explorer stopped successfully"
                }
                
                Start-Sleep -Seconds 2
                
                # Clear Explorer caches
                $explorerCacheResult = Clear-ExplorerCaches -JobId $JobId
                
                # Restart Explorer
                Start-Process "explorer.exe" -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                
                $explorerRunning = Get-Process -Name "explorer" -ErrorAction SilentlyContinue
                if ($explorerRunning) {
                    Update-Progress -Percent 90 -Message "Visual performance optimized"
                    Write-SimpleLog "Explorer restarted successfully"
                }
            }
            catch {
                Write-SimpleLog "Explorer restart failed: $($_.Exception.Message)"
                Update-Progress -Percent 90 -Message "Visual optimization completed with issues"
                
                # Fallback Explorer restart
                try {
                    Start-Process "explorer.exe" -ErrorAction SilentlyContinue
                }
                catch {
                    Write-SimpleLog "Explorer fallback restart failed"
                }
            }
        }
        else {
            Update-Progress -Percent 90 -Message "Visual optimization skipped"
        }
        
        # Finalize
        $jobDuration = (Get-Date) - $jobStartTime
        Update-Progress -Percent 100 -Message "Enhanced cleanup and optimization completed!"
        
        # Calculate totals
        $totalFiles = $defenderResult.Files + $deliveryResult.Files + $internetResult.Files + 
                      $tempResult.Files + $thumbResult.Files + $upgradeResult.Files + $explorerCacheResult.Files
        $totalSize = $defenderResult.Size + $deliveryResult.Size + $internetResult.Size + 
                     $tempResult.Size + $thumbResult.Size + $upgradeResult.Size + $explorerCacheResult.Size
        $totalSizeMB = [Math]::Round($totalSize / 1MB, 1)
        
        # Log summary
        Write-SimpleLog "=== TARGETED CLEANUP SUMMARY ==="
        Write-SimpleLog "Registry cleanup success: $cleanupSuccess"
        Write-SimpleLog "TOTAL TARGETED CLEANUP: $totalFiles files, $totalSizeMB MB freed"
        $durationText = "{0:D2}:{1:D2}" -f [int][Math]::Floor($jobDuration.TotalMinutes), [int]$jobDuration.Seconds
        Write-SimpleLog "Targeted cleanup completed in $durationText"
        
        # Check if Windows.old was actually removed
        $windowsOldFinallyRemoved = $windowsOldExists -and $windowsOldRemoved -and (-not (Test-Path $windowsOldPath))
        
        # Output final result
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
            CompletedTasks            = "Registry cleanup, Windows.old removal, targeted cleanup, network optimization, visual optimization"
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

#region 9. Job Management Functions - Background Job Control
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
        [ValidateNotNull()]
        [string]$Arguments,
        
        [Parameter()]
        [string]$InitialStatus = "Operation in progress..."
    )
    
    # Check if another job is running
    if ($null -ne $script:currentRepairJob) {
        $message = "Another repair operation is already in progress. Please wait for it to complete."
        Show-WarningMessage -Message $message
        Write-RepairLog -Message "Job start blocked: Another job is running" -Category "WARNING"
        return $false
    }
    
    # Validate executable exists
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
            $executableFound = $false
        }
    }
    
    if (-not $executableFound) {
        $message = "Executable not found: $Executable"
        Show-ErrorMessage -Message $message
        Write-RepairLog -Message "Job start failed: Executable not found: $Executable" -Category "ERROR"
        return $false
    }
    
    Write-RepairLog -Message "Starting repair job: $JobName" -Category "JOB"
    Update-UiForJobStart -StatusMessage $InitialStatus
    
    # Reset job state
    $script:operationStartTime = Get-Date
    $script:progressMessageCount = 0
    $script:capturedJobResult = $null
    $script:fallbackProgressEnabled = $false
    $script:progressCommunicationFailures = 0
    $script:lastFallbackLogTime = [DateTime]::MinValue
    $script:lastProgressUpdate = Get-Date
    
    try {
        # Start background job
        $script:currentRepairJob = Start-Job -Name $JobName -ScriptBlock $script:commandRunnerScriptBlock -ArgumentList $Executable, $Arguments
        
        if ($null -ne $script:currentRepairJob) {
            # Track job in collection
            $jobInfo = @{
                Job = $script:currentRepairJob
                StartTime = $script:operationStartTime
                Type = $JobName
                Executable = $Executable
            }
            $script:jobCollection.TryAdd($script:currentRepairJob.Id.ToString(), $jobInfo) | Out-Null
            
            Write-RepairLog -Message "Job started with ID: $($script:currentRepairJob.Id)" -Category "JOB"
        }
        
        # Start progress monitoring
        Start-ProgressTimer
        Write-RepairLog -Message "Background job started successfully" -Category "JOB"
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
    $result = Start-RepairJob -JobName "DISMRepairJob" `
                              -Executable "DISM.exe" `
                              -Arguments "/Online /Cleanup-Image /RestoreHealth" `
                              -InitialStatus "DISM Repair in progress... 0%"
    
    if (-not $result) {
        Write-RepairLog -Message "DISM repair job failed to start" -Category "ERROR" -Operation "DISM"
        Write-OperationEnd -OperationType "DISM" -Success $false -ExitCode -1
    }
}

function Start-SFCRepair {
    [CmdletBinding()]
    param()
    
    if (-not (Confirm-AdminOrFail -OperationName "SFC System File Check")) { 
        return 
    }
    
    Write-OperationStart -OperationType "SFC"
    $result = Start-RepairJob -JobName "SFCRepairJob" `
                              -Executable "sfc.exe" `
                              -Arguments "/scannow" `
                              -InitialStatus "SFC Scan in progress... 0%"
    
    if (-not $result) {
        Write-RepairLog -Message "SFC repair job failed to start" -Category "ERROR" -Operation "SFC"
        Write-OperationEnd -OperationType "SFC" -Success $false -ExitCode -1
    }
}

function Start-DiskCleanup {
    [CmdletBinding()]
    param()
    
    if (-not (Confirm-AdminOrFail -OperationName "Comprehensive System Cleanup")) { 
        return 
    }
    
    # Check if another job is running
    if ($null -ne $script:currentRepairJob) {
        $message = "Another repair operation is already in progress."
        Show-WarningMessage -Message $message
        return
    }
    
    Write-OperationStart -OperationType "CLEANUP"
    
    Update-UiForJobStart -StatusMessage "System Optimization in progress... 0%"
    
    # Initialize cleanup job state
    $script:operationStartTime = Get-Date
    $script:progressMessageCount = 0
    $script:capturedJobResult = $null
    $script:currentJobId = [System.Guid]::NewGuid().ToString("N").Substring(0, 12)
    $script:lastUiUpdate = [DateTime]::MinValue
    $script:fallbackProgressEnabled = $false
    $script:progressCommunicationFailures = 0
    $script:lastProgressUpdate = Get-Date
    $script:lastFallbackLogTime = [DateTime]::MinValue
    
    Write-RepairLog -Message "Cleanup operation initialized with Job ID: $script:currentJobId" -Category "JOB" -Operation "CLEANUP"
    
    try {
        # Start cleanup job with parameters
        $script:currentRepairJob = Start-Job -Name "DiskCleanupJob" `
                                             -ScriptBlock $script:diskCleanupScriptBlock `
                                             -ArgumentList $script:logPath, $script:currentJobId, 300, $false
        
        if ($null -ne $script:currentRepairJob) {
            # Track job in collection
            $jobInfo = @{
                Job = $script:currentRepairJob
                StartTime = $script:operationStartTime
                Type = "DiskCleanup"
                JobId = $script:currentJobId
            }
            $script:jobCollection.TryAdd($script:currentRepairJob.Id.ToString(), $jobInfo) | Out-Null
            
            Write-RepairLog -Message "Cleanup job started with ID: $($script:currentRepairJob.Id)" -Category "JOB"
        }
        
        # Start progress monitoring
        Start-ProgressTimer
        Write-RepairLog -Message "Cleanup background job started successfully" -Category "JOB" -Operation "CLEANUP"
    }
    catch {
        Write-RepairLog -Message "Failed to start cleanup job: $($_.Exception.Message)" -Category "ERROR" -Operation "CLEANUP"
        Update-UiForJobEnd -StatusMessage "ERROR: Failed to start cleanup operation." -IsSuccess $false
        Write-OperationEnd -OperationType "CLEANUP" -Success $false -ExitCode -1
    }
}

function Start-ProgressTimer {
    [CmdletBinding()]
    param()
    
    try {
        # Stop existing timer if any
        Stop-ProgressTimer
        
        # Check if form is valid
        if ($null -ne $script:form -and ($script:form.IsDisposed -or $script:form.Disposing)) {
            Write-RepairLog -Message "Cannot start timer - form is disposed" -Category "WARNING"
            return
        }
        
        # Create new timer
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
            Write-RepairLog -Message "Stopping progress timer" -Category "JOB"
            
            # Store reference and clear script variable immediately
            $timerToStop = $script:progressUpdateTimer
            $script:progressUpdateTimer = $null
            
            # Stop timer
            try {
                if ($timerToStop.Enabled) {
                    $timerToStop.Stop()
                }
            }
            catch {
                Write-RepairLog -Message "Error stopping timer: $($_.Exception.Message)" -Category "WARNING"
            }
            
            # Remove event handler
            try {
                $timerToStop.Remove_Tick($script:progressTimerAction)
            }
            catch {
                Write-RepairLog -Message "Error removing timer event: $($_.Exception.Message)" -Category "WARNING"
            }
            
            # Dispose timer
            try {
                $timerToStop.Dispose()
            }
            catch {
                Write-RepairLog -Message "Error disposing timer: $($_.Exception.Message)" -Category "WARNING"
            }
            
            Write-RepairLog -Message "Progress timer stopped and disposed" -Category "JOB"
        }
    }
    catch {
        Write-RepairLog -Message "Error stopping progress timer: $($_.Exception.Message)" -Category "WARNING"
        $script:progressUpdateTimer = $null
    }
}

function Stop-AllJobs {
    [CmdletBinding()]
    param()
    
    try {
        Write-RepairLog -Message "Stopping all running jobs" -Category "JOB"
        
        # Stop current job if running
        if ($null -ne $script:currentRepairJob) {
            if ($script:currentRepairJob.State -eq 'Running') {
                Write-RepairLog -Message "Stopping job: $($script:currentRepairJob.Name)" -Category "JOB"
                $script:currentRepairJob | Stop-Job -ErrorAction SilentlyContinue
            }
            $script:currentRepairJob | Remove-Job -ErrorAction SilentlyContinue
            $script:currentRepairJob = $null
        }
        
        # Clear job collection
        foreach ($jobId in $script:jobCollection.Keys) {
            $jobInfo = $null
            if ($script:jobCollection.TryGetValue($jobId, [ref]$jobInfo)) {
                if ($null -ne $jobInfo -and $null -ne $jobInfo.Job) {
                    try {
                        if ($jobInfo.Job.State -eq 'Running') {
                            $jobInfo.Job | Stop-Job -ErrorAction SilentlyContinue
                        }
                        $jobInfo.Job | Remove-Job -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-RepairLog -Message "Error removing job $jobId`: $($_.Exception.Message)" -Category "WARNING"
                    }
                }
            }
        }
        $script:jobCollection.Clear()
        
        # Clear communication files
        Clear-JobCommunicationFiles
        
        Write-RepairLog -Message "All jobs stopped" -Category "JOB"
    }
    catch {
        Write-RepairLog -Message "Error stopping all jobs: $($_.Exception.Message)" -Category "ERROR"
    }
}
#endregion

#region 10. Progress Timer and Job Processing - Real-time Progress Monitoring
$script:progressTimerAction = {
    try {
        # Basic validation
        if ($null -eq $script:currentRepairJob -or 
            $null -eq $script:form -or $script:form.IsDisposed) {
            Stop-ProgressTimer
            return
        }
        
        # Check job state first
        $jobState = $script:currentRepairJob.State
        
        if ($jobState -ne [System.Management.Automation.JobState]::Running) {
            Write-RepairLog -Message "Job completed, state: $jobState" -Category "JOB"
            Complete-JobExecution
            return
        }
        
        # Simplified and more reliable job output reading
        $hasNewProgress = $false
        if ($script:currentRepairJob.HasMoreData) {
            try {
                # Use a safer approach with proper error handling
                $newOutput = @()
                
                # Try to receive new output without -Keep to avoid conflicts
                try {
                    $allOutput = @(Receive-Job -Job $script:currentRepairJob -Keep -ErrorAction Stop)
                    
                    # Only process new output since last check
                    if ($allOutput.Count -gt $script:lastOutputCount) {
                        $newOutput = $allOutput[$script:lastOutputCount..($allOutput.Count - 1)]
                        $script:lastOutputCount = $allOutput.Count
                    }
                }
                catch {
                    # If -Keep fails, try without it and track differently
                    try {
                        $freshOutput = @(Receive-Job -Job $script:currentRepairJob -ErrorAction Stop)
                        if ($freshOutput.Count -gt 0) {
                            $newOutput = $freshOutput
                        }
                    }
                    catch {
                        # Complete failure - continue to fallback progress
                    }
                }
                
                if ($newOutput.Count -gt 0) {
                    $hasNewProgress = Invoke-NewJobOutput -Output $newOutput
                }
            }
            catch {
                # Only log unexpected errors, not stream conflicts
                if ($_.Exception.Message -notlike "*stream*" -and $_.Exception.Message -notlike "*use*") {
                    Write-RepairLog -Message "Timer output warning: $($_.Exception.Message)" -Category "DEBUG"
                }
            }
        }
        
        # Calculate runtime for fallback progress
        $jobRuntime = if ($script:operationStartTime -ne [DateTime]::MinValue) { 
            (Get-Date) - $script:operationStartTime 
        } else { 
            New-TimeSpan 
        }
        
        # Enable fallback progress if no updates for a while
        if (-not $hasNewProgress -and $jobRuntime.TotalSeconds -gt 30) {
            if (-not $script:fallbackProgressEnabled) {
                $script:fallbackProgressEnabled = $true
                $script:progressCommunicationFailures++
                Write-RepairLog -Message "Enabling fallback progress estimation" -Category "WARNING"
            }
            Update-FallbackProgress
        }
        
        # Update status display
        Update-StatusDisplay
        
    }
    catch {
        Write-RepairLog -Message "Timer error: $($_.Exception.Message)" -Category "ERROR"
        try {
            Stop-ProgressTimer
            if ($null -ne $script:form -and -not $script:form.IsDisposed) {
                Update-UiForJobEnd -StatusMessage "ERROR: Progress monitoring failed." -IsSuccess $false
            }
        }
        catch {
            # Final fallback
        }
    }
}

function Update-FallbackProgress {
    if ($script:operationStartTime -eq [DateTime]::MinValue) { return }
    
    $elapsed = (Get-Date) - $script:operationStartTime
    $jobDisplayName = if ($null -ne $script:currentRepairJob) {
        Get-JobDisplayName -JobName $script:currentRepairJob.Name
    } else {
        "Operation"
    }
    
    # Calculate estimated progress based on job type and elapsed time
    $estimatedProgress = switch ($jobDisplayName) {
        "DISM Repair" {
            # DISM typically takes 15-30 minutes
            [Math]::Min(($elapsed.TotalMinutes / 25) * 95, 95)
        }
        "SFC Scan" {
            # SFC typically takes 10-30 minutes
            [Math]::Min(($elapsed.TotalMinutes / 20) * 95, 95)
        }
        "System Optimization" {
            # Cleanup typically takes 3-10 minutes
            [Math]::Min(($elapsed.TotalMinutes / 5) * 95, 95)
        }
        default {
            # Generic estimation
            [Math]::Min(($elapsed.TotalMinutes / 10) * 95, 95)
        }
    }
    
    $estimatedProgress = [int]$estimatedProgress
    
    # Calculate time since last update
    $timeSinceLastUpdate = if ($script:lastProgressUpdate -ne [DateTime]::MinValue) { 
        (Get-Date) - $script:lastProgressUpdate 
    }
    else { 
        $elapsed 
    }
    
    # Update progress if significant time has passed
    if ($timeSinceLastUpdate.TotalSeconds -gt 45 -and $estimatedProgress -gt 0) {
        try {
            if ($null -ne $script:progressBar -and -not $script:progressBar.IsDisposed) {
                $currentValue = $script:progressBar.Value
                
                # Only apply fallback progress if reasonable
                if (($estimatedProgress -gt $currentValue -or $currentValue -eq 0) -and 
                    $estimatedProgress -le ($currentValue + 10)) {
                    
                    # Use the safe update function
                    Update-ProgressBarSafe -Percent $estimatedProgress
                }
                
                # Improved logging to reduce spam
                $currentTime = Get-Date
                
                # Initialize lastFallbackEnableLog if not exists
                if (-not (Get-Variable -Name 'lastFallbackEnableLog' -Scope Script -ErrorAction SilentlyContinue)) {
                    $script:lastFallbackEnableLog = [DateTime]::MinValue
                }
                
                # Only log fallback progress periodically (every 30 seconds)
                if ($script:lastFallbackLogTime -eq [DateTime]::MinValue -or 
                    ($currentTime - $script:lastFallbackLogTime).TotalSeconds -gt 30) {
                    
                    # Check if we need to log the initial enable message
                    if (-not $script:fallbackProgressEnabled) {
                        $script:fallbackProgressEnabled = $true
                        $script:progressCommunicationFailures++
                        Write-RepairLog -Message "Enabling fallback progress estimation (no updates for $([int]$timeSinceLastUpdate.TotalSeconds) seconds)" -Category "INFO"
                        $script:lastFallbackEnableLog = $currentTime
                    }
                    elseif (($currentTime - $script:lastFallbackEnableLog).TotalSeconds -gt 60) {
                        # Only log status update every 60 seconds to reduce spam
                        Write-RepairLog -Message "Fallback progress active: $estimatedProgress% (estimated)" -Category "DEBUG"
                        $script:lastFallbackEnableLog = $currentTime
                    }
                    
                    # Log the actual progress percentage every 30 seconds
                    if ($estimatedProgress -ne $currentValue) {
                        Write-RepairLog -Message "Fallback progress: $estimatedProgress% (estimated)" -Category "INFO"
                    }
                    
                    $script:lastFallbackLogTime = $currentTime
                }
            }
        }
        catch {
            Write-RepairLog -Message "Error updating fallback progress: $($_.Exception.Message)" -Category "WARNING"
        }
    }
}

function Complete-JobExecution {
    try {
        # Stop timer first to prevent race conditions
        Stop-ProgressTimer
        
        # Validate form
        if ($null -eq $script:form -or $script:form.IsDisposed) {
            return
        }
        
        # Get job reference
        $jobToProcess = $script:currentRepairJob
        $script:currentRepairJob = $null
        
        if ($null -eq $jobToProcess) {
            Write-RepairLog -Message "No job to complete" -Category "WARNING"
            return
        }
        
        Write-RepairLog -Message "Completing job: $($jobToProcess.Name) (State: $($jobToProcess.State))" -Category "JOB"
        
        # Give the job a moment to finish writing output
        Start-Sleep -Milliseconds 500
        
        # Get final result - try captured result first, then fetch from job
        $jobResult = $script:capturedJobResult
        if ($null -eq $jobResult) {
            Write-RepairLog -Message "Getting result from job output" -Category "JOB"
            $jobResult = Get-JobResult -Job $jobToProcess
        }
        
        # Update progress to 100% if successful
        if ($null -ne $jobResult -and $jobResult.ExitCode -eq 0) {
            try {
                if ($null -ne $script:progressBar -and -not $script:progressBar.IsDisposed) {
                    if ($script:progressBar.InvokeRequired) {
                        $script:progressBar.Invoke([Action]{ $script:progressBar.Value = 100 })
                    } else {
                        $script:progressBar.Value = 100
                    }
                }
            }
            catch {
                Write-RepairLog -Message "Final progress update failed: $($_.Exception.Message)" -Category "WARNING"
            }
        }
        
        # Process job completion
        Complete-RepairJob -Job $jobToProcess -JobResult $jobResult
        
        # Cleanup job
        try {
            if ($jobToProcess.State -eq 'Running') {
                $jobToProcess | Stop-Job -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 200
            }
            
            # Remove from collection first
            $script:jobCollection.TryRemove($jobToProcess.Id.ToString(), [ref]$null) | Out-Null
            
            # Final cleanup
            Remove-Job $jobToProcess -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-RepairLog -Message "Job cleanup warning: $($_.Exception.Message)" -Category "WARNING"
        }
        
        # Reset state
        Reset-JobState
        
        Write-RepairLog -Message "Job completion finished" -Category "JOB"
    }
    catch {
        Write-RepairLog -Message "Error in Complete-JobExecution: $($_.Exception.Message)" -Category "ERROR"
        try {
            if ($null -ne $script:form -and -not $script:form.IsDisposed) {
                Update-UiForJobEnd -StatusMessage "ERROR: Job completion failed." -IsSuccess $false
            }
        }
        catch {
            # Final fallback
        }
    }
}

function Invoke-NewJobOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Output
    )
    
    $hasProgress = $false
    
    try {
        # Look for result object first
        if ($null -eq $script:capturedJobResult) {
            $resultObject = $Output | Where-Object { 
                $_ -is [PSCustomObject] -and 
                ($null -ne $_.PSObject.Properties['JobType'] -or $null -ne $_.PSObject.Properties['ExitCode'])
            } | Select-Object -First 1
            
            if ($null -ne $resultObject) {
                $script:capturedJobResult = $resultObject
            }
        }
        
        # Better output processing with detailed logging
        foreach ($item in $Output) {
            if ($null -eq $item) { continue }
            
            # Skip result objects
            if ($item -is [PSCustomObject] -and 
                ($null -ne $item.PSObject.Properties['JobType'] -or $null -ne $item.PSObject.Properties['ExitCode'])) {
                continue
            }
            
            $itemStr = $item.ToString().Trim()
            if ([string]::IsNullOrWhiteSpace($itemStr)) { continue }
            
            # More detailed progress line processing
            if ($itemStr.StartsWith("PROGRESS_LINE:", [System.StringComparison]::OrdinalIgnoreCase)) {
                Write-RepairLog -Message "Processing progress line: $itemStr" -Category "DEBUG"
                Update-ProgressLine -Line $itemStr
                $hasProgress = $true
            }
            elseif ($itemStr.StartsWith("WINDOWS_OLD_EXISTS:", [System.StringComparison]::OrdinalIgnoreCase)) {
                # Better UI thread scheduling
                if ($null -ne $script:form -and -not $script:form.IsDisposed) {
                    try {
                        $script:form.BeginInvoke([Action]{
                            Show-WindowsOldPrompt
                        })
                    }
                    catch {
                        Write-RepairLog -Message "Error scheduling Windows.old prompt: $($_.Exception.Message)" -Category "ERROR"
                    }
                }
            }
            elseif ($itemStr.StartsWith("EXPLORER_RESTART_REQUEST:", [System.StringComparison]::OrdinalIgnoreCase)) {
                # Better UI thread scheduling
                if ($null -ne $script:form -and -not $script:form.IsDisposed) {
                    try {
                        $script:form.BeginInvoke([Action]{
                            Show-ExplorerRestartPrompt
                        })
                    }
                    catch {
                        Write-RepairLog -Message "Error scheduling Explorer restart prompt: $($_.Exception.Message)" -Category "ERROR"
                    }
                }
            }
        }
        
        return $hasProgress
    }
    catch {
        Write-RepairLog -Message "Error in Invoke-NewJobOutput: $($_.Exception.Message)" -Category "ERROR"
        return $false
    }
}

function Update-ProgressLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Line
    )
    
    try {
        # Extract progress content
        if (-not $Line.StartsWith("PROGRESS_LINE:", [System.StringComparison]::OrdinalIgnoreCase)) {
            return
        }
        
        $progressContent = $Line.Substring("PROGRESS_LINE:".Length).Trim()
        if ([string]::IsNullOrWhiteSpace($progressContent)) {
            return
        }
        
        # Update last progress time and disable fallback
        $script:lastProgressUpdate = Get-Date
        $script:fallbackProgressEnabled = $false
        
        # FIXED: Improved percentage extraction with better regex
        $percentMatch = $null
        $percentPattern = '^(\d{1,3})(?:\.(\d+))?%'
        $regexResult = [regex]::Match($progressContent, $percentPattern)
        
        if ($regexResult.Success) {
            $wholeNumber = [int]$regexResult.Groups[1].Value
            $decimalPart = if ($regexResult.Groups[2].Success) { 
                [int]$regexResult.Groups[2].Value 
            } else { 
                0 
            }
            
            # Handle decimal properly - if decimal >= 5, round up
            $percentMatch = if ($decimalPart -ge 5 -and $wholeNumber -lt 100) { 
                $wholeNumber + 1 
            } else { 
                $wholeNumber 
            }
        }
        else {
            # Try simpler pattern
            $simplePattern = '(\d{1,3})%'
            $simpleResult = [regex]::Match($progressContent, $simplePattern)
            if ($simpleResult.Success) {
                $percentMatch = [int]$simpleResult.Groups[1].Value
            }
        }
        
        if ($null -ne $percentMatch) {
            $percent = [int]$percentMatch
            if ($percent -ge 0 -and $percent -le 100) {
                # Synchronous UI update with proper thread safety
                Update-ProgressBarSafe -Percent $percent
            }
        }
        
        # Log significant progress with throttling
        if ($null -ne $percentMatch) {
            $percent = [int]$percentMatch
            if ($percent -in @(0, 25, 50, 75, 100) -and $percent -ne $script:lastLoggedPercent) {
                $operation = Get-JobOperation
                Write-RepairLog -Message $progressContent -Category "PROGRESS" -Operation $operation
                $script:lastLoggedPercent = $percent
                $script:lastProgressLogTime = Get-Date
            }
        }
    }
    catch {
        Write-RepairLog -Message "Error updating progress line: $($_.Exception.Message)" -Category "ERROR"
    }
}

function Update-ProgressBarSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 100)]
        [int]$Percent
    )
    
    try {
        if ($null -eq $script:progressBar -or $script:progressBar.IsDisposed) {
            return
        }
        
        # Use proper UI thread marshaling
        if ($script:progressBar.InvokeRequired) {
            # Use Invoke (synchronous) instead of BeginInvoke for critical UI updates
            try {
                $script:progressBar.Invoke([Action]{
                    param()
                    try {
                        if (-not $script:progressBar.IsDisposed) {
                            $currentValue = $script:progressBar.Value
                            
                            # Better progress logic
                            # Allow forward progress, 100% completion, or small corrections
                            if ($Percent -eq 100 -or 
                                $Percent -gt $currentValue -or 
                                ($Percent -ge ($currentValue - 3) -and $Percent -ge 0)) {
                                
                                $script:progressBar.Value = $Percent
                                
                                # Force immediate visual update
                                try {
                                    $script:progressBar.Refresh()
                                }
                                catch {
                                    # Silently continue if refresh fails
                                }
                                
                                Write-RepairLog -Message "Progress bar updated to $Percent%" -Category "DEBUG"
                            }
                        }
                    }
                    catch {
                        Write-RepairLog -Message "Error in progress bar update delegate: $($_.Exception.Message)" -Category "ERROR"
                    }
                })
            }
            catch {
                Write-RepairLog -Message "Failed to invoke progress bar update: $($_.Exception.Message)" -Category "ERROR"
                
                # Fallback - try direct update if we're close to UI thread
                try {
                    if (-not $script:progressBar.IsDisposed) {
                        $script:progressBar.Value = $Percent
                    }
                }
                catch {
                    Write-RepairLog -Message "Direct progress bar update also failed: $($_.Exception.Message)" -Category "ERROR"
                }
            }
        }
        else {
            # We're already on the UI thread
            try {
                $currentValue = $script:progressBar.Value
                
                if ($Percent -eq 100 -or 
                    $Percent -gt $currentValue -or 
                    ($Percent -ge ($currentValue - 3) -and $Percent -ge 0)) {
                    
                    $script:progressBar.Value = $Percent
                    $script:progressBar.Refresh()
                    Write-RepairLog -Message "Progress bar updated to $Percent% (direct)" -Category "DEBUG"
                }
            }
            catch {
                Write-RepairLog -Message "Direct progress bar update failed: $($_.Exception.Message)" -Category "ERROR"
            }
        }
    }
    catch {
        Write-RepairLog -Message "Error in Update-ProgressBarSafe: $($_.Exception.Message)" -Category "ERROR"
    }
}

function Show-WindowsOldPrompt {
    try {
        Write-RepairLog -Message "=== WINDOWS.OLD PROMPT STARTING ===" -Category "USER"
        
        if ($null -eq $script:form -or $script:form.IsDisposed) {
            Write-RepairLog -Message "ERROR: Form is disposed" -Category "ERROR"
            return
        }
        
        # Stop timer during modal dialog
        $timerWasRunning = $false
        if ($null -ne $script:progressUpdateTimer -and $script:progressUpdateTimer.Enabled) {
            $timerWasRunning = $true
            Stop-ProgressTimer
            Write-RepairLog -Message "Progress timer stopped for Windows.old dialog" -Category "USER"
        }
        
        try {
            # Create message
            $message = "The Windows.old folder contains your previous Windows installation.`n`n" +
                       "Removing it will free up disk space but will prevent you from rolling back to your previous Windows version.`n`n" +
                       "Do you want to remove the Windows.old folder?`n`n" +
                       "⚠️ This action cannot be undone!"
            
            Write-RepairLog -Message "Displaying Windows.old removal dialog" -Category "USER"
            
            # Show dialog with proper error handling
            $dialogResult = [System.Windows.Forms.DialogResult]::No
            try {
                $dialogResult = [System.Windows.Forms.MessageBox]::Show(
                    $script:form,
                    $message, 
                    "Windows.old Folder Detected", 
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question,
                    [System.Windows.Forms.MessageBoxDefaultButton]::Button2
                )
            }
            catch {
                Write-RepairLog -Message "Error showing Windows.old dialog: $($_.Exception.Message)" -Category "ERROR"
                # Fallback to parentless dialog
                $dialogResult = [System.Windows.Forms.MessageBox]::Show(
                    $message, 
                    "Windows.old Folder Detected", 
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question
                )
            }
            
            # Process decision
            $decision = if ($dialogResult -eq [System.Windows.Forms.DialogResult]::Yes) { "YES" } else { "NO" }
            Write-RepairLog -Message "User selected: $decision for Windows.old removal" -Category "USER"
            
            # Communicate decision to job with improved retry logic
            $communicationSuccess = $false
            for ($attempt = 1; $attempt -le 3; $attempt++) {
                try {
                    Set-JobCommunication -JobId $script:currentJobId -Key "WINDOWSOLD_DECISION" -Value $decision
                    
                    # Brief verification delay
                    Start-Sleep -Milliseconds 150
                    
                    # Verify communication file exists
                    $userTempPath = [System.IO.Path]::GetTempPath()
                    $expectedFile = [System.IO.Path]::Combine($userTempPath, "$($script:CONSTANTS.COMMUNICATION_PREFIX)_$($script:currentJobId)_WINDOWSOLD_DECISION.tmp")
                    
                    if (Test-Path $expectedFile) {
                        $communicationSuccess = $true
                        break
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
                Write-RepairLog -Message "WARNING: All communication attempts failed" -Category "ERROR"
            }
            
            Write-RepairLog -Message "=== WINDOWS.OLD PROMPT COMPLETED ===" -Category "USER"
        }
        finally {
            # Restart timer if it was running
            if ($timerWasRunning) {
                try {
                    Start-ProgressTimer
                    Write-RepairLog -Message "Progress timer resumed" -Category "USER"
                }
                catch {
                    Write-RepairLog -Message "Error resuming timer: $($_.Exception.Message)" -Category "WARNING"
                }
            }
        }
    }
    catch {
        Write-RepairLog -Message "Critical error in Windows.old prompt: $($_.Exception.Message)" -Category "ERROR"
        # Ensure timer is restarted even on error
        try {
            if ($null -eq $script:progressUpdateTimer -or -not $script:progressUpdateTimer.Enabled) {
                Start-ProgressTimer
            }
        }
        catch {
            # Final fallback
        }
    }
}

function Show-ExplorerRestartPrompt {
    try {
        Write-RepairLog -Message "=== EXPLORER RESTART PROMPT STARTING ===" -Category "USER"
        
        if ($null -eq $script:form -or $script:form.IsDisposed) {
            Write-RepairLog -Message "ERROR: Form is disposed" -Category "ERROR"
            return
        }
        
        # Stop timer during modal dialog
        $timerWasRunning = $false
        if ($null -ne $script:progressUpdateTimer -and $script:progressUpdateTimer.Enabled) {
            $timerWasRunning = $true
            Stop-ProgressTimer
            Write-RepairLog -Message "Progress timer stopped for Explorer dialog" -Category "USER"
        }
        
        try {
            # Create message
            $message = "To complete the icon cache refresh, Windows Explorer needs to be restarted.`n`n" +
                       "This will temporarily close all File Explorer windows and make the desktop/taskbar disappear for a few seconds.`n`n" +
                       "Do you want to proceed?"
            
            Write-RepairLog -Message "Displaying Explorer restart dialog" -Category "USER"
            
            # Show dialog with proper error handling
            $dialogResult = [System.Windows.Forms.DialogResult]::No
            try {
                $dialogResult = [System.Windows.Forms.MessageBox]::Show(
                    $script:form,
                    $message, 
                    "Explorer Restart Required", 
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question,
                    [System.Windows.Forms.MessageBoxDefaultButton]::Button2
                )
            }
            catch {
                Write-RepairLog -Message "Error showing Explorer dialog: $($_.Exception.Message)" -Category "ERROR"
                # Fallback to parentless dialog
                $dialogResult = [System.Windows.Forms.MessageBox]::Show(
                    $message, 
                    "Explorer Restart Required", 
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question
                )
            }
            
            # Process decision
            $decision = if ($dialogResult -eq [System.Windows.Forms.DialogResult]::Yes) { "YES" } else { "NO" }
            Write-RepairLog -Message "User selected: $decision for Explorer restart" -Category "USER"
            
            # Communicate decision to job with improved retry logic
            $communicationSuccess = $false
            for ($attempt = 1; $attempt -le 3; $attempt++) {
                try {
                    Set-JobCommunication -JobId $script:currentJobId -Key "EXPLORER_RESTART" -Value $decision
                    
                    # Brief verification delay
                    Start-Sleep -Milliseconds 150
                    
                    # Verify communication file exists
                    $userTempPath = [System.IO.Path]::GetTempPath()
                    $expectedFile = [System.IO.Path]::Combine($userTempPath, "$($script:CONSTANTS.COMMUNICATION_PREFIX)_$($script:currentJobId)_EXPLORER_RESTART.tmp")
                    
                    if (Test-Path $expectedFile) {
                        $communicationSuccess = $true
                        Write-RepairLog -Message "Explorer restart communication verified" -Category "USER"
                        break
                    }
                }
                catch {
                    Write-RepairLog -Message "Explorer communication attempt $attempt failed: $($_.Exception.Message)" -Category "ERROR"
                }
                
                if ($attempt -lt 3) {
                    Start-Sleep -Milliseconds 200
                }
            }
            
            if (-not $communicationSuccess) {
                Write-RepairLog -Message "WARNING: Explorer restart communication failed" -Category "ERROR"
            }
            
            Write-RepairLog -Message "=== EXPLORER RESTART PROMPT COMPLETED ===" -Category "USER"
        }
        finally {
            # Resume timer if it was running
            if ($timerWasRunning) {
                try {
                    Start-ProgressTimer
                    Write-RepairLog -Message "Progress timer resumed" -Category "USER"
                }
                catch {
                    Write-RepairLog -Message "Error resuming timer: $($_.Exception.Message)" -Category "WARNING"
                }
            }
        }
    }
    catch {
        Write-RepairLog -Message "Critical error in Explorer restart prompt: $($_.Exception.Message)" -Category "ERROR"
        # Ensure timer is restarted even on error
        try {
            if ($null -eq $script:progressUpdateTimer -or -not $script:progressUpdateTimer.Enabled) {
                Start-ProgressTimer
            }
        }
        catch {
            # Final fallback
        }
    }
}

function Get-JobDisplayName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$JobName
    )
    
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
    elseif ($lowerJobName -match "(diskcleanup|cleanup|clean|optimize)") {
        return "System Optimization"
    }
    else {
        return "Operation"
    }
}

function Update-StatusDisplay {
    try {
        # Validate state
        if ($null -eq $script:currentRepairJob -or 
            $null -eq $script:form -or $script:form.IsDisposed -or $script:form.Disposing -or 
            $null -eq $script:statusLabel -or $script:statusLabel.IsDisposed -or 
            $null -eq $script:progressBar -or $script:progressBar.IsDisposed) {
            return
        }
        
        # Throttle UI updates
        $currentTime = Get-Date
        if ($script:lastUiUpdate -eq [DateTime]::MinValue -or 
            ($currentTime - $script:lastUiUpdate).TotalMilliseconds -ge $script:CONSTANTS.UI_UPDATE_THROTTLE_MS) {
            
            $jobDisplayName = Get-JobDisplayName -JobName $script:currentRepairJob.Name
            $currentProgress = $script:progressBar.Value
            $newStatusText = "$jobDisplayName in progress... $currentProgress%"
            
            # Thread-safe status update using Invoke instead of BeginInvoke for immediate update
            if ($script:statusLabel.Text -ne $newStatusText) {
                try {
                    if ($script:statusLabel.InvokeRequired) {
                        $script:statusLabel.Invoke([Action]{
                            if (-not $script:statusLabel.IsDisposed) {
                                $script:statusLabel.Text = $newStatusText
                            }
                        })
                    }
                    else {
                        $script:statusLabel.Text = $newStatusText
                    }
                }
                catch {
                    # Silently continue if UI update fails
                }
            }
            
            $script:lastUiUpdate = $currentTime
        }
    }
    catch [System.ObjectDisposedException] {
        # Silently continue
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
    elseif ($jobNameLower -match "(diskcleanup|cleanup|clean|optimize)") {
        return "CLEANUP"
    }
    else {
        return "TOOLKIT"
    }
}

function Reset-JobState {
    $script:currentJobId = [String]::Empty
    $script:capturedJobResult = $null
    $script:lastLoggedProgress = [String]::Empty
    $script:lastLoggedPercent = -1
    $script:lastProgressLogTime = [DateTime]::MinValue
    $script:operationStartTime = [DateTime]::MinValue
    $script:lastUiUpdate = [DateTime]::MinValue
    $script:fallbackProgressEnabled = $false
    $script:progressCommunicationFailures = 0
    $script:lastProgressUpdate = [DateTime]::MinValue
    $script:lastFallbackLogTime = [DateTime]::MinValue
    # Reset the new output tracking variables
    $script:lastOutputCount = 0
    $script:lastProcessedOutputCount = 0
}
#endregion

#region 11. Job Result Processing and Completion Handlers
function Get-JobResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Management.Automation.Job]$Job
    )
    
    try {
        Write-RepairLog -Message "Retrieving results for job: $($Job.Name)" -Category "JOB"
        
        # Give job time to finish writing output
        Start-Sleep -Milliseconds 200
        
        # Receive all job output with error handling
        $allOutput = @()
        try {
            # Final receive of all output
            $allOutput = @(Receive-Job -Job $Job -ErrorAction Stop)
        }
        catch {
            Write-RepairLog -Message "Error receiving final job output: $($_.Exception.Message)" -Category "ERROR"
            
            # Try to get whatever output we can
            try {
                $allOutput = @(Receive-Job -Job $Job -Keep -ErrorAction SilentlyContinue)
            }
            catch {
                Write-RepairLog -Message "Could not retrieve any job output" -Category "ERROR"
                $allOutput = @()
            }
        }
        
        # Check for empty output
        if ($null -eq $allOutput -or $allOutput.Count -eq 0) {
            Write-RepairLog -Message "Job produced no output" -Category "WARNING"
            return [PSCustomObject]@{ 
                ExitCode      = if ($Job.State -eq [System.Management.Automation.JobState]::Completed) { 0 } else { 1 }
                StandardError = "Job completed but produced no output"
                JobType       = "EMPTY"
                OutputLines   = 0
            }
        }
        
        Write-RepairLog -Message "Job produced $($allOutput.Count) output items" -Category "JOB"
        
        # Try to find result objects with different markers
        $finalResult = Get-ResultBetweenMarkers -Output $allOutput -StartMarker "FINAL_RESULT_START" -EndMarker "FINAL_RESULT_END"
        if ($null -ne $finalResult) {
            Write-RepairLog -Message "Found cleanup job result" -Category "JOB"
            return $finalResult
        }
        
        $commandResult = Get-ResultBetweenMarkers -Output $allOutput -StartMarker "COMMAND_RESULT_START" -EndMarker "COMMAND_RESULT_END"
        if ($null -ne $commandResult) {
            Write-RepairLog -Message "Found command job result" -Category "JOB"
            return $commandResult
        }
        
        # Look for any PSCustomObject with ExitCode property
        foreach ($item in $allOutput) {
            if ($null -ne $item -and $item -is [PSCustomObject] -and 
                $null -ne $item.PSObject.Properties['ExitCode']) {
                return $item
            }
        }
        
        # Create fallback result based on job state
        $exitCode = switch ($Job.State) {
            'Completed' { 0 }
            'Failed' { 1 }
            'Stopped' { -1 }
            default { 1 }
        }
        
        Write-RepairLog -Message "No result object found, creating fallback (Job State: $($Job.State))" -Category "WARNING"
        return [PSCustomObject]@{ 
            ExitCode      = $exitCode
            StandardError = "Job completed but no structured result was found"
            JobType       = "FALLBACK"
            OutputLines   = $allOutput.Count
            JobState      = $Job.State.ToString()
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
        [ValidateNotNull()]
        [array]$Output,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StartMarker,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$EndMarker
    )
    
    try {
        $startIndex = -1
        $endIndex = -1
        
        # Find markers
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
        
        # Extract result if found
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

function Complete-DismJob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [PSCustomObject]$JobResult
    )
    
    try {
        $duration = if ($script:operationStartTime -ne [DateTime]::MinValue) { 
            (Get-Date) - $script:operationStartTime 
        }
        else { 
            New-TimeSpan 
        }
        
        $success = ($null -ne $JobResult -and $JobResult.ExitCode -eq 0)
        
        # Log completion
        Write-OperationEnd -OperationType "DISM" -Duration $duration -Success $success -ExitCode $JobResult.ExitCode
        
        if ($success) {
            Update-UiForJobEnd -StatusMessage "SUCCESS: STEP 1 completed successfully." -IsSuccess $true
            $message = "DISM successfully repaired the Windows system image.`n`n" +
                       "Next recommended step: Run SFC System File Check (Step 2)."
            Show-InfoMessage -Title "DISM Repair Complete" -Message $message
        }
        else {
            Update-UiForJobEnd -StatusMessage "ATTENTION: DISM completed with issues." -IsSuccess $false
            $logPath = "C:\Windows\Logs\DISM\dism.log"
            $message = "DISM finished with exit code: $($JobResult.ExitCode).`n`n" +
                       "For detailed information, please review:`n$logPath"
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
        [ValidateNotNull()]
        [PSCustomObject]$JobResult
    )
    
    try {
        $duration = if ($script:operationStartTime -ne [DateTime]::MinValue) { 
            (Get-Date) - $script:operationStartTime 
        }
        else { 
            New-TimeSpan 
        }
        
        $success = ($null -ne $JobResult -and $JobResult.ExitCode -eq 0)
        
        # Prepare additional info
        $additionalInfo = ""
        if ($JobResult.OutputLines -gt 0) {
            $additionalInfo = "$($JobResult.OutputLines) output lines processed."
        }
        
        # Log completion
        Write-OperationEnd -OperationType "SFC" -Duration $duration -Success $success -ExitCode $JobResult.ExitCode -AdditionalInfo $additionalInfo
        
        if ($success) {
            Update-UiForJobEnd -StatusMessage "SUCCESS: STEP 2 completed successfully." -IsSuccess $true
            $message = "SFC completed successfully and verified system file integrity.`n`n" +
                       "Next recommended step: Run System Cleanup (Step 3)."
            Show-InfoMessage -Title "SFC Scan Complete" -Message $message
        }
        else {
            Update-UiForJobEnd -StatusMessage "ATTENTION: SFC scan completed - please review results." -IsSuccess $false
            $logPath = "C:\Windows\Logs\CBS\CBS.log"
            $message = "SFC finished with exit code $($JobResult.ExitCode).`n`n" +
                       "For detailed results, search for '[SR]' entries in:`n$logPath"
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
        [ValidateNotNull()]
        [PSCustomObject]$JobResult
    )
    
    try {
        $duration = if ($script:operationStartTime -ne [DateTime]::MinValue) { 
            (Get-Date) - $script:operationStartTime 
        }
        else { 
            New-TimeSpan 
        }
        
        $success = ($null -ne $JobResult -and $JobResult.ExitCode -eq 0)
        
        # Build additional info
        $additionalInfo = @()
        if ($JobResult.WindowsOldExists) { 
            if ($JobResult.WindowsOldRemoved) {
                if ($JobResult.WindowsOldActuallyRemoved) {
                    $additionalInfo += "Windows.old folder was successfully removed."
                }
                else {
                    $additionalInfo += "Windows.old removal was attempted but may not have completed."
                }
            }
            else {
                $additionalInfo += "Windows.old folder was preserved."
            }
        }
        
        if ($JobResult.TotalSpaceFreedMB -gt 0) {
            $additionalInfo += "$($JobResult.TotalSpaceFreedMB) MB freed."
        }
        
        $additionalInfoText = $additionalInfo -join " "
        
        # Log completion
        Write-OperationEnd -OperationType "CLEANUP" -Duration $duration -Success $success -ExitCode $JobResult.ExitCode -AdditionalInfo $additionalInfoText
        
        if ($success) {
            Update-UiForJobEnd -StatusMessage "SUCCESS: STEP 3 completed successfully." -IsSuccess $true
            
            # Build success message
            $message = "Disk cleanup and optimization finished successfully!`n`n"
            $message += "Completed operations:`n"
            $message += "• Temporary file removal`n"
            $message += "• Registry cleanup configuration`n"
            $message += "• Cache optimization`n"
            $message += "• Network optimization"
            
            if ($JobResult.WindowsOldActuallyRemoved) {
                $message += "`n• Windows.old folder removal"
            }
            
            if ($JobResult.TotalSpaceFreedMB -gt 0) {
                $message += "`n`nTotal space freed: $($JobResult.TotalSpaceFreedMB) MB"
            }
            
            Show-InfoMessage -Title "Cleanup Complete" -Message $message
        }
        else {
            Update-UiForJobEnd -StatusMessage "ERROR: Cleanup encountered issues." -IsSuccess $false
            $message = "The cleanup process encountered issues.`n`n" +
                       "Error: $($JobResult.StandardError)`n`n" +
                       "Check 'SystemRepairLog.txt' on your Desktop for details."
            Show-ErrorMessage -Title "Cleanup Issues" -Message $message
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
        [ValidateNotNull()]
        [System.Management.Automation.Job]$Job,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [PSCustomObject]$JobResult
    )
    
    try {
        $displayName = Get-JobDisplayName -JobName $Job.Name
        Write-RepairLog -Message "Processing completion for $displayName" -Category "JOB"
        
        # Route to appropriate completion handler
        $jobNameLower = $Job.Name.ToLower()
        
        if ($jobNameLower -like "*dism*") {
            Complete-DismJob -JobResult $JobResult
        }
        elseif ($jobNameLower -like "*sfc*") {
            Complete-SfcJob -JobResult $JobResult
        }
        elseif ($jobNameLower -match "(diskcleanup|cleanup|clean|optimize)") {
            Complete-DiskCleanupJob -JobResult $JobResult
        }
        else {
            Write-RepairLog -Message "Unknown job type completed: '$displayName'" -Category "WARNING"
            Update-UiForJobEnd -StatusMessage "Operation completed." -IsSuccess $false
        }
        
        # Clear job ID for cleanup jobs
        if ($jobNameLower -match "(diskcleanup|cleanup)") {
            $script:currentJobId = [String]::Empty
        }
    }
    catch {
        Write-RepairLog -Message "Critical error in job completion handler: $($_.Exception.Message)" -Category "ERROR"
        Show-ErrorMessage -Title "Completion Error" -Message "An error occurred while finalizing the operation."
        Update-UiForJobEnd -StatusMessage "ERROR: Completion processing failed." -IsSuccess $false
    }
}
#endregion

#region 12. Windows 11 GUI Design - User Interface Creation Functions
function Initialize-MainForm {
    [CmdletBinding()]
    param()
    
    try {
        Write-RepairLog -Message "Initializing main form with Windows 11 Fluent Design" -Category "SYSTEM"
        
        $colors = $script:FLUENT_DESIGN.Colors
        
        # Create main form with Windows 11 styling
        $script:form = New-Object System.Windows.Forms.Form
        $script:form.Text = "System Repair Toolkit"
        $script:form.Size = New-Object System.Drawing.Size(450, 400)
        $script:form.StartPosition = "CenterScreen"
        $script:form.FormBorderStyle = "FixedSingle"
        $script:form.MaximizeBox = $false
        $script:form.MinimizeBox = $true
        $script:form.BackColor = $colors.BACKGROUND  # Windows 11 background color
        $script:form.Icon = [System.Drawing.SystemIcons]::Shield
        $script:form.ShowInTaskbar = $true
        
        # Initialize fonts with Windows 11 typography
        Initialize-Fonts
        
        # Create all controls with Fluent Design
        Initialize-Controls
        
        # Set tab order
        Set-TabOrder
        
        # Configure keyboard shortcuts
        Set-KeyboardShortcuts
        
        Write-RepairLog -Message "Windows 11 Fluent Design form initialized successfully" -Category "SYSTEM"
        return $true
    }
    catch {
        Write-RepairLog -Message "Failed to initialize Windows 11 form: $($_.Exception.Message)" -Category "ERROR"
        return $false
    }
}

function Initialize-Fonts {
    [CmdletBinding()]
    param()
    
    try {
        # Use standard Windows 11 fonts with proper fallback chain
        try {
            # Primary Windows 11 font - clean, no shadow effects
            $script:titleFont = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Regular)
            $script:secondaryFont = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
        }
        catch {
            # Fallback to system default if Segoe UI unavailable
            $script:titleFont = New-Object System.Drawing.Font([System.Drawing.SystemFonts]::DefaultFont.FontFamily, 18, [System.Drawing.FontStyle]::Regular)
            $script:secondaryFont = New-Object System.Drawing.Font([System.Drawing.SystemFonts]::DefaultFont.FontFamily, 9, [System.Drawing.FontStyle]::Regular)
        }
        
        Write-RepairLog -Message "Fonts initialized: $($script:titleFont.Name)" -Category "SYSTEM"
    }
    catch {
        Write-RepairLog -Message "Error initializing fonts: $($_.Exception.Message)" -Category "WARNING"
    }
}

function Initialize-Controls {
    [CmdletBinding()]
    param()
    
    # Calculate layout using 8px grid system - Optimized spacing
    $spacing = $script:FLUENT_DESIGN.Spacing
    $colors = $script:FLUENT_DESIGN.Colors
    $buttonDims = $script:FLUENT_DESIGN.ButtonDimensions
    
    $buttonLeftMargin = ($script:form.ClientSize.Width - $buttonDims.MAIN_WIDTH) / 2
    $currentY = $spacing.MEDIUM  # Reduced from LARGE (24px) to MEDIUM (16px)
    
    # Create title label with clean Windows 11 typography (NO SHADOW)
    $script:titleLabel = New-Object System.Windows.Forms.Label
    $script:titleLabel.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
    $script:titleLabel.Size = New-Object System.Drawing.Size($buttonDims.MAIN_WIDTH, 32)  # Reduced from 36 to 32
    $script:titleLabel.Text = "System Repair Toolkit"
    $script:titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Regular)
    $script:titleLabel.ForeColor = $colors.TEXT_PRIMARY
    $script:titleLabel.TextAlign = "MiddleCenter"
    $script:titleLabel.BackColor = [System.Drawing.Color]::Transparent
    # Ensure no text effects/shadows
    $script:titleLabel.FlatStyle = 'Standard'
    $script:titleLabel.UseCompatibleTextRendering = $false
    $currentY += $script:titleLabel.Height + $spacing.TINY  # Reduced gap from SMALL (8px) to TINY (4px)
    
    # Create instruction label with COMPLETE text and perfect alignment
    $script:instructionLabel = New-Object System.Windows.Forms.Label
    # Keep same width as buttons but ensure text fits
    $script:instructionLabel.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
    $script:instructionLabel.Size = New-Object System.Drawing.Size($buttonDims.MAIN_WIDTH, 20)  # Reduced from 24 to 20
    # Shorter text that fits within button width
    $script:instructionLabel.Text = "Sequence: DISM → SFC → Optimize"
    $script:instructionLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Regular)
    $script:instructionLabel.ForeColor = $colors.TEXT_SECONDARY
    $script:instructionLabel.TextAlign = "MiddleCenter"
    $script:instructionLabel.BackColor = [System.Drawing.Color]::Transparent
    $script:instructionLabel.UseCompatibleTextRendering = $false
    $currentY += $script:instructionLabel.Height + $spacing.MEDIUM  # Reduced gap from LARGE (24px) to MEDIUM (16px)
    
    # Create DISM button with proper Windows 11 Fluent Design
    $script:dismButton = New-Object System.Windows.Forms.Button
    $script:dismButton.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
    Set-FluentButtonStyle -Button $script:dismButton -Text "STEP 1: Repair System Image (DISM)" -IsPrimary $true
    $script:dismButton.Add_Click({
        try {
            Write-RepairLog -Message "DISM button clicked" -Category "USER"
            $(Start-DISMRepair)
        }
        catch {
            Write-RepairLog -Message "Error in DISM button click: $($_.Exception.Message)" -Category "ERROR"
            Show-ErrorMessage -Message "Failed to start DISM repair: $($_.Exception.Message)"
        }
    })
    $currentY += $script:dismButton.Height + $spacing.SMALL  # Reduced gap from MEDIUM (16px) to SMALL (8px)
    
    # Create SFC button with proper Windows 11 Fluent Design
    $script:sfcButton = New-Object System.Windows.Forms.Button
    $script:sfcButton.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
    # Proper ampersand escaping
    Set-FluentButtonStyle -Button $script:sfcButton -Text "STEP 2: Scan && Fix System Files (SFC)"
    $script:sfcButton.Add_Click({
        try {
            Write-RepairLog -Message "SFC button clicked" -Category "USER"
            $(Start-SFCRepair)
        }
        catch {
            Write-RepairLog -Message "Error in SFC button click: $($_.Exception.Message)" -Category "ERROR"
            Show-ErrorMessage -Message "Failed to start SFC scan: $($_.Exception.Message)"
        }
    })
    $currentY += $script:sfcButton.Height + $spacing.SMALL  # Reduced gap from MEDIUM (16px) to SMALL (8px)
    
    # Create Cleanup button with proper Windows 11 Fluent Design
    $script:cleanupButton = New-Object System.Windows.Forms.Button
    $script:cleanupButton.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
    # Proper ampersand escaping
    Set-FluentButtonStyle -Button $script:cleanupButton -Text "STEP 3: Disk Cleanup && Performance"
    $script:cleanupButton.Add_Click({
        try {
            Write-RepairLog -Message "Cleanup button clicked" -Category "USER"
            $(Start-DiskCleanup)
        }
        catch {
            Write-RepairLog -Message "Error in Cleanup button click: $($_.Exception.Message)" -Category "ERROR"
            Show-ErrorMessage -Message "Failed to start cleanup: $($_.Exception.Message)"
        }
    })
    $currentY += $script:cleanupButton.Height + $spacing.SMALL  # Reduced gap from MEDIUM (16px) to SMALL (8px)
    
    # Create modern Windows 11 style progress bar
    $script:progressBar = New-Object System.Windows.Forms.ProgressBar
    $script:progressBar.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
    $script:progressBar.Size = New-Object System.Drawing.Size($buttonDims.MAIN_WIDTH, 4)
    $script:progressBar.Style = 'Continuous'
    $script:progressBar.Minimum = 0
    $script:progressBar.Maximum = 100
    $script:progressBar.Value = 0
    # Windows 11 progress bar colors
    $script:progressBar.ForeColor = $colors.PRIMARY_BLUE
    $script:progressBar.BackColor = [System.Drawing.Color]::FromArgb(230, 230, 230)
    $script:progressBar.Visible = $false
    $currentY += $script:progressBar.Height + $spacing.SMALL  # Reduced gap from MEDIUM (16px) to SMALL (8px)
    
    # Create status label with proper Windows 11 typography and alignment
    $script:statusLabel = New-Object System.Windows.Forms.Label
    $script:statusLabel.Location = New-Object System.Drawing.Point($buttonLeftMargin, $currentY)
    $script:statusLabel.Size = New-Object System.Drawing.Size($buttonDims.MAIN_WIDTH, 32)  # Reduced from 40 to 32
    $script:statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Regular)
    $script:statusLabel.TextAlign = "MiddleCenter"
    $script:statusLabel.ForeColor = $colors.TEXT_SECONDARY
    $script:statusLabel.BackColor = [System.Drawing.Color]::Transparent
    $script:statusLabel.UseCompatibleTextRendering = $false
    $script:statusLabel.AutoEllipsis = $true
    $currentY += $script:statusLabel.Height + $spacing.TINY  # Reduced gap from MEDIUM (16px) to TINY (4px)
    
    # Create bottom panel with Windows 11 spacing - Proper positioning
    New-FluentBottomPanel -CurrentY $currentY
    
    # Create enhanced tooltip with Windows 11 styling
    $script:toolTip = New-Object System.Windows.Forms.ToolTip
    $script:toolTip.InitialDelay = 500
    $script:toolTip.ReshowDelay = 100
    $script:toolTip.AutoPopDelay = 12000
    $script:toolTip.BackColor = $colors.CARD_BACKGROUND
    $script:toolTip.ForeColor = $colors.TEXT_PRIMARY
    $script:toolTip.SetToolTip($script:dismButton, "Repairs Windows component store and system image using DISM")
    $script:toolTip.SetToolTip($script:sfcButton, "Scans and repairs corrupted system files using SFC")
    $script:toolTip.SetToolTip($script:cleanupButton, "Performs comprehensive disk cleanup and system optimization")
    
    # Add all controls to form
    $script:form.Controls.AddRange(@(
        $script:titleLabel, 
        $script:instructionLabel, 
        $script:dismButton, 
        $script:sfcButton, 
        $script:cleanupButton,
        $script:progressBar, 
        $script:statusLabel, 
        $script:bottomPanel
    ))
}

function New-FluentBottomPanel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$CurrentY
    )
    
    # Use FLUENT_DESIGN spacing constants instead of hardcoded values
    $spacing = $script:FLUENT_DESIGN.Spacing
    $buttonDims = $script:FLUENT_DESIGN.ButtonDimensions
    
    # Completely revised button positioning calculation
    $formWidth = $script:form.ClientSize.Width
    $buttonWidth = $buttonDims.UTIL_WIDTH  # Standardized button width
    $buttonSpacing = $spacing.MEDIUM  # Use design system spacing (16px)
    $totalButtonsWidth = (3 * $buttonWidth) + (2 * $buttonSpacing)  # 3 buttons + 2 gaps
    $startX = ($formWidth - $totalButtonsWidth) / 2  # Center the button group
    
    # Create panel with exact positioning
    $script:bottomPanel = New-Object System.Windows.Forms.Panel
    $script:bottomPanel.Location = New-Object System.Drawing.Point(0, $CurrentY)
    $script:bottomPanel.Size = New-Object System.Drawing.Size($formWidth, 36)  # Reduced height from 40 to 36
    $script:bottomPanel.BackColor = [System.Drawing.Color]::Transparent
    
    # Create utility buttons with precise positioning
    $script:helpButton = New-Object System.Windows.Forms.Button
    $script:helpButton.Location = New-Object System.Drawing.Point($startX, $spacing.TINY)  # Use design system spacing (4px)
    Set-FluentUtilityButtonStyle -Button $script:helpButton -Text "Help"
    $script:helpButton.Add_Click({
        try {
            Write-RepairLog -Message "Help button clicked" -Category "USER"
            $(Show-HelpDialog)
        }
        catch {
            Write-RepairLog -Message "Error in Help button click: $($_.Exception.Message)" -Category "ERROR"
        }
    })
    
    $script:viewLogButton = New-Object System.Windows.Forms.Button
    $script:viewLogButton.Location = New-Object System.Drawing.Point(($startX + $buttonWidth + $buttonSpacing), $spacing.TINY)  # Use design system spacing
    Set-FluentUtilityButtonStyle -Button $script:viewLogButton -Text "View Log"
    $script:viewLogButton.Add_Click({
        try {
            Write-RepairLog -Message "View Log button clicked" -Category "USER"
            $(Open-LogFile)
        }
        catch {
            Write-RepairLog -Message "Error in View Log button click: $($_.Exception.Message)" -Category "ERROR"
        }
    })
    
    $script:closeButton = New-Object System.Windows.Forms.Button
    $script:closeButton.Location = New-Object System.Drawing.Point(($startX + (2 * $buttonWidth) + (2 * $buttonSpacing)), $spacing.TINY)  # Use design system spacing
    Set-FluentUtilityButtonStyle -Button $script:closeButton -Text "Close"
    $script:closeButton.Add_Click({ 
        try {
            Write-RepairLog -Message "Close button clicked" -Category "USER"
            $script:form.Close() 
        }
        catch {
            Write-RepairLog -Message "Error in Close button click: $($_.Exception.Message)" -Category "ERROR"
        }
    })
    
    # Add buttons directly to panel with exact positioning
    $script:bottomPanel.Controls.AddRange(@($script:helpButton, $script:viewLogButton, $script:closeButton))
}

function Set-FluentButtonStyle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Windows.Forms.Button]$Button,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Text,
        
        [Parameter()]
        [bool]$IsPrimary = $false
    )
    
    $colors = $script:FLUENT_DESIGN.Colors
    $buttonDims = $script:FLUENT_DESIGN.ButtonDimensions
    
    # Set consistent Windows 11 button properties
    $Button.Size = New-Object System.Drawing.Size($buttonDims.MAIN_WIDTH, $buttonDims.MAIN_HEIGHT)
    $Button.Text = $Text
    
    # Windows 11 typography - consistent font
    $Button.Font = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Regular)
    
    # Windows 11 button styling
    $Button.FlatStyle = 'Flat'
    $Button.Cursor = 'Hand'
    $Button.TextAlign = 'MiddleCenter'
    $Button.UseVisualStyleBackColor = $false
    $Button.UseCompatibleTextRendering = $false
    
    # Tag for style tracking
    $Button.Tag = if ($IsPrimary) { "FluentPrimary" } else { "FluentSecondary" }
    
    # Apply proper Windows 11 Fluent Design styling
    if ($IsPrimary) {
        # Primary button (accent color) - Windows 11 blue
        $Button.BackColor = $colors.PRIMARY_BLUE
        $Button.ForeColor = [System.Drawing.Color]::White
        $Button.FlatAppearance.BorderSize = 0
        
        # Windows 11 hover effects
        $Button.Add_MouseEnter({
            if ($this.Enabled) {
                $this.BackColor = $script:FLUENT_DESIGN.Colors.PRIMARY_HOVER
            }
        })
        $Button.Add_MouseLeave({
            if ($this.Enabled) {
                $this.BackColor = $script:FLUENT_DESIGN.Colors.PRIMARY_BLUE
            }
        })
        $Button.Add_MouseDown({
            if ($this.Enabled) {
                $this.BackColor = $script:FLUENT_DESIGN.Colors.PRIMARY_PRESSED
            }
        })
        $Button.Add_MouseUp({
            if ($this.Enabled) {
                $this.BackColor = $script:FLUENT_DESIGN.Colors.PRIMARY_HOVER
            }
        })
    }
    else {
        # Secondary button - Windows 11 subtle style
        $Button.BackColor = $colors.SECONDARY_BG
        $Button.ForeColor = $colors.TEXT_PRIMARY
        $Button.FlatAppearance.BorderSize = 1
        $Button.FlatAppearance.BorderColor = $colors.BORDER_MEDIUM
        
        # Windows 11 subtle hover effects
        $Button.Add_MouseEnter({
            if ($this.Enabled) {
                $this.BackColor = $script:FLUENT_DESIGN.Colors.SECONDARY_HOVER
                $this.FlatAppearance.BorderColor = $script:FLUENT_DESIGN.Colors.PRIMARY_BLUE
                $this.ForeColor = $script:FLUENT_DESIGN.Colors.PRIMARY_BLUE
            }
        })
        $Button.Add_MouseLeave({
            if ($this.Enabled) {
                $this.BackColor = $script:FLUENT_DESIGN.Colors.SECONDARY_BG
                $this.FlatAppearance.BorderColor = $script:FLUENT_DESIGN.Colors.BORDER_MEDIUM
                $this.ForeColor = $script:FLUENT_DESIGN.Colors.TEXT_PRIMARY
            }
        })
        $Button.Add_MouseDown({
            if ($this.Enabled) {
                $this.BackColor = $script:FLUENT_DESIGN.Colors.SECONDARY_PRESSED
            }
        })
        $Button.Add_MouseUp({
            if ($this.Enabled) {
                $this.BackColor = $script:FLUENT_DESIGN.Colors.SECONDARY_HOVER
            }
        })
    }
    
    # Windows 11 disabled state
    $Button.Add_EnabledChanged({
        try {
            if (-not $this.Enabled) {
                $this.ForeColor = $script:FLUENT_DESIGN.Colors.TEXT_TERTIARY
                $this.BackColor = $script:FLUENT_DESIGN.Colors.SECONDARY_BG
                $this.FlatAppearance.BorderColor = $script:FLUENT_DESIGN.Colors.BORDER_LIGHT
            }
            else {
                if ($this.Tag -eq "FluentPrimary") {
                    $this.ForeColor = [System.Drawing.Color]::White
                    $this.BackColor = $script:FLUENT_DESIGN.Colors.PRIMARY_BLUE
                    $this.FlatAppearance.BorderSize = 0
                }
                else {
                    $this.ForeColor = $script:FLUENT_DESIGN.Colors.TEXT_PRIMARY
                    $this.BackColor = $script:FLUENT_DESIGN.Colors.SECONDARY_BG
                    $this.FlatAppearance.BorderSize = 1
                    $this.FlatAppearance.BorderColor = $script:FLUENT_DESIGN.Colors.BORDER_MEDIUM
                }
            }
        }
        catch {
            Write-RepairLog -Message "Error in Fluent button EnabledChanged: $($_.Exception.Message)" -Category "WARNING"
        }
    })
}

function Set-FluentUtilityButtonStyle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Windows.Forms.Button]$Button,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Text
    )
    
    $colors = $script:FLUENT_DESIGN.Colors
    $buttonDims = $script:FLUENT_DESIGN.ButtonDimensions
    
    # Windows 11 utility button sizing - consistent and properly sized
    $Button.Size = New-Object System.Drawing.Size($buttonDims.UTIL_WIDTH, $buttonDims.UTIL_HEIGHT)  # Standardized size
    $Button.Text = $Text
    
    # Windows 11 typography for utility buttons
    $Button.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Regular)  # Slightly smaller font
    
    # Windows 11 subtle button styling
    $Button.BackColor = $colors.CARD_BACKGROUND
    $Button.ForeColor = $colors.TEXT_PRIMARY
    $Button.FlatStyle = 'Flat'
    $Button.FlatAppearance.BorderSize = 1
    $Button.FlatAppearance.BorderColor = $colors.BORDER_LIGHT
    $Button.Cursor = 'Hand'
    $Button.TextAlign = 'MiddleCenter'
    $Button.UseCompatibleTextRendering = $false
    
    # Windows 11 hover effects for utility buttons
    $Button.Add_MouseEnter({
        if ($this.Enabled) {
            $this.BackColor = $script:FLUENT_DESIGN.Colors.SECONDARY_HOVER
            $this.FlatAppearance.BorderColor = $script:FLUENT_DESIGN.Colors.PRIMARY_BLUE
            $this.ForeColor = $script:FLUENT_DESIGN.Colors.PRIMARY_BLUE
        }
    })
    $Button.Add_MouseLeave({
        if ($this.Enabled) {
            $this.BackColor = $script:FLUENT_DESIGN.Colors.CARD_BACKGROUND
            $this.FlatAppearance.BorderColor = $script:FLUENT_DESIGN.Colors.BORDER_LIGHT
            $this.ForeColor = $script:FLUENT_DESIGN.Colors.TEXT_PRIMARY
        }
    })
    $Button.Add_MouseDown({
        if ($this.Enabled) {
            $this.BackColor = $script:FLUENT_DESIGN.Colors.SECONDARY_PRESSED
        }
    })
    $Button.Add_MouseUp({
        if ($this.Enabled) {
            $this.BackColor = $script:FLUENT_DESIGN.Colors.SECONDARY_HOVER
        }
    })
}

function Set-TabOrder {
    [CmdletBinding()]
    param()
    
    # Set logical tab order
    $script:dismButton.TabIndex = 0
    $script:sfcButton.TabIndex = 1
    $script:cleanupButton.TabIndex = 2
    $script:helpButton.TabIndex = 3
    $script:viewLogButton.TabIndex = 4
    $script:closeButton.TabIndex = 5
}

function Set-KeyboardShortcuts {
    [CmdletBinding()]
    param()
    
    # Enable key preview on form
    $script:form.KeyPreview = $true
    
    # Add keyboard event handler
    $script:form.Add_KeyDown({
        param($eventSender, $e)
        
        try {
            switch ($e.KeyCode) {
                'F1' { 
                    Write-RepairLog -Message "F1 key pressed" -Category "USER"
                    $script:helpButton.PerformClick()
                    $e.Handled = $true
                }
                'F2' { 
                    Write-RepairLog -Message "F2 key pressed" -Category "USER"
                    $script:viewLogButton.PerformClick()
                    $e.Handled = $true
                }
                'Escape' { 
                    Write-RepairLog -Message "Escape key pressed" -Category "USER"
                    $script:closeButton.PerformClick()
                    $e.Handled = $true
                }
                'D1' { 
                    Write-RepairLog -Message "1 key pressed" -Category "USER"
                    if ($script:dismButton.Enabled) { 
                        $script:dismButton.PerformClick() 
                    }
                    $e.Handled = $true
                }
                'D2' { 
                    Write-RepairLog -Message "2 key pressed" -Category "USER"
                    if ($script:sfcButton.Enabled) { 
                        $script:sfcButton.PerformClick() 
                    }
                    $e.Handled = $true
                }
                'D3' { 
                    Write-RepairLog -Message "3 key pressed" -Category "USER"
                    if ($script:cleanupButton.Enabled) { 
                        $script:cleanupButton.PerformClick() 
                    }
                    $e.Handled = $true
                }
            }
        }
        catch {
            Write-RepairLog -Message "Error in keyboard handler: $($_.Exception.Message)" -Category "WARNING"
        }
    })
}

function Show-HelpDialog {
    [CmdletBinding()]
    param()
    
    $helpMsg = "System Repair Toolkit v4.0`n" +
    "Windows 11 Compatible • PowerShell 5.0+`n`n" +
    "This toolkit automates essential Windows repair and system optimization:`n`n" +
    "STEP 1 - DISM System Image Repair:`n" +
    "Fixes the Windows component store and system image.`n`n" +
    "STEP 2 - SFC System File Check:`n" +
    "Scans and repairs individual protected system files.`n`n" +
    "STEP 3 - Comprehensive System Optimization:`n" +
    "Multi-phase optimization including disk cleanup, registry optimization, and performance improvements.`n`n" +
    "Administrator privileges are required. All actions are logged to 'SystemRepairLog.txt' on your Desktop.`n`n" +
    "Keyboard Shortcuts:`n" +
    "• F1: Show this help`n" +
    "• F2: View log file`n" +
    "• 1-3: Run steps 1-3`n" +
    "• ESC: Close application"
    
    Show-InfoMessage -Title "System Repair Toolkit - Help" -Message $helpMsg
    Write-RepairLog -Message "User accessed help documentation" -Category "USER"
}

function Open-LogFile {
    [CmdletBinding()]
    param()
    
    try {
        if (Test-Path $script:logPath) {
            # Try to open with notepad
            Start-Process -FilePath "notepad.exe" -ArgumentList $script:logPath -ErrorAction Stop
            Write-RepairLog -Message "Log file opened by user" -Category "USER"
        }
        else {
            $message = "Log file not found. The log file will be created when you perform your first repair operation."
            Show-InfoMessage -Title "Log File Not Found" -Message $message
        }
    }
    catch {
        try {
            # Fallback to system default
            Invoke-Item $script:logPath
            Write-RepairLog -Message "Log file opened using system default" -Category "USER"
        }
        catch {
            $message = "Could not open the log file. Please manually open 'SystemRepairLog.txt' from your Desktop."
            Show-WarningMessage -Title "Unable to Open Log" -Message $message
        }
    }
}
#endregion

#region 13. UI State Management Functions - Dynamic UI Updates
function Update-UiForJobStart {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StatusMessage
    )
    
    try {
        # Synchronous UI updates for critical initialization
        if ($null -ne $script:form -and -not $script:form.IsDisposed) {
            if ($script:form.InvokeRequired) {
                # Use synchronous Invoke for initial setup to prevent race conditions
                $script:form.Invoke([Action]{
                    try {
                        # Check if form is still valid
                        if ($null -eq $script:form -or $script:form.IsDisposed -or $script:form.Disposing) {
                            return
                        }
                        
                        # Update status label
                        if ($null -ne $script:statusLabel -and -not $script:statusLabel.IsDisposed) {
                            $script:statusLabel.Text = $StatusMessage
                            $script:statusLabel.ForeColor = $script:FLUENT_DESIGN.Colors.TEXT_PRIMARY
                        }
                        
                        # Disable all main buttons
                        @($script:dismButton, $script:sfcButton, $script:cleanupButton) | ForEach-Object {
                            if ($null -ne $_ -and -not $_.IsDisposed) {
                                $_.Enabled = $false
                            }
                        }
                        
                        # Reset and show progress bar with explicit visibility and refresh
                        if ($null -ne $script:progressBar -and -not $script:progressBar.IsDisposed) {
                            $script:progressBar.Value = 0
                            $script:progressBar.Visible = $true
                            $script:progressBar.Refresh()
                            
                            Write-RepairLog -Message "Progress bar reset to 0% and made visible" -Category "DEBUG"
                        }
                        
                        # Update form title
                        if ($null -ne $script:form -and -not $script:form.IsDisposed) {
                            $script:form.Text = "System Repair Toolkit - Operation in Progress"
                        }
                    }
                    catch {
                        Write-RepairLog -Message "Error in UI update delegate: $($_.Exception.Message)" -Category "ERROR"
                    }
                })
            }
            else {
                # Already on UI thread, execute directly
                if ($null -ne $script:statusLabel -and -not $script:statusLabel.IsDisposed) {
                    $script:statusLabel.Text = $StatusMessage
                    $script:statusLabel.ForeColor = $script:FLUENT_DESIGN.Colors.TEXT_PRIMARY
                }
                
                @($script:dismButton, $script:sfcButton, $script:cleanupButton) | ForEach-Object {
                    if ($null -ne $_ -and -not $_.IsDisposed) {
                        $_.Enabled = $false
                    }
                }
                
                if ($null -ne $script:progressBar -and -not $script:progressBar.IsDisposed) {
                    $script:progressBar.Value = 0
                    $script:progressBar.Visible = $true
                    $script:progressBar.Refresh()
                    Write-RepairLog -Message "Progress bar reset to 0% and made visible (direct)" -Category "DEBUG"
                }
                
                if ($null -ne $script:form -and -not $script:form.IsDisposed) {
                    $script:form.Text = "System Repair Toolkit - Operation in Progress"
                }
            }
        }
        
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
        # Synchronous UI updates for job completion
        if ($null -ne $script:form -and -not $script:form.IsDisposed) {
            if ($script:form.InvokeRequired) {
                $script:form.Invoke([Action]{
                    try {
                        # Check if form is still valid
                        if ($null -eq $script:form -or $script:form.IsDisposed -or $script:form.Disposing) {
                            return
                        }
                        
                        # Set progress bar to 100% if successful before hiding
                        if ($null -ne $script:progressBar -and -not $script:progressBar.IsDisposed) {
                            if ($IsSuccess) {
                                $script:progressBar.Value = 100
                                $script:progressBar.Refresh()
                                
                                # Show 100% for a moment before hiding
                                Start-Sleep -Milliseconds 500
                            }
                            $script:progressBar.Visible = $true  # Keep visible to show final state
                        }
                        
                        # Update status label with appropriate color
                        if ($null -ne $script:statusLabel -and -not $script:statusLabel.IsDisposed) {
                            $script:statusLabel.Text = $StatusMessage
                            if ($IsSuccess) {
                                $script:statusLabel.ForeColor = $script:FLUENT_DESIGN.Colors.SUCCESS_GREEN
                            }
                            else {
                                $script:statusLabel.ForeColor = $script:FLUENT_DESIGN.Colors.ERROR_RED
                            }
                        }
                        
                        # Re-enable all main buttons
                        $buttonsToEnable = @($script:dismButton, $script:sfcButton, $script:cleanupButton)
                        foreach ($button in $buttonsToEnable) {
                            if ($null -ne $button -and -not $button.IsDisposed) { 
                                $button.Enabled = $true 
                            }
                        }
                        
                        # Reset form title
                        if ($null -ne $script:form -and -not $script:form.IsDisposed) {
                            $script:form.Text = "System Repair Toolkit"
                        }
                    }
                    catch {
                        Write-RepairLog -Message "Error in job end UI update delegate: $($_.Exception.Message)" -Category "ERROR"
                    }
                })
            }
            else {
                # Already on UI thread
                if ($null -ne $script:progressBar -and -not $script:progressBar.IsDisposed) {
                    if ($IsSuccess) {
                        $script:progressBar.Value = 100
                        $script:progressBar.Refresh()
                        Start-Sleep -Milliseconds 500
                    }
                    $script:progressBar.Visible = $true
                }
                
                if ($null -ne $script:statusLabel -and -not $script:statusLabel.IsDisposed) {
                    $script:statusLabel.Text = $StatusMessage
                    if ($IsSuccess) {
                        $script:statusLabel.ForeColor = $script:FLUENT_DESIGN.Colors.SUCCESS_GREEN
                    }
                    else {
                        $script:statusLabel.ForeColor = $script:FLUENT_DESIGN.Colors.ERROR_RED
                    }
                }
                
                @($script:dismButton, $script:sfcButton, $script:cleanupButton) | ForEach-Object {
                    if ($null -ne $_ -and -not $_.IsDisposed) {
                        $_.Enabled = $true
                    }
                }
                
                if ($null -ne $script:form -and -not $script:form.IsDisposed) {
                    $script:form.Text = "System Repair Toolkit"
                }
            }
        }
        
        Write-RepairLog -Message "UI updated for job end: $StatusMessage (Success: $IsSuccess)" -Category "SYSTEM"
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
        if ($null -ne $script:statusLabel -and -not $script:statusLabel.IsDisposed) {
            if ($IsAdministrator) {
                $script:statusLabel.Text = "Ready • Admin Mode • All functions available"
                $script:statusLabel.ForeColor = $script:FLUENT_DESIGN.Colors.SUCCESS_GREEN
                Write-RepairLog -Message "UI status set: Administrator mode" -Category "SYSTEM"
            }
            else {
                $script:statusLabel.Text = "Limited Mode • Run as Administrator for full functionality"
                $script:statusLabel.ForeColor = $script:FLUENT_DESIGN.Colors.WARNING_ORANGE
                Write-RepairLog -Message "UI status set: Limited mode" -Category "WARNING"
            }
            $script:statusLabel.Refresh()
        }
    }
    catch {
        Write-RepairLog -Message "Error setting ready status: $($_.Exception.Message)" -Category "ERROR"
    }
}
#endregion

#region 14. Form Event Handlers - Application Lifecycle Event Definitions
# Form closing event handler
$script:form_FormClosing = {
    param($formSender, $closeEventArgs)
    
    try {
        Write-RepairLog -Message "Application shutdown initiated" -Category "SYSTEM"
        
        # Stop progress timer
        Stop-ProgressTimer
        
        # Check if job is running
        if ($null -ne $script:currentRepairJob) {
            try {
                $jobState = $script:currentRepairJob.State
                Write-RepairLog -Message "Current job state: $jobState" -Category "JOB"
                
                if ($jobState -eq 'Running') {
                    # Ask user for confirmation
                    $message = "A repair operation is in progress. Are you sure you want to exit?"
                    $result = Show-QuestionMessage -Message $message -Title "Operation in Progress"
                    
                    if ($result -eq [System.Windows.Forms.DialogResult]::No) {
                        $closeEventArgs.Cancel = $true
                        Write-RepairLog -Message "Shutdown cancelled by user" -Category "USER"
                        # Restart timer if it was stopped
                        Start-ProgressTimer
                        return
                    }
                }
                
                # Stop the job
                Write-RepairLog -Message "Stopping active repair job" -Category "JOB"
                try {
                    $script:currentRepairJob | Stop-Job -ErrorAction SilentlyContinue
                    $script:currentRepairJob | Remove-Job -ErrorAction SilentlyContinue
                }
                catch {
                    Write-RepairLog -Message "Error stopping job: $($_.Exception.Message)" -Category "WARNING"
                }
            }
            catch {
                Write-RepairLog -Message "Error checking job state: $($_.Exception.Message)" -Category "WARNING"
            }
        }
        
        # Clear current job reference
        $script:currentRepairJob = $null
        
        # Clean up communication files
        if (-not [string]::IsNullOrEmpty($script:currentJobId)) {
            try {
                Clear-JobCommunicationFiles -JobId $script:currentJobId
            }
            catch {
                Write-RepairLog -Message "Error clearing communication files: $($_.Exception.Message)" -Category "WARNING"
            }
        }
        
        # Dispose of resources
        try {
            # Dispose tooltip
            if ($null -ne $script:toolTip -and -not $script:disposedObjects.Contains($script:toolTip)) {
                $script:toolTip.Dispose()
                $script:disposedObjects.Add($script:toolTip) | Out-Null
            }
            
            # Dispose fonts
            if ($null -ne $script:titleFont -and -not $script:disposedObjects.Contains($script:titleFont)) {
                $script:titleFont.Dispose()
                $script:disposedObjects.Add($script:titleFont) | Out-Null
            }
            if ($null -ne $script:secondaryFont -and -not $script:disposedObjects.Contains($script:secondaryFont)) {
                $script:secondaryFont.Dispose()
                $script:disposedObjects.Add($script:secondaryFont) | Out-Null
            }
        }
        catch {
            Write-RepairLog -Message "Error disposing resources: $($_.Exception.Message)" -Category "WARNING"
        }
        
        Write-RepairLog -Message "Application shutdown completed" -Category "SYSTEM"
    }
    catch {
        Write-Warning "Error during shutdown: $($_.Exception.Message)"
    }
}

# Form load event handler
$script:form_Load = {
    try {
        Write-RepairLog -Message "Main window loaded" -Category "SYSTEM"
        
        # Check administrator status
        $isAdmin = Test-IsAdministrator
        Set-ReadyStatus -IsAdministrator $isAdmin
        
        # Log system information
        $osInfo = [System.Environment]::OSVersion
        # FIXED: Use $Host.Version instead of $PSVersionTable
        $psVersion = $Host.Version.ToString()
        Write-RepairLog -Message "System Info - OS: $($osInfo.VersionString), PS: $psVersion" -Category "SYSTEM"
        
        # Set initial focus
        if ($null -ne $script:dismButton -and -not $script:dismButton.IsDisposed) {
            $script:dismButton.Focus()
        }
        
        # Show limited mode warning if not admin
        if (-not $isAdmin) {
            $message = "Welcome!`n`nYou are in Limited Mode. For full functionality, please restart as Administrator."
            Show-InfoMessage -Title "Limited Mode Notice" -Message $message
        }
        
        $script:isInitialized = $true
    }
    catch {
        Write-RepairLog -Message "Error during form load: $($_.Exception.Message)" -Category "ERROR"
        $script:isInitialized = $false
    }
}

# Form shown event handler
$script:form_Shown = {
    try {
        Write-RepairLog -Message "Application interface displayed" -Category "SYSTEM"
        
        # Log startup mode
        if (Test-IsAdministrator) {
            Write-RepairLog -Message "Toolkit started with Administrator privileges" -Category "SYSTEM"
        }
        else {
            Write-RepairLog -Message "Toolkit started in standard user mode" -Category "WARNING"
        }
        
        # Verify log file accessibility
        if (-not (Test-Path $script:logPath)) {
            Write-RepairLog -Message "Warning: Log file path may not be accessible" -Category "WARNING"
        }
        
        Write-RepairLog -Message "Initialization completed successfully" -Category "SYSTEM"
    }
    catch {
        Write-RepairLog -Message "Error during form shown event: $($_.Exception.Message)" -Category "ERROR"
    }
}

function Register-FormEvents {
    [CmdletBinding()]
    param()
    
    try {
        # Register event handlers
        $script:form.Add_FormClosing($script:form_FormClosing)
        $script:form.Add_Load($script:form_Load)
        $script:form.Add_Shown($script:form_Shown)
        
        Write-RepairLog -Message "Form events registered" -Category "SYSTEM"
    }
    catch {
        Write-RepairLog -Message "Error registering form events: $($_.Exception.Message)" -Category "ERROR"
        throw
    }
}
#endregion

#region 15. Application Entry Point and Execution - Main Program Flow
# Register unhandled exception handler
try {
    [System.AppDomain]::CurrentDomain.add_UnhandledException({
        param($exceptionSender, $exceptionEventArgs)
        try {
            $exception = $exceptionEventArgs.ExceptionObject
            Write-RepairLog -Message "Unhandled exception: $($exception.ToString())" -Category "ERROR"
            
            # Show error to user
            [System.Windows.Forms.MessageBox]::Show(
                "An unexpected error occurred. The application will close.`n`nError: $($exception.Message)",
                "System Repair Toolkit - Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
        catch {
            Write-Error "Critical exception: $($exceptionEventArgs.ExceptionObject.ToString())"
        }
    })
}
catch {
    Write-Warning "Could not register unhandled exception handler: $($_.Exception.Message)"
}

# Main application entry point - This must be at the END after all functions are defined
try {
    Write-RepairLog -Message "=== SYSTEM REPAIR TOOLKIT STARTUP ===" -Category "SYSTEM"
    Write-RepairLog -Message "Application startup initiated" -Category "SYSTEM"
    
    # Verify OS version
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -lt 10) {
        Write-RepairLog -Message "Warning: Running on pre-Windows 10 system (Version: $osVersion)" -Category "WARNING"
        
        $message = "This toolkit is designed for Windows 10/11. Some features may not work correctly on older versions."
        [System.Windows.Forms.MessageBox]::Show(
            $message,
            "System Repair Toolkit - Compatibility Warning",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
    }
    
    # Log .NET version
    try {
        $netVersion = [System.Environment]::Version
        Write-RepairLog -Message ".NET Runtime Version: $netVersion" -Category "SYSTEM"
    }
    catch {
        Write-RepairLog -Message "Could not determine .NET version" -Category "WARNING"
    }
    
    # Initialize main form - Now this function exists!
    if (-not (Initialize-MainForm)) {
        throw "Failed to initialize main form"
    }
    
    # Register form events
    Register-FormEvents
    
    Write-RepairLog -Message "Displaying main application window" -Category "SYSTEM"
    
    # Show the form
    [void]$script:form.ShowDialog()
    
    Write-RepairLog -Message "Main window closed by user" -Category "SYSTEM"
}
catch {
    $errorMessage = "Critical startup error: $($_.Exception.Message)"
    Write-RepairLog -Message $errorMessage -Category "ERROR"
    
    try {
        [System.Windows.Forms.MessageBox]::Show(
            "A critical error occurred during startup:`n`n$($_.Exception.Message)`n`n" +
            "Please ensure .NET Framework 4.x is installed and try running as Administrator.",
            "System Repair Toolkit - Startup Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
    catch {
        Write-Error "Critical error: $($_.Exception.Message)"
    }
}
finally {
    try {
        Write-RepairLog -Message "Application execution completed - cleanup starting" -Category "SYSTEM"
        
        # Stop progress timer
        Stop-ProgressTimer
        
        # Stop all jobs
        try {
            Stop-AllJobs
        }
        catch {
            Write-RepairLog -Message "Error stopping jobs: $($_.Exception.Message)" -Category "WARNING"
        }
        
        # Clean up communication files
        try {
            Clear-JobCommunicationFiles
        }
        catch {
            Write-RepairLog -Message "Error clearing communication files: $($_.Exception.Message)" -Category "WARNING"
        }
        
        # Dispose timer lock
        try {
            if ($null -ne $script:timerLock) {
                $script:timerLock.Dispose()
            }
        }
        catch {
            Write-RepairLog -Message "Error disposing timer lock: $($_.Exception.Message)" -Category "WARNING"
        }
        
        # Clear job collection
        try {
            $script:jobCollection.Clear()
        }
        catch {
            Write-RepairLog -Message "Error clearing job collection: $($_.Exception.Message)" -Category "WARNING"
        }
        
        # Dispose all tracked objects
        try {
            foreach ($obj in $script:disposedObjects) {
                if ($null -ne $obj -and $obj -is [System.IDisposable]) {
                    try {
                        $obj.Dispose()
                    }
                    catch {
                        # Silently continue
                    }
                }
            }
            $script:disposedObjects.Clear()
        }
        catch {
            Write-RepairLog -Message "Error disposing tracked objects: $($_.Exception.Message)" -Category "WARNING"
        }
        
        Write-RepairLog -Message "=== SYSTEM REPAIR TOOLKIT SESSION END ===" -Category "SYSTEM"
        Close-RepairLog
    }
    catch {
        Write-Warning "Error during final cleanup: $($_.Exception.Message)"
    }
}
#endregion