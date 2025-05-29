# System Repair Toolkit

A comprehensive Windows system repair and cleanup utility with a user-friendly graphical interface.
![Screenshot](https://github.com/user-attachments/assets/4b4009bc-0918-47a3-96f7-6998a0326895)

## What It Does

Automates common Windows maintenance tasks to fix system issues and optimize performance:

- **DISM Image Repair** - Fixes Windows component store corruption
- **SFC System File Check** - Scans and repairs protected system files  
- **Comprehensive Disk Cleanup** - Removes temporary files and frees disk space

## Key Features

✅ **Non-blocking UI** - Window stays responsive during operations  
✅ **Real-time Progress** - Live progress bars and status updates  
✅ **Comprehensive Logging** - Detailed activity log saved to Desktop  
✅ **Windows.old Handling** - Optional removal of previous Windows installations  
✅ **Administrator Detection** - Automatic privilege level detection  
✅ **Background Processing** - All operations run as background jobs  

## Requirements

- Windows 10/11
- PowerShell 5.1 or later
- Administrator privileges (for full functionality)

## Usage

### Quick Start
1. Right-click the script file
2. Select "Run with PowerShell" 
3. If prompted, click "Run anyway"

### Recommended Order
1. **Step 1: DISM Repair** - Run first to fix component store issues
2. **Step 2: SFC Scan** - Run after DISM to repair system files
3. **Step 3: Disk Cleanup** - Run last to clean up temporary files

### Administrator Mode
For full functionality, run as Administrator:
1. Right-click PowerShell
2. Select "Run as administrator"
3. Navigate to script location and run

## What Gets Cleaned

The disk cleanup removes:
- Temporary files and caches
- Recycle Bin contents
- Windows Update files
- System error reports
- Windows upgrade logs
- Memory dump files
- Browser cache files
- **Windows.old folder** (with user confirmation)

## Logs

All activities are logged to `SystemRepairLog.txt` on your Desktop for troubleshooting and review.

## Notes

- Operations may take several minutes to complete
- Some cleanup operations require a reboot to fully take effect
- Windows.old removal is irreversible - removes ability to rollback Windows versions
- Close other applications before running for best results

## Safety

This tool only uses built-in Windows utilities (DISM, SFC, cleanmgr.exe). No System Restore points are created - manage System Restore manually if needed.

---

**Version:** 1.0  
**Compatibility:** Windows 10/11  
**License:** Free for personal and commercial use
