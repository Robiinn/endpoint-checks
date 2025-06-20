function Get-GroupFromSID($sid) {
    return $(Get-WmiObject -Query "SELECT * FROM Win32_Group WHERE LocalAccount = TRUE AND SID = '$sid'").Name
}

function Write-Title($title) {
    Write-Host
    Write-Host -ForegroundColor Yellow $("=" * 46)
    Write-Host -ForegroundColor Yellow $title
    Write-Host -ForegroundColor Yellow $("=" * 46)
    Write-Host
}

function Run($Command) {
    $FullCommand = $Command + " 2>&1"
    $File = "$OutputDir\${Section}.txt".ToLower().Replace(" ", "_")
    $Output = ($FullCommand | IEX | Out-string) -join "`n"
    $Snippet = @"
$ $Command

$Output

"@
    Write-Host "$ $Command" -ForegroundColor Green
    Write-Host
    Write-Host "$Output"
    Add-Content -Path "$File" -Value "$Snippet"
}

function Get-Tasklist {
    [string[]] $Result = tasklist /v
    $Format = $Result[2] | ConvertFrom-String | Measure-Object -Property * -Character | Select-Object property, characters        
    $Processes = foreach ($r in $Result) {       
        if ($r.length -eq 0) {
            continue
        }
        if ($r -match '^(===)+' -or $r -match '^Image\sName\s+PID') {
            continue
        }

        [int] $StringPosition = 0
        $Fields = foreach ($FieldCount in 0..8) {
            $Column = ($r.Substring($StringPosition, $Format[$FieldCount].characters)).Trim()
            $StringPosition += $Format[$FieldCount].characters + 1
            $Column
        }

        $prop = [ordered] @{
            'Image Name' = $fields[0]
            'PID'        = $fields[1]
            # 'SessionName' = $fields[2]
            'Session#'   = $fields[3]
            # 'Mem Usage'  = $fields[4]
            # 'Status' = $fields[5]
            'User Name'  = $fields[6]
            'CPU Time'   = $fields[7]
            # 'WindowTitle' = $fields[8]
        } 
        New-Object -TypeName psobject -Property $prop
    } 
    $Processes | Format-Table
}

function Get-ScheduledObjects {
    $Tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" }
    foreach ($Task in $Tasks) {
        if ($Task.Actions.ClassId -ne $null) {
            if ($Task.Triggers.Enabled -eq $true) {
                if ($Task.Principal.GroupId -eq "Users") {
                    Write-Host "Task Name: " $Task.TaskName
                    Write-Host "Task Path: " $Task.TaskPath
                    Write-Host "CLSID: " $Task.Actions.ClassId
                    Write-Host
                }
            }
        }
    }
}

# Check if the script is running with elevated privileges
$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Create output directory
$OutputDir = "CH80_{0:yyyyMMddHHmmss}" -f $(Get-Date)
New-Item -Path $OutputDir -ItemType Directory >$null
If (Test-Path -Path $OutputDir) {
    Write-Host "[*] Output directory created successfully at $PWD\$OutputDir"
}
Else {
    Write-Host "Failed to create directory at $PWD\$OutputDir"
    exit 1
}

# Last boot time
$Section = "BOOT TIME"
Write-Title $Section
Run '(Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime'

$Section = "SYSTEM INFO"
Write-Title $Section
Run 'systeminfo'

# Security patches
$Section = "SECURITY PATCHES"
Write-Title $Section
Run 'Get-Hotfix | Sort-Object -Property InstalledOn -Descending'

# Networking
$Section = "NETWORKING"
Write-Title $Section
Run 'ipconfig /all'
Run 'route print'
Run 'netstat -ano'

# Firewalling
$Section = "FIREWALL SETTINGS"
Write-Title $Section
Run 'netsh advfirewall show allprofiles'

# Powershell
$Section = "POWERSHELL"
Write-Title $Section
Run '$PSVersionTable'
Run '$ExecutionContext.SessionState.LanguageMode'

# AppLocker
$Section = "APPLICATION WHITELISTING"
Write-Title $Section
Import-Module applocker
Run 'Get-AppLockerPolicy -effective -xml'

# Processes
$Section = "PROCESSES"
Write-Title $Section
Run 'Get-Tasklist'

# Exfiltration
# fsutil file createNew dummyfile 1572864000

# AntiVirus
$Section = "AV STATUS"
Write-Title $Section
# This will fail if executed in Windows Server, as the namespace 'SecuritySpace2' does not exist in this version.
# I could not found a workaround for Windows Server, so for now, it fails when executed.
try {
    Run 'Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntivirusProduct" -ErrorAction Stop | Select-Object -ExcludeProperty __* -Property *'
    If ((Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntivirusProduct").displayName -eq "Windows Defender") {
        Run 'Get-MPComputerStatus'
        Run "Get-ChildItem 'registry::HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions' -ErrorAction SilentlyContinue"
    }
}
catch {
    Write-Host -ForegroundColor Red "[!] Failed to lookup AV software in WMIC"
}
Run 'Get-WmiObject -Class Win32_Product -Namespace root\cimv2 | Where-Object { $_.Name -match "antivirus|security|defender|crowdstrike|sentinel|mcafee|sophos|carbon black|cylance|symantec|trend micro|eset|bitdefender" } | Select-Object Name, Version, Vendor'

# Third-party software
$Section = "3rd PARTY SOFTWARE"
Write-Title $Section
Run 'Get-WmiObject -Class Win32_Product | Where-Object { $_.Vendor -notlike "Microsoft Corporation" -and $_.Vendor -notlike "Microsoft" } | Select-Object Name, Version, Vendor'

# Users
$Section = "USERS"
Write-Title $Section
Run 'whoami /priv'
Run 'net user'
# Careful with language-dependant usernames!
$Administrator = (Get-WmiObject -Query "SELECT Name FROM win32_useraccount WHERE sid LIKE '%500'").Name
$Guest = (Get-WmiObject -Query "SELECT Name FROM win32_useraccount WHERE sid LIKE '%501'").Name
If (![string]::IsNullOrEmpty($Administrator)) {
    Run "net user $Administrator"
}
Else {
    Write-Host -ForegroundColor Red "[!] Administrator user not found!"
    # Run this command to reflect in the log that the user did not exist
    Run "net user Administrator"
}
If (![string]::IsNullOrEmpty($Guest)) {
    Run "net user $Guest"
}
Else {
    Write-Host -ForegroundColor Red "[!] Guest user not found!"
    # Run this command to reflect in the log that the user did not exist
    Run "net user Guest"
}

# Groups
$Section = "GROUPS"
Write-Title $Section
Run 'net localgroup'
Run "net localgroup ""$(Get-GroupFromSID 'S-1-5-32-544')"""
Run "net localgroup ""$(Get-GroupFromSID 'S-1-5-32-555')"""
Run "net localgroup ""$(Get-GroupFromSID 'S-1-5-32-546')"""
Run 'whoami /groups'

$Section = "PRIVILEGE ESCALATION"
Write-Title $Section
## Unquoted services
Write-Host "[*] Check for unquoted services:"
Run 'wmic service get name,pathname,displayname,startmode | Select-String auto | Select-String -NotMatch "C:\\Windows\\" | Select-String -NotMatch ''"'' | Select line'
## Cached credentials
Run 'reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential'
Run 'reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount'
## COM objects in the task scheduler
Run 'Get-ScheduledObjects'
Write-Host "[*] Check for PrintNightmare (CVE-2021-34527):"
Run 'reg query "HKLM\software\policies\microsoft\windows nt\printers\pointandprint" /v restrictdriverinstallationtoadministrators'
run 'reg query "HKLM\software\policies\microsoft\windows nt\printers\pointandprint" /v nowarningnoelevationoninstall'
run 'reg query "HKLM\software\policies\microsoft\windows nt\printers\pointandprint" /v updatepromptsettings'

# Bitlocker
$Section = "BITLOCKER"
Write-Title $Section
If ($elevated) {
    Import-Module -WarningAction:SilentlyContinue -ErrorAction:SilentlyContinue BitLocker
    If ((Get-Module BitLocker).Count -ne 0) {
        Run 'Get-BitlockerVolume'
        Get-BitlockerVolume | ForEach-Object {
            If ($_.ProtectionStatus -eq "On") {
                Run "manage-bde -protectors -get $($_.MountPoint)"
            }
        }
    }
    Else {
        Write-Host -ForegroundColor Red "[!] BitLocker module could not be imported"
    }
}
Else {
    Write-Host -ForegroundColor Red "[-] Running as non-privileged user, can't enumerate BitLocker configuration."
}

# Compress output files
$Section = "DONE!"
Write-Title $Section
Compress-Archive -Path "$OutputDir" -DestinationPath "${OutputDir}.zip"
Write-Host "[+] Output files compressed in $PWD\${OutputDir}.zip"
Write-Host "[*] Cleaning up..."
Remove-Item "$PWD\$OutputDir" -Recurse -Force
