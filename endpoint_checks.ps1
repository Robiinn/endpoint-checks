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
    $File = "$OutputDir\${Section}.txt".ToLower().Replace(" ", "_")
    $Output = ($Command | IEX | Out-string) -join "`n"
    $Snippet = @"
$ $Command

$Output

"@
    Write-Host "$ $Command" -ForegroundColor Green
    Write-Host
    Write-Host "$Output"
    Add-Content -Path "$File" -Value "$Snippet"
}

# Check if the script is running with elevated privileges
$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Create output directory
$OutputDir = "CH80_{0:yyyyMMddHHmmss}" -f $(Get-Date)
New-Item -Path $OutputDir -ItemType Directory >$null
If (Test-Path -Path $OutputDir)
{
    Write-Host "[*] Output directory created successfully at $PWD\$OutputDir"
} Else
{
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
Run 'tasklist /v'

# Exfiltration
# fsutil file createNew dummyfile 1572864000

# AntiVirus
$Section = "AV STATUS"
Write-Title $Section
# This will fail if executed in Windows Server, as the namespace 'SecuritySpace2' does not exist in this version.
# I could not found a workaround for Windows Server, so for now, it fails when executed.
Write-Host "[*] This is likely to fail in Windows Server:"
Run 'Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntivirusProduct" | Select-Object -ExcludeProperty __* -Property *'
If ((Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntivirusProduct").displayName -eq "Windows Defender")
{
    Run 'Get-MPComputerStatus'
    Run "Get-ChildItem 'registry::HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions' -ErrorAction SilentlyContinue"
}

# Third-party software
$Section = "3rd PARTY SOFTWARE"
Write-Title $Section
Run 'Get-WmiObject -Class Win32_Product | Where-Object { $_.Vendor -notlike "Microsoft Corporation" -and $_.Vendor -notlike "Microsoft" } | Select-Object Name, Version, Vendor'

# Users
$Section = "USERS"
Write-Title $Section
Run 'whoami /priv'
Run 'net user'
Run 'net user Administrator'
# Careful with language-dependant usernames!
$Guest = (Get-WmiObject -Query "SELECT Name FROM win32_useraccount WHERE sid LIKE '%501'").Name
If (![string]::IsNullOrEmpty($Guest)) {
    Run "net user $Guest"
} Else {
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
Run 'reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential 2>&1'
Run 'reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount'

# Bitlocker
$Section = "BITLOCKER"
Write-Title $Section
If ($elevated)
{
    Import-Module -WarningAction:SilentlyContinue -ErrorAction:SilentlyContinue BitLocker
    If ((Get-Module BitLocker).Count -ne 0)
    {
        Run 'Get-BitlockerVolume'
        Get-BitlockerVolume | ForEach-Object {
            If ($_.ProtectionStatus -eq "On")
            {
                Run "manage-bde -protectors -get $($_.MountPoint)"
            }
        }
    } Else
    {
        Write-Host -ForegroundColor Red "[!] BitLocker module could not be imported"
    }
} Else
{
    Write-Host -ForegroundColor Red "[-] Running as non-privileged user, can't enumerate BitLocker configuration."
}

# Compress output files
$Section = "DONE!"
Write-Title $Section
Compress-Archive -Path "$OutputDir" -DestinationPath "${OutputDir}.zip"
Write-Host "[+] Output files compressed in $PWD\${OutputDir}.zip"
Write-Host "[*] Cleaning up..."
Remove-Item "$PWD\$OutputDir" -Recurse -Force
