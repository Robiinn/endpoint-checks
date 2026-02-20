<#
    .SYNOPSIS
    Get-ADInfo.ps1

    .DESCRIPTION
    Get Active Directory information.

    .NOTES
    Written by: ALI TAJRAN
    Edited by: Robiinn

    .CHANGELOG
    V1.20, 08/12/2024 - Added Windows Server 2025 support
    V1.21, 20-02-2025 - Added server flag for AD commands to run from non domain joined system
#>
param (
	[string]$server = $null
)

$adParams = @{}

if ($server) {
	$adParams.Server = "$server"
}

# Get counts of different types of objects in Active Directory
$Computers = (Get-ADComputer @adParams -Filter * | Measure-Object).Count
$Workstations = (Get-ADComputer @adParams -Filter { OperatingSystem -notlike "*Server*" } | Measure-Object).Count
$Servers = (Get-ADComputer @adParams -Filter { OperatingSystem -like "*Server*" } | Measure-Object).Count
$Users = (Get-ADUser @adParams -Filter * | Measure-Object).Count
$Groups = (Get-ADGroup @adParams -Filter * | Measure-Object).Count

# Get Active Directory Forest information
$ADForest = (Get-ADDomain @adParams ).Forest
$ADForestMode = (Get-ADForest @adParams ).ForestMode
$ADDomainMode = (Get-ADDomain @adParams ).DomainMode

# Obtain Active Directory Schema version and translate it to the corresponding Windows Server version
$ADVer = Get-ADObject (Get-ADRootDSE @adParams ).schemaNamingContext @adParams  -Property objectVersion | Select-Object objectVersion
$ADNum = $ADVer -replace "@{objectVersion=", "" -replace "}", ""

switch ($ADNum) {
    '91' { $srv = 'Windows Server 2025' }
    '88' { $srv = 'Windows Server 2019/Windows Server 2022' }
    '87' { $srv = 'Windows Server 2016' }
    '69' { $srv = 'Windows Server 2012 R2' }
    '56' { $srv = 'Windows Server 2012' }
    '47' { $srv = 'Windows Server 2008 R2' }
    '44' { $srv = 'Windows Server 2008' }
    '31' { $srv = 'Windows Server 2003 R2' }
    '30' { $srv = 'Windows Server 2003' }
}

# Display collected information
Write-host "Active Directory Info" -ForegroundColor Yellow
Write-host ""
Write-Host "Computers  = $Computers" -ForegroundColor Cyan
Write-Host "Workstions = $Workstations" -ForegroundColor Cyan
Write-Host "Servers    = $Servers" -ForegroundColor Cyan
Write-Host "Users      = $Users" -ForegroundColor Cyan
Write-Host "Groups     = $Groups" -ForegroundColor Cyan
Write-host ""
Write-Host "Active Directory Forest Name = "$ADForest -ForegroundColor Cyan
Write-Host "Active Directory Forest Mode = "$ADForestMode -ForegroundColor Cyan
Write-Host "Active Directory Domain Mode = "$ADDomainMode -ForegroundColor Cyan
Write-Host "Active Directory Schema Version is $ADNum which corresponds to $srv" -ForegroundColor Cyan
Write-Host ""
Write-Host "FSMO Role Owners" -ForegroundColor Cyan

# Retrieve FSMO roles individually
$Forest = Get-ADForest @adParams 
$SchemaMaster = $Forest.SchemaMaster
$DomainNamingMaster = $Forest.DomainNamingMaster
$Domain = Get-ADDomain @adParams 
$RIDMaster = $Domain.RIDMaster
$PDCEmulator = $Domain.PDCEmulator
$InfrastructureMaster = $Domain.InfrastructureMaster

# Display FSMO role owners
Write-Host "Schema Master         =  $SchemaMaster" -ForegroundColor Cyan
Write-Host "Domain Naming Master  =  $DomainNamingMaster" -ForegroundColor Cyan
Write-Host "RID Master            =  $RIDMaster" -ForegroundColor Cyan
Write-Host "PDC Emulator          =  $PDCEmulator" -ForegroundColor Cyan
Write-Host "Infrastructure Master =  $InfrastructureMaster" -ForegroundColor Cyan
