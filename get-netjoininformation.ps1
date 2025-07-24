Add-Type -TypeDefinition @"
namespace PInvoke {
    public enum NetJoinStatus
    {
        NetSetupUnknownStatus = 0,
        NetSetupUnjoined,
        NetSetupWorkgroupName,
        NetSetupDomainName
    }
}
"@;
 
$NetGetJoinInformation = @'
[DllImport("Netapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern int NetGetJoinInformation(
    string server, 
    out IntPtr domain,
    out int status);
'@
 
$args1 = $null
$args2 = [IntPtr]::Zero
$args3 = New-Object PInvoke.NetJoinStatus;
 
$type = Add-Type -MemberDefinition $NetGetJoinInformation -Name NetJoin -Namespace Test -PassThru
 
$retValue = $type::NetGetJoinInformation($args1, [ref] $args2, [ref] $args3);
 
if ($retValue -eq 0) {
    Write-Host "Success"
 
    switch ($args3.ToString())
    {
        $([PInvoke.NetJoinStatus]::NetSetupUnknownStatus.value__) { Write-Host ([PInvoke.NetJoinStatus]::NetSetupUnknownStatus); continue  }
        $([PInvoke.NetJoinStatus]::NetSetupUnjoined.value__) { Write-Host ([PInvoke.NetJoinStatus]::NetSetupUnjoined); continue }
        $([PInvoke.NetJoinStatus]::NetSetupDomainName.value__) { Write-Host "$([PInvoke.NetJoinStatus]::NetSetupDomainName): $([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($args2))"; continue }
        $([PInvoke.NetJoinStatus]::NetSetupWorkgroupName.value__) { Write-Host "$([PInvoke.NetJoinStatus]::NetSetupWorkgroupName): $([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($args2))"; continue }
        Default { write-host "Only errors" }
    }
 
}
else
{
    Write-Host "Error: I did not include any error control here :)";
}
