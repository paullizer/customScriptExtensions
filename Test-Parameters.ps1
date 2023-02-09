<#  
.SYNOPSIS  
    Install IIS
.DESCRIPTION  
    Install IIS

        v1.0 - Initial
.NOTES  
    File Name       :   Initialize-WebServer.ps1  
    Author          :   Paul Lizer, paullizer@microsoft.com
    Prerequisite    :   PowerShell V5, Azure PowerShell 5.6.0 or greater
    Version         :   1.0 (2023 01 13)     
.LINK  
    https://github.com/paullizer/customScriptExtensions
.EXAMPLE  
    Used as a Custom Script Extension.
        Initialize-WebServer.ps1
#>

<#***************************************************
        Install IIS and Update Windows Firewall
***************************************************#>

Param(
        [Parameter(Mandatory=$true)]
        [string]$userPassword,
        [Parameter(Mandatory=$true)]
        [string]$uploadPassword
)


# Create temp folder
$log = "c:\temp\log.txt"
$temp = Get-Item "c:\temp" -ErrorAction SilentlyContinue
if (!$temp) {
    try {
        New-Item -ItemType Directory -Path "c:\temp"
        "Created c:\temp"
    }
    catch {
        $_
    }
}

$userPassword | out-file $log -Append

$uploadPassword | out-file $log -Append
