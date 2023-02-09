<#  
.SYNOPSIS  
    Install DNS Server, deploy primary lookup zone, reverse lookup zone, and deploy coorsponding A records
.DESCRIPTION  
    Install DNS Server, deploy primary lookup zone, reverse lookup zone, and deploy coorsponding A records

        v1.0 - Initial
.NOTES  
    File Name       :   Initialize-DnsServer.ps1  
    Author          :   Paul Lizer, paullizer@microsoft.com
    Prerequisite    :   PowerShell V5, Azure PowerShell 5.6.0 or greater
    Version         :   1.0 (2023 01 13)     
.LINK  
    https://github.com/paullizer/customScriptExtensions
.EXAMPLE  
    Used as a Custom Script Extension.
        Initialize-DnsServer.ps1
#>

<#***************************************************
                       Variables
***************************************************#>

<#***************************************************
                       Functions
-----------------------------------------------------
***************************************************#>

<#***************************************************
                       Execution
***************************************************#>

Install-WindowsFeature -name DNS -IncludeManagementTools
Enable-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)"

Add-DnsServerPrimaryZone -Name "spikecamp.fs" -ZoneFile "spikecamp.fs.dns"
Add-DnsServerPrimaryZone -Name "microsoftdatabox.com" -ZoneFile "microsoftdatabox.com.dns"
Add-DnsServerPrimaryZone -Name "spikecamp.fs" -ZoneFile "spikecamp.fs.dns"
Add-DnsServerPrimaryZone -NetworkId "192.168.0.0/24" -ZoneFile "192_168_0_0-24.dns"

Add-DnsServerResourceRecordA -Name "spikecamp.fs" -ZoneName "spikecamp.fs" -AllowUpdateAny -IPv4Address "192.168.0.54" -TimeToLive 01:00:00
Add-DnsServerResourceRecordPtr -Name "54" -ZoneName "0.168.192.in-addr.arpa" -PtrDomainName "spikecamp.fs"

Add-DnsServerResourceRecordA -Name "dvm-tma-00133" -ZoneName "microsoftdatabox.com" -AllowUpdateAny -IPv4Address "192.168.0.89" -TimeToLive 01:00:00 -CreatePtr
Add-DnsServerResourceRecordA -Name "vm-tma-00133" -ZoneName "microsoftdatabox.com" -AllowUpdateAny -IPv4Address "192.168.0.89" -TimeToLive 01:00:00 -CreatePtr
Add-DnsServerResourceRecordA -Name "login.dvm-tma-00133" -ZoneName "microsoftdatabox.com" -AllowUpdateAny -IPv4Address "192.168.0.89" -TimeToLive 01:00:00 -CreatePtr
Add-DnsServerResourceRecordA -Name "login.vm-tma-00133" -ZoneName "microsoftdatabox.com" -AllowUpdateAny -IPv4Address "192.168.0.89" -TimeToLive 01:00:00 -CreatePtr
Add-DnsServerResourceRecordA -Name "management.dvm-tma-00133" -ZoneName "microsoftdatabox.com" -AllowUpdateAny -IPv4Address "192.168.0.89" -TimeToLive 01:00:00 -CreatePtr
Add-DnsServerResourceRecordA -Name "management.vm-tma-00133" -ZoneName "microsoftdatabox.com" -AllowUpdateAny -IPv4Address "192.168.0.89" -TimeToLive 01:00:00 -CreatePtr
