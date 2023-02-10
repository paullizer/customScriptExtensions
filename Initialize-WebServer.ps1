<#  
.SYNOPSIS  
    Install IIS
.DESCRIPTION  
    Install IIS

        v1.0 - Initial
        v1.1 - Added support for additional TLS and SSL versions
        v1.2 - Added Path reload
        v1.3 - Using incidents instead of download
.NOTES  
    File Name       :   Initialize-WebServer.ps1  
    Author          :   Paul Lizer, paullizer@microsoft.com
    Prerequisite    :   PowerShell V5, Azure PowerShell 5.6.0 or greater
    Version         :   1.3 (2023 02 09)     
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
        [string]$userPassword
)

    $log = "c:\temp\log.txt"

# Create temp folder
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
    
    $userSecurePassword = $userPassword | ConvertTo-SecureString -AsPlainText -Force
    $userUsername = "user"
    $userCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $userUsername, $userSecurePassword

    $hostFileShare = "dvm-tma-00133.microsoftdatabox.com"

    $uploadFolder = "upload"
    $downloadFolder = "incidents"

    $projectFile = "project.txt"

    [Net.ServicePointManager]::SecurityProtocol = "Tls, Tls11, Tls12, Ssl3"

# Create local user to run IIS that has the same name and password as the account used to connect to ASE file share
    try {
        New-LocalUser $userUsername -Password $userSecurePassword -Description "Runs IIS and accesses ASE shares." -AccountNeverExpires -PasswordNeverExpires
        "Created new user" | out-file $log -Append
        start-sleep -s 5
    }
    catch {
        "Failed create new user" | out-file $log -Append
        $_ | out-file $log -Append
    }

# Install IIS, Install CGI (aka FastCGI)
    try {
        Install-WindowsFeature -name Web-Server, Web-CGI -IncludeManagementTools
        "Installed IIS and CGI" | out-file $log -Append
        start-sleep -s 5
    }
    catch {
        "Failed to install IIS and CGI" | out-file $log -Append
        $_ | out-file $log -Append
    }

# update all the web sites to run under the context of the specified user
    try {
        $dir = Get-Location
        "Collected location" | out-file $log -Append
        start-sleep -s 5
    }
    catch {
        "Failed to collect location" | out-file $log -Append
        $_ | out-file $log -Append
    }

    try {
        cd IIS:\Sites
        $webSites = Get-Website
        "Collected websites" | out-file $log -Append
        start-sleep -s 5
    }
    catch {
        "Failed to collect websites" | out-file $log -Append
        $_ | out-file $log -Append
    }

    try {
        ForEach($webSite in $webSites)
        {
            $siteName = ($webSite | Select-Object -Property "Name").name
            $fullPath = "system.applicationHost/sites/site[@name='$siteName']/application[@path='/']/virtualDirectory[@path='/']"
            Set-WebConfigurationProperty $fullPath -Name "username" -Value $userUsername
            Set-WebConfigurationProperty $fullPath -Name "password" -Value $userPassword
        }
        ("Updated username and password for website - " + $siteName) | out-file $log -Append
        start-sleep -s 5
    }
    catch {
        ("Failed to update username and password for website - " + $siteName) | out-file $log -Append
        $_ | out-file $log -Append
    }
    
    try {
        cd $dir
        iisreset
        "Restarted IIS" | out-file $log -Append
        start-sleep -s 5
    }
    catch {
        "Failed to restart IIS" | out-file $log -Append
        $_ | out-file $log -Append
    }

# Update firewall to allow ping
    try {
        Enable-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)"
        "Updated filewall, enabled File and Printer Sharing (Echo Request - ICMPv4-In)" | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        "Faileds to update filewall, enabled File and Printer Sharing (Echo Request - ICMPv4-In)" | out-file $log -Append 
        $_ | out-file $log -Append 
    }

<#***************************************************
                    Install PHP
***************************************************#>

# Get latest version of PHP
    try {
        $urlPhp = "https://windows.php.net/download/"
        $versionsPhp = (Invoke-WebRequest $urlPhp -UseBasicParsing).Content | Select-String -Pattern ".*PHP \d+\.\d+ \(\d+\.\d+\.\d+\)" -AllMatches
        $matchPhp = ($versionsPhp.Matches.Value)[0].replace('(','')
        $matchPhp = $matchPhp.replace(')','')
        $latestPhp = ($matchPhp -split " ")
        $urlPhpDownload = "https://windows.php.net/downloads/releases/php-" + $latestPhp[$latestPhp.count-1] + "-nts-Win32-vs16-x64.zip"
        "Collected latest PHP version" | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        "Failed to collect latest PHP version. This is a catastrophic error, exiting. Contact support." | out-file $log -Append 
        $_ | out-file $log -Append
        Exit
    }

# Download latest version of PHP
    try {
        Invoke-WebRequest -Uri $urlPhpDownload -OutFile ("c:\temp\php-" + $latestPhp[$latestPhp.count-1] + "-nts-Win32-vs16-x64.zip") -UseBasicParsing
        ("Downloaded php-" + $latestPhp[$latestPhp.count-1] + "-nts-Win32-vs16-x64.zip") | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        ("Failed to download php-" + $latestPhp[$latestPhp.count-1] + "-nts-Win32-vs16-x64.zip. This is a catastrophic error, exiting. Contact support.") | out-file $log -Append 
        $_ | out-file $log -Append 
        Exit
    }

# Extract PHP Architect to C:\PHP
    try {
        Expand-Archive -Path ("c:\temp\php-" + $latestPhp[$latestPhp.count-1] + "-nts-Win32-vs16-x64.zip") -DestinationPath "C:\PHP"
        ("Extracted php-" + $latestPhp[$latestPhp.count-1] + "-nts-Win32-vs16-x64.zip to c:\PHP") | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        ("Failed to extract php-" + $latestPhp[$latestPhp.count-1] + "-nts-Win32-vs16-x64.zip to c:\PHP. This is a catastrophic error, exiting. Contact support.") | out-file $log -Append 
        $_ | out-file $log -Append
        Exit
    }

# Get the latest version of PHP Manager
    try {
        $urlTag = "https://github.com/phpmanager/phpmanager/tags"
        $versions = (Invoke-WebRequest $urlTag -UseBasicParsing).Content | Select-String -Pattern "Link--primary.*v\d+\.\d+"
        $latestVersion = "https://github.com/phpmanager/phpmanager/releases/download/" + ($versions.Matches.Value -split ">")[1] + "/PHPManagerForIIS_x64.msi"
        ("Collected latest php manager version, " + ($versions.Matches.Value -split ">")[1]) | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        "Failed to collect latest php manager version. This is a catastrophic error, exiting. Contact support." | out-file $log -Append 
        $_ | out-file $log -Append
        Exit
    }

# Download the latest version of PHP Manager
    try {
        Invoke-WebRequest -Uri $latestVersion -OutFile "c:\temp\PHPManagerForIIS_x64.msi" -UseBasicParsing
        "Downloaded, c:\temp\PHPManagerForIIS_x64.msi." | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        "Failed to download, c:\temp\PHPManagerForIIS_x64.msi. This is a catastrophic error, exiting. Contact support." | out-file $log -Append 
        $_ | out-file $log -Append
        Exit
    }

# Install PHP Manager
    try {
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i c:\temp\PHPManagerForIIS_x64.msi /quiet" -Wait
        "Installed PHPManagerForIIS_x64.msi" | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        "Failed to install PHPManagerForIIS_x64.msi. This is a catastrophic error, exiting. Contact support." | out-file $log -Append 
        $_ | out-file $log -Append 
        Exit
    }

# Add PHP Manager Snapin
    try {
        Add-PsSnapin PHPManagerSnapin
        "Added PHPManager Snapin" | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        "Failed to add PHPManager Snapin. " | out-file $log -Append 
        $_ | out-file $log -Append 
    }

# Register PHP
    try {
        New-PHPVersion -ScriptProcessor "C:\PHP\php-cgi.exe"
        ("Registered PHP") | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        ("Failed to register PHP. ") | out-file $log -Append 
        $_ | out-file $log -Append 
    }

# Download VC15 or VS16 (Visual Studio 2017 or 2019 compiler respectively) 64-bit installer.
    try {
        $urlVc64 = "https://aka.ms/vs/16/release/VC_redist.x64.exe"
        Invoke-WebRequest -Uri $urlVc64 -OutFile ("c:\temp\VC_redist.x64.exe") -UseBasicParsing
        ("Downloaded VC_redist.x64.exe") | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        ("Failed to download VC_redist.x64.exe. ") | out-file $log -Append 
        $_ | out-file $log -Append 
    }

# Download VC15 or VS16 (Visual Studio 2017 or 2019 compiler respectively) 32-bit installer.
    try {
        $urlVc86 = "https://aka.ms/vs/16/release/VC_redist.x86.exe"
        Invoke-WebRequest -Uri $urlVc86 -OutFile ("c:\temp\VC_redist.x86.exe") -UseBasicParsing
        ("Downloaded VC_redist.x86.exe") | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        ("Failed to download VC_redist.x86.exe. ") | out-file $log -Append 
        $_ | out-file $log -Append 
    }

# Install VC15 or VS16 (Visual Studio 2017 or 2019 compiler respectively) 64-bit installer.
    try {
        Start-Process -FilePath "c:\temp\VC_redist.x64.exe" -ArgumentList '/quiet', '/norestart' -Wait -NoNewWindow
        ("Installed VC_redist.x64.exe") | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        ("Failed to install VC_redist.x64.exe. ") | out-file $log -Append
        $_ | out-file $log -Append 
    }

# Install VC15 or VS16 (Visual Studio 2017 or 2019 compiler respectively) 32-bit installer.
    try {
        Start-Process -FilePath "c:\temp\VC_redist.x86.exe" -ArgumentList '/quiet', '/norestart' -Wait -NoNewWindow
        ("Installed VC_redist.x86.exe") | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        ("Failed to install VC_redist.x86.exe. ") | out-file $log -Append 
        $_ | out-file $log -Append 
    }

<#***************************************************
            Configure IIS and PHP
***************************************************#>

# Update PHP INI to increase upload file size
    try {
        $contentPhp = Get-Content "c:\PHP\php.ini"
        $updatedContentPhp = $contentPhp.Replace("upload_max_filesize = 2M","upload_max_filesize = 2048M")
        $updatedContentPhp = $updatedContentPhp.Replace("post_max_size = 8M","post_max_size = 2048M")
        $updatedContentPhp = $updatedContentPhp.Replace("memory_limit = 128M","memory_limit = 2048M")
        $updatedContentPhp | Out-File "c:\PHP\php.ini"
        ("Updated php.ini" ) | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        ("Failed to update php.ini. " ) | out-file $log -Append 
        $_ | out-file $log -Append 
    }

# Register PHP, reloads settings following update to ini file
    try {
        New-PHPVersion -ScriptProcessor "C:\PHP\php-cgi.exe"
        ("Register PHP, reloads settings following update to ini file") | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        ("Failed to register PHP, reloads settings following update to ini file. ") | out-file $log -Append 
        $_ | out-file $log -Append 
    }

# Update IIS Web Server Request Filtering limits to increase upload file size
    try {
        $ConfigSection = Get-IISConfigSection -SectionPath "system.webServer/security/requestFiltering"
        $Elem = Get-IISConfigElement -ConfigElement $ConfigSection -ChildElementName "requestLimits"
        ("Collected Web Server IIS Config requestLimits element") | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        ("Failed to collect Web Server IIS Config requestLimits element.") | out-file $log -Append 
        $_ | out-file $log -Append 
    }

# Save IIS Web Server Config
    try {
        Set-IISConfigAttributeValue -ConfigElement $Elem -AttributeName "maxAllowedContentLength" -AttributeValue 4294967295
        ("Updated Web Server maxAllowedContentLength to 4294967295") | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        ("Failed to update Web Server maxAllowedContentLength to 4294967295.") | out-file $log -Append 
        $_ | out-file $log -Append 
    }

# Update IIS Default Web Site Request Filtering limits to increase upload file size
    try {
        $ConfigSection = Get-IISConfigSection -CommitPath 'Default Web Site' -SectionPath "system.webServer/security/requestFiltering"
        $Elem = Get-IISConfigElement -ConfigElement $ConfigSection -ChildElementName "requestLimits"
        ("Collected Default Web Site IIS Config requestLimits element") | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        ("Failed to collect Default Web Site IIS Config requestLimits element. ") | out-file $log -Append 
        $_ | out-file $log -Append 
    }

# Save IIS Default Web Site Config
    try {
        Set-IISConfigAttributeValue -ConfigElement $Elem -AttributeName "maxAllowedContentLength" -AttributeValue 4294967295
        ("Updated Default Web Site maxAllowedContentLength to 4294967295") | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        ("Failed to update Default Web Site maxAllowedContentLength to 4294967295.") | out-file $log -Append 
        $_ | out-file $log -Append 
    }

<#***************************************************
                     Install Git
***************************************************#>

# Get the latest version of Git
    try {
        $urlTag = "https://github.com/git-for-windows/git/tags"
        $versions = (Invoke-WebRequest $urlTag -UseBasicParsing).Content | Select-String -Pattern "Link--primary.*v\d+\.\d+.\d+.\windows.\d+"
        $latestVersion = "https://github.com/git-for-windows/git/releases/download/" + ($versions.Matches.Value -split ">")[1] + "/Git-" + ((($versions.Matches.Value -split ">")[1]) -split ".windows")[0].replace("v","") + "-64-bit.exe"
        ("Collected latest git version, " + ((($versions.Matches.Value -split ">")[1]) -split ".windows")[0].replace("v","")) | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        ("Failed to collect latest git version. ") | out-file $log -Append 
        $_ | out-file $log -Append 
    }

# Download the latest version of Git
    try {
        $localVersion = ("c:\temp\Git-" + ((($versions.Matches.Value -split ">")[1]) -split ".windows")[0].replace("v","") + "-64-bit.exe")
        Invoke-WebRequest -Uri $latestVersion -OutFile $localVersion -UseBasicParsing
        ("Downloaded " + $localVersion) | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        ("Failed to download git version. ") | out-file $log -Append 
        $_ | out-file $log -Append 
    }

# Install latest version of git 64-bit.
    try {
        Start-Process -FilePath $localVersion -ArgumentList '/verysilent', '/suppressmsgboxes', '/norestart' -Wait -NoNewWindow
        ("Installed, " + $localVersion) | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        ("Failed to install latest git version. ") | out-file $log -Append 
        $_ | out-file $log -Append 
    }

# Reload Path
    try {
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") 
        "Reloaded PATH" | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        "Failed to reload PATH" | out-file $log -Append 
        $_ | out-file $log -Append 
    }

<#***************************************************
            Deploy & configure Web App
***************************************************#>

# Deploy website from Git Repo to C:\inetpub\wwwroot\
    try { 
        git config --global --add safe.directory C:/inetpub/wwwroot
        cd C:\inetpub\wwwroot\
        git init
        git remote add main https://github.com/TrainingExample/IncidentManagement.git
        git fetch
        git checkout -t main/main
        ("Deployed git repo. ") | out-file $log -Append 
    }
    catch {
        ("Failed to deploy git repo. ") | out-file $log -Append 
        $_ | out-file $log -Append 

    }

<#***************************************************
            Connect to ASE Azure Files
***************************************************#>
# This is not a function because its only two drives, if this expands - it would make sense to update to a function

# Map ASE Upload Folder to s drive 
    try {
        New-PSDrive -Name "u" -Root ("\\" + $hostFileShare + "\" + $uploadFolder) -Persist -PSProvider "FileSystem" -Credential $userCredentials -Scope Global | out-file $log -Append 
        ("Mapped \\" + $hostFileShare + "\" + $uploadFolder) | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        ("Failed to map \\" + $hostFileShare + "\" + $uploadFolder + ". ") | out-file $log -Append 
        $_ | out-file $log -Append 
    }

# Map ASE Download Folder to t drive 
    try {
        New-PSDrive -Name "r" -Root ("\\" + $hostFileShare + "\" + $downloadFolder) -Persist -PSProvider "FileSystem" -Credential $userCredentials -Scope Global | out-file $log -Append 
        ("Mapped \\" + $hostFileShare + "\" + $downloadFolder) | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        ("Failed to map \\" + $hostFileShare + "\" + $downloadFolder + ". ") | out-file $log -Append 
        $_ | out-file $log -Append 
    }

# Create sym link to connect download mapped drive to C:\inetpub\wwwroot\report
    try {
        New-Item -ItemType SymbolicLink -Path ("C:\inetpub\wwwroot\report") -Target r:\
        ("Created symbolic link from C:\inetpub\wwwroot\download to t:\ drive") | out-file $log -Append 
        start-sleep -s 5
    }
    catch {
        ("Failed to create symbolic link from C:\inetpub\wwwroot\download to t:\ drive") | out-file $log -Append 
        $_ | out-file $log -Append 
    }

<#***************************************************
            Create Project File
***************************************************#>

# Create project file
    $projectFileStatus = Get-Item ("C:\inetpub\wwwroot\" + $projectFile) -ErrorAction SilentlyContinue
    if (!$projectFileStatus) {
        try {
            New-Item -ItemType File -Path ("C:\inetpub\wwwroot\" + $projectFile)
            ("Created C:\inetpub\wwwroot\" + $projectFile) | out-file $log -Append 
            start-sleep -s 5
        }
        catch {
            ("Failed to create C:\inetpub\wwwroot\" + $projectFile) | out-file $log -Append 
            $_ | out-file $log -Append 
        }
    }

# Get name of most recently edited subfolder witin the download folder and update project file to use
    $downloadFolderList = Get-ChildItem -Directory -Path t:\
    $downloadFolder = $downloadFolderList | Sort-Object -Property LastWriteTime
    ("download/" + $downloadFolder[1].name) | Out-File ("C:\inetpub\wwwroot\" + $projectFile) -Encoding ascii

<#***************************************************
            Create Status File
***************************************************#>

# Create status file
    $statusFileStatus = Get-Item ("C:\inetpub\wwwroot\" + $projectFile) -ErrorAction SilentlyContinue
    if (!$statusFileStatus) {
        try {
            New-Item -ItemType File -Path ("C:\inetpub\wwwroot\" + $statusFile)
            $statusInput | Out-File ("C:\inetpub\wwwroot\" + $statusFile) -Encoding ascii
            ("Created C:\inetpub\wwwroot\" + $statusFile) | out-file $log -Append 
            start-sleep -s 5
        }
        catch {
            ("Failed to create C:\inetpub\wwwroot\" + $statusFile) | out-file $log -Append 
            $_ | out-file $log -Append 
        }
    }

<#***************************************************
        Update file and folder permissions
***************************************************#>

# Update permissions on project file for BUILT-IN\Users
try {
    $ACL = Get-ACL -Path ("C:\inetpub\wwwroot\" + $projectFile)
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users","Modify","Allow")
    $ACL.SetAccessRule($AccessRule)
    $ACL | Set-Acl -Path ("C:\inetpub\wwwroot\" + $projectFile)
    ("Updated permissions on upload folder for BUILT-IN\Users on " + $projectFile) | out-file $log -Append 
    start-sleep -s 5
}
catch {
    $_ | out-file $log -Append 
}

# Update permissions on project file for BUILT-IN\IIS_IUSRS
try {
    $ACL = Get-ACL -Path ("C:\inetpub\wwwroot\" + $projectFile)
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS","Modify","Allow")
    $ACL.SetAccessRule($AccessRule)
    $ACL | Set-Acl -Path ("C:\inetpub\wwwroot\" + $projectFile)
    ("Updated permissions on upload folder for BUILT-IN\IIS_IUSRS on " + $projectFile) | out-file $log -Append 
}
catch {
    $_ | out-file $log -Append 
}