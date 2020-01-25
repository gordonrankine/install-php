#region ScriptInfo

<#

.SYNOPSIS
Installs PHP on Windows Server.

.DESCRIPTION
This script installs the Web Server, Web CGI & IIS management tools roles, installs and configures PHP including the wincache dll, configures IIS for PHP and creates
a index.php file preconfigured with phpinfo().

.PARAMETER bldPkg
This is the full path to the build package zip file that contains the files needed to install PHP and associated components.

.EXAMPLE
.\Install-PHP.ps1 -bldPkg "C:\Build\Build7.4x64.zip"
Installs PHP from the files located in Build7.4x64.zip

.LINK
https://github.com/gordonrankine/install-php

.NOTES
License:            MIT License
Compatibility:      Server 2016 & 2019
Author:             Gordon Rankine
Date:               25/01/2020
Version:            1.1
PSSscriptAnalyzer:  Pass.
Change History:     Version  Date        Author          Details
                    1.0      02/01/2020  Gordon Rankine  Initial script.
                    1.1      25/01/2020  Gordon Rankine  Removed information about WinCache still being in development.

#>

#endregion ScriptInfo

#region Bindings
[cmdletbinding()]

Param(

    [Parameter(Mandatory=$True, Position=1, HelpMessage="This is the full path to the build package. E.G. c:\Build\Build7.4x64.zip.")]
    [string]$bldPkg

)
#endregion Bindings

#region Functions
function fnCreateDir {

<#

.SYNOPSIS
Creates a directory.

.DESCRIPTION
Creates a directory.

.PARAMETER outDir
This is the directory to be created.

.EXAMPLE
.\Create-Directory.ps1 -outDir "c:\test"
Creates a directory called "test" in c:\

.EXAMPLE
.\Create-Directory.ps1 -outDir "\\COMP01\c$\test"
Creates a directory called "test" in c:\ on COMP01

.LINK
https://github.com/gordonrankine/powershell

.NOTES
    License:            MIT License
    Compatibility:      Windows 7 or Server 2008 and higher
    Author:             Gordon Rankine
    Date:               13/01/2019
    Version:            1.1
    PSSscriptAnalyzer:  Pass

#>

    [CmdletBinding()]

        Param(

        # The directory to be created.
        [Parameter(Mandatory=$True, Position=0, HelpMessage='This is the directory to be created. E.g. C:\Temp')]
        [string]$outDir

        )

        # Create out directory if it doesnt exist
        if(!(Test-Path -path $outDir)){
            if(($outDir -notlike "*:\*") -and ($outDir -notlike "*\\*")){
            Write-Output "[ERROR]: $outDir is not a valid path. Script terminated."
            break
            }
                try{
                New-Item $outDir -type directory -Force -ErrorAction Stop | Out-Null
                Write-Output "[INFO] Created output directory $outDir"
                }
                catch{
                Write-Output "[ERROR]: There was an issue creating $outDir. Script terminated."
                Write-Output ($_.Exception.Message)
                Write-Output ""
                break
                }
        }
        # Directory already exists
        else{
        Write-Output "[INFO] $outDir already exists."
        }

} # end fnCreateDir

function fnCheckPSAdmin {

<#

.SYNOPSIS
Checks PowerShell is running as Administrator.

.DESCRIPTION
Checks PowerShell is running as Administrator.

.LINK
https://github.com/gordonrankine/powershell

.NOTES
    License:            MIT License
    Compatibility:      Windows 7 or Server 2008 and higher
    Author:             Gordon Rankine
    Date:               19/09/2019
    Version:            1.0
    PSSscriptAnalyzer:  Pass

#>

    try{
    $wIdCurrent = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $wPrinCurrent = New-Object System.Security.Principal.WindowsPrincipal($wIdCurrent)
    $wBdminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

        if(!$wPrinCurrent.IsInRole($wBdminRole)){
        Write-Output "[ERROR] PowerShell is not running as administrator. Script terminated."
        Break
        }

    }

    catch{
    Write-Output "[ERROR] There was an unexpected error checking if PowerShell is running as administrator. Script terminated."
    Break
    }

} # end fnCheckPSAdmin
#endregion Functions

#region PreChecks
Clear-Host

# Start stopwatch
$sw = [system.diagnostics.stopwatch]::StartNew()

# Check script is running as administrator
fnCheckPSAdmin

    # Verify build package exists
    if(!(Test-Path $bldPkg -Include *.zip)){
    Write-Output "[ERROR] Build package $bldPkg was  not found. Script terminated."
    Break
    }
    else{
    Write-Output "[INFO] Build package $bldPkg found."
    }

    # Extract Build Package
    try{
    $bldFolder = (Split-Path $bldPkg -Leaf -ErrorAction SilentlyContinue) -replace ".zip", ""
    $bldDir = (Split-Path $bldPkg -Parent -ErrorAction SilentlyContinue) + "\" + $bldFolder
    Write-Output "[INFO] Extracting $bldPkg to $bldDir"
    Expand-Archive -LiteralPath $bldpKg -DestinationPath $bldDir -Force -ErrorAction SilentlyContinue
    Write-Output "[INFO] Extracted $bldPkg to $bldDir"
    }
    catch{
    Write-Output "[ERROR] Extraction of the build package failed. Script terminated."
    Write-Output "[ERROR] $($_.exception.message)"
    Break
    }

    # Verify xml report file exists
    if(!(Test-Path "$bldDir\Config.xml" -Include *.xml)){
    Write-Output "[ERROR] Configuration xml file $bldDir\Config.xml was not found. Script terminated."
    Break
    }
    else{
    Write-Output "[INFO] Configuration xml file $bldDir\Config.xml found."
    }

    # Read config xml file
    try{
    Write-Output "[INFO] Reading contents of $bldDir\Config.xml."
    [xml]$xml = Get-Content -Path "$bldDir\Config.xml" -ErrorAction SilentlyContinue
    }
    catch{
    Write-Output "[ERROR] Unable to open $bldDir\Config.xml. Script terminated."
    Write-Output "[ERROR] $($_.exception.message)"
    Break
    }

    # Verify config is valid. Each config item
    if(!($xml.info.server.supported_version)){
    Write-Output "[ERROR] Xml file missing parameter: server/supported_version. Script terminated."
    }
    if(!($xml.info.php.version)){
    Write-Output "[ERROR] Xml file missing parameter: php/version. Script terminated."
    Break
    }
    if(!($xml.info.php.filename)){
    Write-Output "[ERROR] Xml file missing parameter: php/filename. Script terminated."
    Break
    }
    if(!($xml.info.php.sha256)){
    Write-Output "[ERROR] Xml file missing parameter: php/sha256. Script terminated."
    Break
    }
    if(!($xml.info.php.install_directory)){
    Write-Output "[ERROR] Xml file missing parameter: php/install_directory. Script terminated."
    Break
    }
    if(!($xml.info.php.php_ini)){
    Write-Output "[ERROR] Xml file missing parameter: php/php_ini. Script terminated."
    Break
    }
    if(!($xml.info.php.php_ini_sha256)){
    Write-Output "[ERROR] Xml file missing parameter: php/php_ini_256. Script terminated."
    Break
    }
    if(!($xml.info.wincache.version)){
    Write-Output "[ERROR] Xml file missing parameter: wincache/version. Script terminated."
    Break
    }
    if(!($xml.info.wincache.filename)){
    Write-Output "[ERROR] Xml file missing parameter: wincache/filename. Script terminated."
    Break
    }
    if(!($xml.info.wincache.sha256)){
    Write-Output "[ERROR] Xml file missing parameter: wincache/sha256. Script terminated."
    Break
    }
    if(!($xml.info.vc_redist_x64.version)){
    Write-Output "[ERROR] Xml file missing parameter: vc_redist_x64/version. Script terminated."
    Break
    }
    if(!($xml.info.vc_redist_x64.filename)){
    Write-Output "[ERROR] Xml file missing parameter: vc_redist_x64/filename. Script terminated."
    Break
    }
    if(!($xml.info.vc_redist_x64.sha256)){
    Write-Output "[ERROR] Xml file missing parameter: vc_redist_x64/sha256. Script terminated."
    Break
    }
    if(!($xml.info.vc_redist_x64.display_name)){
    Write-Output "[ERROR] Xml file missing parameter: vc_redist_x64/display_name. Script terminated."
    Break
    }
    if(!($xml.info.iis.del_default_site)){
    Write-Output "[ERROR] Xml file missing parameter: iis/del_default_site. Script terminated."
    Break
    }
    if(!($xml.info.iis.site_name)){
    Write-Output "[ERROR] Xml file missing parameter: iis/site_name. Script terminated."
    Break
    }
    if(!($xml.info.iis.site_path)){
    Write-Output "[ERROR] Xml file missing parameter: iis/site_path. Script terminated."
    Break
    }

    # Get Server OS
    try{
    Write-Output "[INFO] Getting Operating System details from registry."
    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $endpoint)
    $key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
    $openSubKey = $reg.OpenSubKey($key)
    Write-Output "[INFO] Operating System is $($openSubKey.getvalue("ProductName"))."

        # Check if supported OS
        if($openSubKey.getvalue("ProductName") -like "*$(($xml.info.server.supported_version))*"){
        Write-Output "[INFO] Operarting System is supported."
        }
        else{
        Write-Output "[ERROR] Operarting System is not supported. Script terminated."
        Break
        }

    }
    catch{
    Write-Output "[ERROR] Unable to get Operating System details from registry. Script terminated."
    Break
    }

    # Check PHP File Exists
    if(!(Test-Path $bldDir\$($xml.info.php.filename))){
    Write-Output "[ERROR] $($xml.info.php.filename) was not found in $bldDir. Script terminated."
    Break
    }
    else{
    Write-Output "[INFO] $($xml.info.php.filename) present."
    }

    # Verify PHP Hash
    try{
    $hash = (Get-FileHash -Path $bldDir\$($xml.info.php.filename) -Algorithm SHA256 -ErrorAction SilentlyContinue).hash

        if($xml.info.php.sha256 -eq $hash){
        Write-Output "[INFO] $($xml.info.php.filename) file hash verified."
        }
        else{
        Write-Output "[ERROR] $($xml.info.php.filename) file hash check failed. Script terminated."
        Break
        }

    }
    catch{
    Write-Output "[ERROR] Unable to get file hash of $($xml.info.php.filename). Script terminated."
    Write-Output "[ERROR] $($_.exception.message)"
    Break
    }

    # Check PHP.ini Exists
    if(!(Test-Path $bldDir\$($xml.info.php.php_ini))){
    Write-Output "[ERROR] $($xml.info.php.php_ini) was not found in $bldDir. Script terminated."
    Break
    }
    else{
    Write-Output "[INFO] $($xml.info.php.php_ini) present."
    }

    # Verify PHP.ini Hash
    try{
    $hash = (Get-FileHash -Path $bldDir\$($xml.info.php.php_ini) -Algorithm SHA256 -ErrorAction SilentlyContinue).hash

        if($xml.info.php.php_ini_sha256 -eq $hash){
        Write-Output "[INFO] $($xml.info.php.php_ini) file hash verified."
        }
        else{
        Write-Output "[ERROR] $($xml.info.php.php_ini) file hash check failed. Script terminated."
        Break
        }

    }
    catch{
    Write-Output "[ERROR] Unable to get file hash of $($xml.info.php.php_ini). Script terminated."
    Write-Output "[ERROR] $($_.exception.message)"
    Break
    }

    # Check WinCache File Exists
    if(!(Test-Path $bldDir\$($xml.info.wincache.filename))){
    Write-Output "[ERROR] $($xml.info.wincache.filename) was not found in $bldDir. Script terminated."
    Break
    }
    else{
    Write-Output "[INFO] $($xml.info.wincache.filename) present."
    }

    # Verify WinCache Hash
    try{
    $hash = (Get-FileHash -Path $bldDir\$($xml.info.wincache.filename) -Algorithm SHA256 -ErrorAction SilentlyContinue).hash

        if($xml.info.wincache.sha256 -eq $hash){
        Write-Output "[INFO] $($xml.info.wincache.filename) file hash verified."
        }
        else{
        Write-Output "[ERROR] $($xml.info.wincache.filename) file hash check failed. Script terminated."
        Break
        }

    }
    catch{
    Write-Output "[ERROR] Unable to get file hash of $($xml.info.wincache.filename). Script terminated."
    Write-Output "[ERROR] $($_.exception.message)"
    Break
    }

    # Check VC Redist x64 File Exists
    if(!(Test-Path $bldDir\$($xml.info.vc_redist_x64.filename))){
    Write-Output "[ERROR] $($xml.info.vc_redist_x64.filename) was not found in $bldDir. Script terminated."
    Break
    }
    else{
    Write-Output "[INFO] $($xml.info.vc_redist_x64.filename) present."
    }

    # Verify VC Redist x64 Hash
    try{
    $hash = (Get-FileHash -Path $bldDir\$($xml.info.vc_redist_x64.filename) -Algorithm SHA256 -ErrorAction SilentlyContinue).hash

        if($xml.info.vc_redist_x64.sha256 -eq $hash){
        Write-Output "[INFO] $($xml.info.vc_redist_x64.filename) file hash verified."
        }
        else{
        Write-Output "[ERROR] $($xml.info.vc_redist_x64.filename) file hash check failed. Script terminated."
        Break
        }

    }
    catch{
    Write-Output "[ERROR] Unable to get file hash of $($xml.info.vc_redist_x64.filename). Script terminated."
    Write-Output "[ERROR] $($_.exception.message)"
    Break
    }
#endregion PreChecks

#region InstallRoles
    # Install Web Server Roles
    try{

    $reboot = "No"

    Write-Output "[INFO] Installing Web-Server, Web-CGI & Management Tools roles."
    $installRoles = Install-WindowsFeature -Name Web-Server, Web-CGI -IncludeManagementTools -Restart:$false -ErrorAction SilentlyContinue

        # Success Code not True
        if($installRoles.Success -ne $true){
        Write-Output "[ERROR] There was a non success code while installing the required roles. Script terminated."
        Break
        }

        # Restart required
        if($installRoles.RestartNeeded -eq 'Yes'){
        Write-Output "[WARNING] Server will need a restart to complete installation. Skipping reboot until the end."
        $reboot = "Yes"
        }

    Write-Output "[INFO] Installed Web-Server, Web-CGI & Management Tools roles."

    }
    catch{
    Write-Output "[ERROR] There was an error installing the required roles. Script terminated."
    Break
    }

#endregion InstallRoles

#region Install&ConfigurePHP

    # Extract PHP
    try{
    Write-Output "[INFO] Extracting $($xml.info.php.filename) to $($xml.info.php.install_directory)"
    Expand-Archive -LiteralPath $bldDir\$($xml.info.php.filename) -DestinationPath $($xml.info.php.install_directory) -Force -ErrorAction SilentlyContinue
    Write-Output "[INFO] Extracted $($xml.info.php.filename) to $($xml.info.php.install_directory)"
    }
    catch{
    Write-Output "[ERROR] Extraction of PHP zip file failed. Script terminated."
    Write-Output "[ERROR] $($_.exception.message)"
    Break
    }

    # Copy PHP.ini
    try{
    Write-Output "[INFO] Copying php.ini file to $($xml.info.php.install_directory)"
    Copy-Item -LiteralPath $bldDir\$($xml.info.php.php_ini) -Destination "$($xml.info.php.install_directory)\php.ini" -Force -ErrorAction SilentlyContinue
    Write-Output "[INFO] Copied php.ini file to $($xml.info.php.install_directory)"
    }
    catch{
    Write-Output "[ERROR] Copying PHP.ini failed. Script terminated."
    Write-Output "[ERROR] $($_.exception.message)"
    Break
    }

# Set extension_dir in php.ini
$date = (Get-Date -Format (Get-culture).DateTimeFormat.ShortDatePattern)
$user = $env:USERDOMAIN +"\"+ $env:USERNAME
$script = $MyInvocation.MyCommand.Name
$a = "extension_dir = `"<<ToBeReplacedByScript>>`""
$b = "; Modified on $date by $user using $script`r`nextension_dir = `"$($xml.info.php.install_directory)\ext`""

    # Search php.ini for extension_dir
    if(Select-String -Path "$($xml.info.php.install_directory)\php.ini" -Pattern $a -ErrorAction SilentlyContinue){
    Write-Output "[INFO] PHP.ini extension_dir parameter needs configured."

        try{
        Write-Output "[INFO] Configuring extension_dir in PHP.ini."
        (Get-Content -path $($xml.info.php.install_directory + "\php.ini") -Raw -Force -ErrorAction SilentlyContinue) -replace $a, $b | Set-Content -Path $($xml.info.php.install_directory + "\php.ini") -Force -ErrorAction SilentlyContinue
        Write-Output "[INFO] Configured extension_dir in PHP.ini."
        }
        catch{
        Write-Output "[ERROR] Configuring extension_dir in PHP.ini failed. Script terminated."
        Write-Output "[ERROR] $($_.exception.message)"
        Break
        }

    }
    else{
    Write-Output "[INFO] PHP.ini extension_dir parameter already configured."
    }

    # Configure Environmental Variable Path
    try{
    Write-Output "[INFO] Adding $($xml.info.php.install_directory) to the path environmental variable."
    $curPath = (Get-Itemproperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name Path -ErrorAction SilentlyContinue).Path

        # If value is already there then skip otherwise set variable
        if($curPath -like "*$($xml.info.php.install_directory)"){
        Write-Output "[INFO] $($xml.info.php.install_directory) already exists in the path environmental variable."
        }
        else{
        $newPath = $curPath + ";" + $($xml.info.php.install_directory)
        Set-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name Path -Value $newPath
        Write-Output "[INFO] Added $($xml.info.php.install_directory) to the path environmental variable."
        }

    }
    catch{
    Write-Output "[ERROR] Unable to add to the path environmental variable. Script terminated."
    Write-Output "[ERROR] $($_.exception.message)"
    Break
    }

    # Copy WinCache DLL
    try{
    Write-Output "[INFO] Copying $bldDir\$($xml.info.wincache.filename) to $($xml.info.php.install_directory)"
    Copy-Item -LiteralPath $bldDir\$($xml.info.wincache.filename) -Destination "$($xml.info.php.install_directory)\Ext" -Force -ErrorAction SilentlyContinue
    Write-Output "[INFO] Copied $bldDir\$($xml.info.wincache.filename) to $($xml.info.php.install_directory)"
    }
    catch{
    Write-Output "[ERROR] Unable to copy $($xml.info.wincache.filename) to $($xml.info.php.install_directory)\Ext. Script terminated."
    Write-Output "[ERROR] $($_.exception.message)"
    Break
    }
#endregion Install&ConfigurePHP

#region ConfigureIIS
# Create IIS data folder
fnCreateDir ($($xml.info.iis.site_path) + "\" + $($xml.info.iis.site_name))

    # Delete IIS default site, if requested in config file
    if($xml.info.iis.del_default_site -eq 'Yes'){

        try{
        Write-Output "[INFO] Deleting IIS Default Website."
        Remove-Website -Name "Default Web Site" -ErrorAction SilentlyContinue
        Write-Output "[INFO] Deleted IIS Default Website."
        }
        catch{
        Write-Output "[ERROR] Unable to delete IIS default website. Script terminated."
        Write-Output "[ERROR] $($_.exception.message)"
        Break
        }

    }

    # Create new IIS site
    try{
    Write-Output "[INFO] Creating IIS Website $($xml.info.iis.site_name)."
    [void](New-Website -Name $($xml.info.iis.site_name) -PhysicalPath $($xml.info.iis.site_path) -Force -ErrorAction SilentlyContinue)
    Write-Output "[INFO] Created IIS Website $($xml.info.iis.site_name)."
    }
    catch{
    Write-Output "[ERROR] Unable to create IIS website $($xml.info.iis.site_name). Script terminated."
    Write-Output "[ERROR] $($_.exception.message)"
    Break
    }

    # IIS: Unlock global config (config editor > system.webServer/handlers)
    try{
    Write-Output "[INFO] Unlocking IIS path at parent level."
    Set-WebConfiguration //System.webServer/handlers -metadata overrideMode -value Allow -PSPath IIS:/ -Force -ErrorAction SilentlyContinue
    Write-Output "[INFO] Unlocked IIS path at parent level."
    }
    catch{
    Write-Output "[ERROR] Unable to unlock IIS path at parent level. Script terminated."
    Write-Output "[ERROR] $($_.exception.message)"
    Break
    }

    # Compose Web Handler name then create
    $wHname = "PHP $($xml.info.php.version)" -replace " ", ""
    $wHScriptProc = "$($xml.info.php.install_directory)\php-cgi.exe"

        # If Web Handler doesn't exist
        if(!(Get-WebHandler -Name $wHname -PSPath "IIS:\Sites\$($xml.info.iis.site_name)")){

            # Create New Web Handler
            try{
            Write-Output "[INFO] Creating IIS Web Handler for PHP."

            # When using New-WebHandler cmdlet, the Web Handler was being created successfully but a php page would not load, the following error would appear.
            # HTTP Error 500.21 - Internal Server Error
            # Handler "PHP7.4.1NTSx64" has a bad module "FastCGIModule" in its module list
            # If the Web Handler was created manually via the IIS GUI php would work.
            # Leaving command used for reference.
            #New-WebHandler -Name $wHname -Verb * -Path *.php -Modules FastCGIModule -ScriptProcessor $wHScriptProc -PSPath "IIS:\Sites\$($xml.info.iis.site_name)" -ResourceType Either -RequiredAccess Script -Force -ErrorAction SilentlyContinue

            Add-WebConfiguration "System.WebServer/Handlers" -PSPath "IIS:\Sites\$($xml.info.iis.site_name)" -Value @{
                Name = $wHname;
                Path = "*.php";
                Verb = "*";
                Modules = "FastCgiModule";
                ScriptProcessor=$wHScriptProc;
                ResourceType='Either';
                RequireAccess='Script'
                } -Force -ErrorAction SilentlyContinue

            Write-Output "[INFO] Created IIS Web Handler for PHP."
            }
            catch{
            Write-Output "[ERROR] Unable to create Web Handler for PHP in IIS. Script terminated."
            Write-Output "[ERROR] $($_.exception.message)"
            Break
            }

        }
        else{
        Write-Output "[INFO] IIS Web Handler for PHP already exists."
        }

    # Create FastCgi application. If app doesn't exist, create it
    if(!(Get-WebConfiguration "System.WebServer/FastCgi/Application" -ErrorAction SilentlyContinue | Where-Object {$_.fullPath -eq $wHScriptProc})){

        # Add FastCgi application
        try{
        Write-Output "[INFO] Creating FastCgi application for PHP."
        Add-WebConfiguration "System.WebServer/FastCgi" -Value @{'fullPath' = $wHScriptProc} -Force -ErrorAction SilentlyContinue
        Write-Output "[INFO] Created FastCgi application for PHP."
        }
        catch{
        Write-Output "[ERROR] Unable to create FastCgi application for PHP in IIS. Script terminated."
        Write-Output "[ERROR] $($_.exception.message)"
        Break
        }

    }
    else{
    Write-Output "[INFO] FastCgi Application for PHP already exists."
    }

    # NOT NEEDED AS WILL STOP IIS WORKING (as message below).
    # Error 500.19
    # This configuration section cannot be used at this path. This happens when the section is locked at a parent level.
    # Locking is either by default (overrideModeDefault="Deny"), or set explicitly by a location tag with overrideMode="Deny" or the legacy allowOverride="false".
    # IIS: Lock global config (config editor > system.webServer/handlers)
    #try{
    #Write-Output "[INFO] Locking IIS path at parent level."
    #Set-WebConfiguration //System.webServer/handlers -metadata overrideMode -value Deny -PSPath IIS:/ -Force -ErrorAction SilentlyContinue
    #Write-Output "[INFO] Locked IIS path at parent level."
    #}
    #catch{
    #Write-Output "[ERROR] Unable to Lock IIS path at parent level. Script terminated."
    #Write-Output "[ERROR] $($_.exception.message)"
    #Break
    #}

    # Create index.php
    try{
    $file = $($xml.info.iis.site_path) + "\" + $($xml.info.iis.site_name) + "\index.php"
    $tab = "`t"

        if(Test-Path -PathType Leaf -path $file -ErrorAction SilentlyContinue){
        Write-Output "[INFO] File index.php already exists, deleting file."
        Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
        Write-Output "[INFO] File index.php deleted."
        }

    Write-Output "[INFO] Creating index.php file in $($xml.info.iis.site_path)"
    Add-Content $file "<?php" -Force -ErrorAction SilentlyContinue
    Add-Content $file "$tab`phpinfo();" -Force -ErrorAction SilentlyContinue
    Add-Content $file "?>" -Force -ErrorAction SilentlyContinue
    Write-Output "[INFO] Created index.php file in $($xml.info.iis.site_path)"
    }
    catch{
    Write-Output "[ERROR] Unable to delete/create index.php file. Script terminated."
    Write-Output "[ERROR] $($_.exception.message)"
    Break
    }

    # Stop/Start Website
    try{
    Write-Output "[INFO] Restarting IIS Site $($xml.info.iis.site_name)."
    Stop-Website -Name $($xml.info.iis.site_name) -ErrorAction SilentlyContinue
    Start-Website -Name $($xml.info.iis.site_name) -ErrorAction SilentlyContinue
    Write-Output "[INFO] Restarted IIS Site $($xml.info.iis.site_name)."
    }
    catch{
    Write-Output "[ERROR] Unable to Stop/Start IIS site $($xml.info.iis.site_name). Script terminated."
    Write-Output "[ERROR] $($_.exception.message)"
    Break
    }
#endregion ConfigureIIS

#region InstallVCRedist
    # Install VC Redist
    try{
    Write-Output "[INFO] Installing Visual C++ Redistributable (x64)."
    $filename = $bldDir + "\" + $($xml.info.vc_redist_x64.filename)
    Invoke-Command -ScriptBlock {Start-Process $filename -ArgumentList "/quiet /norestart" -Wait} -ErrorAction SilentlyContinue
    # No complete message as it will be displayed below once install checked.
    }
    catch{
    Write-Output "[ERROR] Unable to install Visual C++ Redistributable (x64). Script terminated."
    Write-Output "[ERROR] $($_.exception.message)"
    Break
    }

    # PowerShell doesn't handle exit codes in exe's well. So adding in a further check
    try{
    $isInstalled = "No"
    Write-Output "[INFO] Checking Visual C++ Redistributable (x64) is installed."
    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $env:COMPUTERNAME)
    $key = "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    $openSubKey = $reg.OpenSubKey($key)
    $subKeys = $openSubKey.GetSubKeyNames()

        foreach($subKey in $subKeys){

            # Set to Yes if display name is in the registry (Add/remove programs)
            if((($reg.OpenSubKey($key+"\\"+$subKey).getValue('DisplayName')) -replace ",", ";") -eq $xml.info.vc_redist_x64.display_name){
            $isInstalled = "Yes"
            }

        }

        if($isInstalled -eq 'Yes'){
        Write-Output "[INFO] Visual C++ Redistributable (x64) is installed."
        }
        else{
        Write-Output "[ERROR] Visual C++ Redistributable (x64) is not installed. Script terminated."
        Break
        }

    }
    catch{
    Write-Output "[ERROR] Unable determine if Visual C++ Redistributable (x64) is installed. Script terminated."
    Write-Output "[ERROR] $($_.exception.message)"
    Break
    }
#endregion InstallVCRedist

#region Finalise
    # If a reboot is needed.
    if($reboot -eq 'Yes'){
    Write-Output "[INFO] Script complete in $($sw.Elapsed.Hours) hours, $($sw.Elapsed.Minutes) minutes, $($sw.Elapsed.Seconds) seconds."
    Write-Output ""
    Write-Output "[WARNING] Server needs a reboot to complete configuration."
    Write-Output "[WARNING] Please reboot server then open http://localhost/$($xml.info.iis.site_name)/index.php in Internet Explorer."
    Write-Output "[WARNING] index.php should display PHP Info in Internet Explorer."
    Write-Output ""
    Break
    }
    else{
    Write-Output "[INFO] Script complete in $($sw.Elapsed.Hours) hours, $($sw.Elapsed.Minutes) minutes, $($sw.Elapsed.Seconds) seconds."
    Write-Output ""
    }

# Check PHP works
Write-Output "[INFO] Now opening Internet Explorer to check all works. You should see a PHP Info page."
Start-Process "C:\Program Files\Internet Explorer\iexplore.exe" -ArgumentList "http://localhost/$($xml.info.iis.site_name)/index.php"
#endregion Finalise