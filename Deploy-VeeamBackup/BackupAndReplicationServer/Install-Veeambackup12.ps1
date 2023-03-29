<#
    .SYNOPSIS
    Installs Veeam Backup & Replication v12 and any patches.
    Installs Veeam Backup Enterprise Manager also if chosen.

    .PARAMETER SQLEngine
    Specify SQL engine to use.
    If no engine specified, the script defualts to PostgreSQL - recommended engine by Veeam!

    .PARAMETER ISO
    Path to Veeam v12 ISO.
    If no path specified, the script will attempt to download the official ISO image from Veeam.

    .PARAMETER License
    Veeam license key file or direct URL to download the license key file. Example: 'https://url.mylicense.key/VeeamLicenseKey.lic'
    If no path nor proper URL specified, the script will default to Community Edition.

    .PARAMETER VeeamEnterpriseManager
    Install Veeam Backup Enterprise Manager (VEM) along side Veeam Backup & Replication (VBR) v12.
    Will not be installed by default

    .PARAMETER Nutanix
    Install plugins for Nutanix. Will not be installed by default

    .PARAMETER RedHat
    Install plugins for RedHat Virtualization. Will not be installed by default

    .OUTPUTS
    Every step of the script.
    This is also logged.

    .NOTES
    Name: Install-VeeamBackup12.ps1
    Author: ZuuLAutomation
    Version: 1.0

    This script was inspired by Chris Arceneaux' (https://github.com/carceneaux) Update-Veeam.ps1, found in the VeeamHub Github (https://github.com/VeeamHub/powershell/tree/master/BR-UpgradeV11)

    .LINK
    Veeam Official Unattended Cmdline Installation Guide
    https://helpcenter.veeam.com/docs/backup/vsphere/silent_mode.html?ver=120
#>
#Requires -RunAsAdministrator

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateSet('PostgreSQL_15','MSSQL_2022','MSSQL_2019','MSSQL_2017','MSSQL_2016')]
    [String]$SQLEngine,

    [Parameter(Mandatory = $false, Position = 1)]
    [String]$ISO,

    [Parameter(Mandatory = $false, Position = 2)]
    [String]$License,

    [Parameter(Mandatory = $false, Position = 3)]
    [Switch]$VeeamEnterpriseManager,

    [Parameter(Mandatory = $false, Position = 4)]
    [Switch]$Nutanix,

    [Parameter(Mandatory = $false, Position = 5)]
    [Switch]$RedHat
)

$ISOName = "VeeamBackup&Replication_12.0.0.1420_20230223.iso"
$PatchName = "veeam_backup_12.0.0.1420_CumulativePatch20230223.exe"

# -- Logging --
# Preparing logging for debug purposes.
$InstallFolder = "$env:SystemDrive\temp\VBR12-Install"
$LogFolder = $InstallFolder + "\Logs"
if ((Test-Path $LogFolder) -ne $true) {
    New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null
}
$InstallLog = "$LogFolder\VBR12-Install.log"

function Write-VBRInstallLog {
    Param(
        [Parameter()]
        [String]$LogString
    )

    $Entry = "$('[{0:MM/dd/yyyy} {0:HH:mm:ss}]' -f (Get-Date)) $LogString"
    Write-Output $Entry
    Write-Output $Entry | Out-File $InstallLog -Append
}

# -- Determine OS version --
# * Veeam v12 Platform is only supported for Windows Server 2012(R2) and newer
# * And Windows 10/11
# 'OS' under 'Backup Server' section-> https://helpcenter.veeam.com/docs/backup/vsphere/system_requirements.html?ver=120#backup_server
# Though I have chosen not to support install on Windows Server 2012(R2) as it has hit EOL (End Of Life) Support.
Write-VBRInstallLog ("Doing System configuration checks...")
$WindowsVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
if ($WindowsVersion -match "[Windows] Server 2012|2012 R2|2012R2|2016|2019|2022" -or $WindowsVersion -match "Windows 10|11") {
    # Only x64 architecture is supported! 
    if ((Get-CimInstance -ClassName Win32_OperatingSystem).OSArchitecture -notmatch "64[-bit]" ) {
        Write-VBRInstallLog (">> Windows is not running x64 (64-bit) version. Veeam Backup Server v12 is only supported on x64 (64-bit) systems!")
        Exit 1
    }
    else {
        if ($WindowsVersion -match "[Windows] Server 2012|2012 R2|2012R2") {
            Write-VBRInstallLog (">> Windows is running Server 2012(R2). The script does not support this, as it has hit EOL (End Of Life) support.")
            Write-VBRInstallLog (">> If you need Veeam Backup & Replcation on Windows Server 2012(R2) please install this manually.")
            Exit 0
        }
        elseif ($WindowsVersion -match "[Windows] Server 2022" -or $WindowsVersion -match "Windows 11") {
            $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device"
            if ((-not(Get-Item -Path $RegistryPath | Select-Object -ExpandProperty Property | Where-Object { $_ -eq "ForcedPhysicalSectorSizeInBytes" })) -or ((Get-ItemPropertyValue -Path $RegistryPath -Name "ForcedPhysicalSectorSizeInBytes") -ne '* 4095')) {
                # To install Microsoft SQL Server on Windows Server 2022 or Windows 11, a "fix" has to be deployed.
                # This is mainly a problem for installation of Microsoft SQL Server 2022, but is likely to happen on all other versions, as per Microsoft's own troubleshoot.
                # For further and more detailed information, please visit Microsoft's own troubleshooting -> https://learn.microsoft.com/en-us/troubleshoot/sql/database-engine/database-file-operations/troubleshoot-os-4kb-disk-sector-size
                $FixCmd = REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "ForcedPhysicalSectorSizeInBytes" /t REG_MULTI_SZ /d "* 4095" /f
                Write-VBRInstallLog (">> Need to deploy Microsoft SQL Server on Windows Server 2022/Windows 11, a `"fix`" for PhysicalSectorSize must deployed. This will require the system to restart.")
                Write-VBRInstallLog (">> Fix deployed. System must reboot. Please run the script after reboot.")
                Exit 1
            }
        }
    }
}

# -- Install SQL Instance --
# Depending of the SQL Engine from $SQLEngine Parameter, silenty install the SQL Engine for VBR v12 to run on.
# As per Veeam's recommended installation and default installation, default SQL Engine is PostgreSQL. Also this is the ONLY SQL installer preshipped in the VBR v12 ISO.
function Install-PostgreSQL {
    <#
        .SYNOPSIS
        Silently install PostgreSQL. Make Database uder 'postgres' NT System Authority, to avoid setting custom password

        .PARAMETER Installer
        Full path to the PostgreSQL Installer
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Installer
    )

    Write-VBRInstallLog ("Installing PostgreSQL")

    # Build PostgreSQL installation params as per Veeam's own installation
    $Params = @(
        '--mode "unattended"'
        '--unattendedmodeui "none"'
        "--superpassword `"`"" # Leaving it blank, as this will be of no use, when later pointing everything to SYSTEM Account
        '--serverport "5432"'
        "--disable-components `"pgAdmin`",`"stackbuilder`""
    )

    $Result = (Start-Process $Installer -ArgumentList $Params -Wait -PassThru).ExitCode
    
    # Exitcode 0 and/or 3010 is successful install
    if ($Result -eq 0 -or $Result -eq 3010) {
        Write-VBRInstallLog (">> Editing PostgreSQL config files to allow SYSTEM and localhost\Administrator acccess to SQL databases")
        
        # After the initial installation of PostgreSQL, we need to edit two config files pg_hba.conf and pg_ident.conf.
        # By editing these, we may map local administrator and SYSTEM to DB user 'postgres'. This bypasses the need for custom password.
        $MapName = "Veeam"
        $HBA = "$env:ProgramFiles\PostgreSQL\15\data\pg_hba.conf"
        $IDENT = "$env:ProgramFiles\PostgreSQL\15\data\pg_ident.conf"

        # Copy config files just in case something goes wrong!
        Copy-Item $HBA -Destination ($HBA + ".orig") -Force
        Copy-Item $IDENT -Destination ($IDENT + ".orig") -Force

        # Edit pg_ident.conf
        # MAPNAME  SYSTEM-USERNAME  PG-USERNAME
        # For further detail see the pg_ident.conf
        Add-Content -Path $IDENT -Value "$MapName   Administrator@$($env:COMPUTERNAME)   postgres"
        Add-Content -Path $IDENT -Value "$MapName   `"SYSTEM@NT AUTHORITY`"   postgres"

        # Edit pg_hba.conf
        # By default METHOD is 'scram-sha-256'. 
        # These lines will be replaced with 'sspi map=[mapname from pg_ident.conf]'  for authentication with SYSTEM and local adminstrator to work
        $EditHBA = foreach ($Line in Get-Content $HBA) {
            if ($Line -like "*scram-sha-256") {
                $Line -replace "scram-sha-256", "sspi map=$MapName"
            }
            else {
                # Do nothing with the line
                $Line
            }
        }

        $EditHBA | Set-Content -Path $HBA -Force
    }
}

function Install-MSSQL {
    Param(
        [Parameter()]
        [String]$SQLVersion
    )
    
    # Veeam has chosen not to package Microsoft SQL installer with their ISO, as the recommended engine is PostgreSQL.
    # Therefor the script will download the SQL installer from Microsoft's servers.
    $SQLDownloadSources = @{
        SQL2022 = "https://download.microsoft.com/download/5/1/4/5145fe04-4d30-4b85-b0d1-39533663a2f1/SQL2022-SSEI-Expr.exe"
        SQL2019 = "https://download.microsoft.com/download/7/f/8/7f8a9c43-8c8a-4f7c-9f92-83c18d96b681/SQL2019-SSEI-Expr.exe"
        SQL2017 = "https://download.microsoft.com/download/5/E/9/5E9B18CC-8FD5-467E-B5BF-BADE39C51F73/SQLServer2017-SSEI-Expr.exe"
        SQL2016 = "https://download.microsoft.com/download/f/a/8/fa83d147-63d1-449c-b22d-5fef9bd5bb46/SQLServer2016-SSEI-Expr.exe" # Service Pack 3 (SP3)
    }

    switch ($SQLVersion) {
        "MSSQL_2022" {
            $Source = $SQLDownloadSources.SQL2022
            $Exe = $InstallFolder + "\SQL2022-SSEI-Expr.exe"
            $MediaPath = $InstallFolder + "\SQL2022-Expr"
            $InstanceName = "VEEAMSQL2022"
        }
        "MSSQL_2019" {
            $Source = $SQLDownloadSources.SQL2019
            $Exe = $InstallFolder + "\SQL2019-SSEI-Expr.exe"
            $MediaPath = $InstallFolder + "\SQL2019-Expr"
            $InstanceName = "VEEAMSQL2019"
        }
        "MSSQL_2017" {
            $Source = $SQLDownloadSources.SQL2017
            $Exe = $InstallFolder + "\SQLServer2017-SSEI-Expr.exe"
            $MediaPath = $InstallFolder + "\SQL2017-Expr"
            $InstanceName = "VEEAMSQL2017"
        }
        "MSSQL_2016" {
            $Source = $SQLDownloadSources.SQL2016
            $Exe = $InstallFolder + "\SQLServer2016-SSEI-Expr.exe"
            $MediaPath = $InstallFolder + "\SQL2016-Expr"
            $InstanceName = "VEEAMSQL2016"
        }
    }

    Write-VBRInstallLog ("Downloading Microsoft SQL Express Server to: $Exe")
    try {
        (New-Object Net.WebClient).DownloadFile($Source, $Exe)
        Write-VBRInstallLog (">> New Microsoft SQL Express Server exe installer downloaded.")
    }
    catch {
        Write-VBRInstallLog (">> Failed to download new Microsoft SQL Express Server. Please install this manually.")
        Exit 1
    }

    $PrepParams = @(
        '/ACTION="Download"' 
        '/ENU'
        '/LANGUAGE="en-US"' 
        "/MEDIAPATH=`"$MediaPath`""
        '/MEDIATYPE="Core"' 
        '/QUIET'
        '/HIDEPROGRESSBAR'
    )

    $Params = @(
        '/ACTION="Install"'
        '/ROLE="AllFeatures_WithDefaults"'
        '/HIDECONSOLE'
        '/QUIET'
        '/SUPPRESSPRIVACYSTATEMENTNOTICE'
        '/IACCEPTSQLSERVERLICENSETERMS'
        '/IACCEPTROPENLICENSETERMS'
        '/ENU'
        '/UpdateEnabled="False"'
        '/FEATURES="SQLEngine"'
        "/INSTANCENAME=`"$InstanceName`""
        '/AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"'
        '/AGTSVCSTARTUPTYPE="Disabled"'
        '/SQLSVCSTARTUPTYPE="Automatic"'
        '/SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"'
        '/SQLSVCACCOUNT="NT AUTHORITY\SYSTEM"'
        '/SQLSYSADMINACCOUNTS="NT AUTHORITY\SYSTEM" "BUILTIN\Administrators"'
        '/SQLTEMPDBFILESIZE="8"'
        '/SQLTEMPDBLOGFILESIZE="8"'
        '/ADDCURRENTUSERASSQLADMIN="True"'
        '/TCPENABLED="1"'
        '/NPENABLED="1"'
        '/BROWSERSVCSTARTUPTYPE="Automatic"'
    )

    $PrepResult = (Start-Process "$Exe" -ArgumentList $PrepParams -Wait -PassThru).ExitCode
    if ($PrepResult -eq 0) {
        Write-VBRInstallLog ("Installing Microsoft SQL Server...")
        $UnpackExe = $MediaPath + "\SQLEXPR_x64_ENU.exe"
        $UnpackResult = (Start-Process "$UnpackExe" -ArgumentList "/Q /X:`"$($UnpackExe -replace '.exe','')`"" -Wait -PassThru).ExitCode
        if ($UnpackResult -eq 0) {
            $UnpackedExe = $MediaPath + "\SQLEXPR_x64_ENU\SETUP.exe"
            $Result = (Start-Process "$UnpackedExe" -ArgumentList $Params -Wait -PassThru).ExitCode
            if ($Result -eq 0 -or $Result -eq 3010) {
                Write-VBRInstallLog (">> Successfully installed and configured Microsoft SQL Server")
            }
            else {
                Write-VBRInstallLog (">> Failed to install Microsoft SQL Server")
            }
        }
    }
    else {
        Write-VBRInstallLog (">> Failed to unpack Microsoft SQL Server setup")
        Exit 1
    }
}

# -- Build different purpose functions --
function Install-Requirement {
    Param(
        [Parameter()]
        [String]$Exe,

        [Parameter()]
        [String]$Msi
    )

    if (-not([string]::IsNullOrEmpty($Exe))) {
        # Extract package name from provided exe file
        $Exe -match "[^\\]+$" | Out-Null
        $LogName = $Matches[0] -replace ".exe", ".log"

        # Build parameters for installer
        $Params = @(
            '/install'
            '/quiet'
            '/norestart'
            "/log `"$LogFolder\$LogName`""
        )

        return (Start-Process "$Exe" -ArgumentList $Params -Wait -PassThru).ExitCode
    }

    if (-not([string]::IsNullOrEmpty($Msi))) {
        # Extract package name from provided msi installer
        $Msi -match "[^\\]+$" | Out-Null
        $LogName = $Matches[0] -replace ".msi", ".log"

        # Build parameters for installer
        $Params = @(
            "/i `"$Msi`""
            '/qn'
            '/norestart'
            "/L*v `"$LogFolder\$LogName`""
        )

        return (Start-Process msiexec.exe -ArgumentList $Params -Wait -PassThru).ExitCode
    }
}

function Install-Package {
    Param(
        [Parameter()]
        [String]$Msi
    )

    if (-not([string]::IsNullOrEmpty($Msi))) {
        # Extract package name from provided msi installer
        $Msi -match "[^\\]+$" | Out-Null
        $LogName = $Matches[0] -replace ".msi", ".log"

        # Build parameters for installer
        if (($Msi -match "[^\\]+$" -eq "Shell.x64.msi") -or ($Msi -match "[^\\]+$" -eq "VeeamBackupCatalog64.msi")) {
            # 'Shell.x64.msi' -> MSI installer for VBR Console
            # 'VeeamBackupCatalog64.msi' -> MSI installer for Veeam Backup Catalog
            $Params = @(
                "/i `"$Msi`""
                '/qn'
                '/norestart'
                "/L*v `"$LogFolder\$LogName`""
                'ACCEPT_EULA="1"'
                'ACCEPT_THIRDPARTY_LICENSES="1"'
                'ACCEPT_LICENSING_POLICY="1"'
                'ACCEPT_REQUIRED_SOFTWARE="1"'
            )
        }
        else {
            $Params = @(
                "/i `"$Msi`""
                '/qn'
                '/norestart'
                "/L*v `"$LogFolder\$LogName`""
                'ACCEPT_EULA="1"'
                'ACCEPT_THIRDPARTY_LICENSES="1"'
            )
        }
        
        return (Start-Process msiexec.exe -ArgumentList $Params -Wait -PassThru).ExitCode
    }
}

function Install-Explorer {
    Param(
        [Parameter()]
        [String]$Msi
    )

    if (-not([string]::IsNullOrEmpty($Msi))) {
        # Extract package name from provided msi installer
        $Msi -match "[^\\]+$" | Out-Null
        $LogName = $Matches[0] -replace ".msi", ".log"
        
        # Build parameters for installer
        $Params = @(
            "/i `"$Msi`""
            '/qn'
            '/norestart'
            "/L*v `"$LogFolder\$LogName`""
            'ACCEPT_EULA="1"'
            'ACCEPT_THIRDPARTY_LICENSES="1"'
        )
    
        return (Start-Process msiexec.exe -ArgumentList $Params -Wait -PassThru).ExitCode
    }
}

function Install-Plugin {
    Param(
        [Parameter()]
        [String]$Msi
    )

    if (-not([string]::IsNullOrEmpty($Msi))) {
        # Extract package name from provided msi installer
        $Msi -match "[^\\]+$" | Out-Null
        $LogName = $Matches[0] -replace ".msi", ".log"

        # Build parameters for installer
        $Params = @(
            "/i `"$Msi`""
            '/qn'
            "/L*v `"$LogFolder\$LogName`""
            'ACCEPT_EULA="1"'
            'ACCEPT_THIRDPARTY_LICENSES="1"'
        )

        return (Start-Process msiexec.exe -ArgumentList $Params -Wait -PassThru).ExitCode
    }
}

function Install-VeeamBackupReplicationServer {
    Param(
        [Parameter()]
        [String]$Msi,

        [Parameter()]
        [String]$License
    )

    Write-VBRInstallLog ("Installing Veeam Backup & Replication Server")
    if ($License -ne "CE") {
        $Params = @(
            "/i `"$Msi`""
            '/qn'
            '/norestart'
            "/L*v `"$LogFolder\VeeamBackupReplicationServer.log`""
            'ACCEPT_EULA="1"'
            'ACCEPT_THIRDPARTY_LICENSES="1"'
            'ACCEPT_LICENSING_POLICY="1"'
            'ACCEPT_REQUIRED_SOFTWARE="1"'
            "VBR_LICENSE_FILE=`"$License`""
            'VBR_LICENSE_AUTOUPDATE="1"' # Set to 0 if autoupdate (which enables usage reporting) is not desired
        )
    }
    else {
        $Params = @(
            "/i `"$Msi`""
            '/qn'
            '/norestart'
            "/L*v `"$LogFolder\VeeamBackupReplicationServer.log`""
            'ACCEPT_EULA="1"'
            'ACCEPT_THIRDPARTY_LICENSES="1"'
            'ACCEPT_LICENSING_POLICY="1"'
            'ACCEPT_REQUIRED_SOFTWARE="1"'
            'VBR_LICENSE_AUTOUPDATE="1"' # Autoupdate is a must for Community Edition and NFR!
        )
    }

    # By default Veeam installer will point to PostgreSQL.
    # Therefor we need to point to Microsoft SQL, if this is the chosen SQL Engine.
    if ($SQLEngine -like "*MSSQL*") {
        $Params += 'VBR_SQLSERVER_ENGINE="0"' # 1 (by deufalt) = PostgreSQL. 0 = Microsoft SQL
    }

    $Result = return (Start-Process msiexec.exe -ArgumentList $Params -Wait -PassThru).ExitCode
    if ($Result -eq 0) {
        Write-VBRInstallLog (">> Successfully installed Veeam Backup & Replication Server. Exit code [$Result]")
    }
    else {
        Write-VBRInstallLog (">> Failed")
    }
}

function Install-VeeamEnterpriseManager {
    Param(
        [Parameter()]
        [String]$Msi,

        [Parameter()]
        [String]$License
    )

    Write-VBRInstallLog ("Installing Veeam Backup Enterprise Manager")
    if ($License -eq "CE") {
        Write-VBRInstallLog (">> No license key file provided. A valid license key file is needed for Veeam Backup Enterprise Manager.")
    }
    else {
        $Params = @(
            "/i `"$Msi`""
            '/qn'
            '/norestart'
            "/L*v `"$LogFolder\VeeamBackupEnterpriseManager.log`""
            'ACCEPT_EULA="1"'
            'ACCEPT_THIRDPARTY_LICENSES="1"'
            'ACCEPT_LICENSING_POLICY="1"'
            'ACCEPT_REQUIRED_SOFTWARE="1"'
            "VBREM_LICENSE_FILE=`"$License`""
            'VBREM_LICENSE_AUTOUPDATE="1"'
        )
    }

    if ($SQLEngine -like "*MSSQL*") {
        $Params += 'VBREM_SQLSERVER_ENGINE="0"'
    }

    $Result = return (Start-Process msiexec.exe -ArgumentList $Params -Wait -PassThru).ExitCode
    if ($Result -eq 0) {
        Write-VBRInstallLog (">> Successfully installed Veeam Backup Enterprise Manager. Exit code [$Result]")
    }
}

function Update-CumulativePatch {
    Param(
        [Parameter()]
        [String]$Exe
    )

    Write-VBRInstallLog ("Applying Cumulative Patch to Veeam Backup & Replication")
    if (-not([string]::IsNullOrEmpty($Exe))) {
        # Extract package name from provided exe file
        $Exe -match "[^\\]+$" | Out-Null
        $LogName = $Matches[0] -replace ".exe", ".log"

        # Build parameters for installer
        $Params = @(
            '/silent'
            '/quiet'
            '/noreboot'
            "/log `"$LogFolder\$LogName`""
            'VBR_AUTO_UPGRADE="1"'
        )

        $Result = return (Start-Process "$Exe" -ArgumentList $Params -Wait -PassThru).ExitCode
        if ($Result -eq 0 -or $Result -eq 3010) {
            Write-VBRInstallLog (">> Successfully applied patch $PatchName")
        }
        else {
            Write-VBRInstallLog (">> Failed to apply patch $PatchName. Please apply this patch manually.")
        }
    }
}

# -- Check ISO and License --
# If path to ISO specified, resolve absolute path.
# If none specified. Download ISO image from Veeam servers.
if (-not([String]::IsNullOrEmpty($ISO))) {
    $ISO = Resolve-Path $ISO
}
else {
    try {
        Write-VBRInstallLog ("No ISO specified. Checking for previously downloaded ISO...")
        $ISO = $InstallFolder + "\$ISOName"
        if (Test-Path $ISO) {
            Write-VBRInstallLog (">> Previous downloaded ISO found: $ISO")
        }
        else {
            $Source = "https://download2.veeam.com/VBR/v12/$ISOName"
            Write-VBRInstallLog (">> No previous ISO found. Downloading new ISO from: $Source")
            
            (New-Object Net.WebClient).DownloadFile($Source, $ISO)
            Write-VBRInstallLog (">> New ISO downloaded to: $ISO")
        } 
    }
    catch {
        # Exit as further steps requiere ISO.
        Write-VBRInstallLog (">> Failed to download new ISO. Please check installation log for further detail.")
        Exit 1
    }
}

# If license file key specified, resolve absolute path else continue.
if ($License -match "http[s]://") {
    Write-VBRInstallLog ("License parameter matches URL. Trying to download license key file...")
    try {
        $LicenseName = $InstallFolder + "\VeeamLicense.lic"
        (New-Object net.WebClient).DownloadFile($License, $LicenseName)
        $License = Resolve-Path 
        Write-VBRInstallLog (">> License key file downloaded to: $LicenseName")
    }
    catch {
        Write-VBRInstallLog (">> Failed to download license key file. Installing Veeam Backup Server with Community Edition")
        $License = "CE" # CE for Community Edition
    }
}
elseif (-not([String]::IsNullOrEmpty($License))) {
    $License = Resolve-Path $License
}
else {
    $License = "CE"
}

# -- Mount VBR ISO --
try {
    Write-VBRInstallLog ("Mounting Veeam ISO...")
    Mount-DiskImage -ImagePath $ISO | Out-Null
    $MountDrive = (Get-Volume | Where-Object { $_.FileSystemLabel -like "VEEAM BACKUP"}).DriveLetter + ":" # Mounted ISO shows up as 'VEEAM BACKUP' in FriendlyName/FileSystemLabel
}
catch {
    # If mounting of ISO fails, exit script.
    # ISO is needed for any further actions.
    Write-VBRInstallLog ($_)
    Write-VBRInstallLog (">> Failed to mount Veeam ISO!")
    Exit 1
}

# -- Install Veeam Backup & Replication and/or Veeam Backup Enterprise Manager --
function Use-InstallFunction {
    <#
        .SYNOPSIS
        This function is merely used to call other install functions, to reduce the amount of repetitive and bulky code that has to be writting
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Requirement','Package','Explorer','Plugin')]
        [String]$InstallFunction,

        [Parameter(Mandatory = $false)]
        [ValidateSet('MSI','EXE')]
        [String]$InstallType,

        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [Alias('Name_To_Show_In_Log')]
        [String]$ProgramName
    )

    try {
        Write-VBRInstallLog ("Installing $ProgramName")
        switch ($InstallFunction) {
            "Requirement" {
                switch ($InstallType) {
                    "MSI" { $Result = Install-Requirement -Msi $Path }
                    "EXE" { $Result = Install-Requirement -Exe $Path }
                }
            }
            "Plugin" { 
                switch ($InstallType) {
                    "MSI" { $Result = Install-Plugin -Msi $Path }
                    "EXE" { $Result = Install-Plugin -Exe $Path }
                }
            }
            "Package" { 
                $Result = Install-Package -Msi $Path 
            }
            "Explorer" { 
                $Result = Install-Explorer -Msi $Path 
            }
        }

        if ($Result -eq 0 -or $Result -eq 3010) {
            Write-VBRInstallLog (">> Successfull install. Exit code [$Result]")
        }
        elseif ($Result -eq 1638) {
            Write-VBRInstallLog (">> Another instance of the program is already installed. Preceding as success. Exit code [$Result]")
        }
        else {
            Write-VBRInstallLog (">> Error installing $ProgramName. Exit code [$Result]")
        }
    }
    catch {
        Write-VBRInstallLog ($_)
        Write-VBRInstallLog (">> Unmounting ISO and exiting script.")
        Dismount-DiskImage -ImagePath $ISO | Out-Null
        Exit 1
    }
}

# Installing Prerequisites
# Microsoft .NET Core Runtime 6.0.12
Use-InstallFunction -InstallFunction Requirement -InstallType EXE -Path "$MountDrive\Redistr\x64\dotnet-runtime-6.0.12-win-x64.exe" -ProgramName "Microsoft .NET Core Runtime 6.0.12"

# Microsoft .NET Framework 4.7.2
# * Some versions of Windows comes with .NET Framework preisntalled -> https://learn.microsoft.com/en-us/dotnet/framework/get-started/system-requirements
# 528040 is the minimum verision for .NET 4.7.2 -> https://learn.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed
if (-not(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release -ge 528040) {
    Use-InstallFunction -InstallFunction Requirement -InstallType EXE -Path "$MountDrive\Redistr\NDP472-KB4054530-x86-x64-AllOS-ENU.exe" -ProgramName "Microsoft .NET Framework 4.7.2"
}

# Microsoft ASP.NET Core Shared Framework 6.0.12
Use-InstallFunction -InstallFunction Requirement -InstallType EXE -Path "$MountDrive\Redistr\x64\aspnetcore-runtime-6.0.12-win-x64.exe" -ProgramName "Microsoft ASP.NET Core Shared Framework 6.0.12"

# Microsoft Visual C++ Redistributable
Use-InstallFunction -InstallFunction Requirement -InstallType EXE -Path "$MountDrive\Redistr\x64\VC_redist.x64.exe" -ProgramName "Microsoft Visual C++ Redistributable"

# Microsoft System CLR Tpes For SQL Server 2014
Use-InstallFunction -InstallFunction Requirement -InstallType MSI -Path "$MountDrive\Redistr\x64\SQLSysClrTypes.msi" -ProgramName "Microsoft System CLR Tpes For SQL Server 2014"

# Microsoft Report Viewer Redistributable 2015
Use-InstallFunction -InstallFunction Requirement -InstallType MSI -Path "$MountDrive\Redistr\ReportViewer.msi" -ProgramName "Microsoft Report Viewer Redistributable 2015"

# Install SQL Engine
switch ($SQLEngine) {
    "PostgreSQL_15" { 
        Install-PostgreSQL -Installer "$MountDrive\Redistr\x64\PostgreSQL\15.1-1\postgresql-15.1-1-windows-x64.exe" 
    }
    { $_ -match "MSSQL_[2016|2017|2019|2022]" } { 
        Install-MSSQL -SQLVersion $SQLEngine 
    }

    Default { 
        Install-PostgreSQL -Installer "$MountDrive\Redistr\x64\PostgreSQL\15.1-1\postgresql-15.1-1-windows-x64.exe" 
    }
}

# -- Installing Veeam Backup & Replication -- 
# Install order -> https://helpcenter.veeam.com/docs/backup/vsphere/silent_mode.html?ver=120

# Veeam Backup Catalog
Use-InstallFunction -InstallFunction Package -InstallType MSI -Path "$MountDrive\Catalog\VeeamBackupCatalog64.msi" -ProgramName "Veeam Backup Catalog"

# Veeam Backup & Replication server
Install-VeeamBackupReplicationServer -Msi "$MountDrive\Backup\Server.x64.msi" -License $License

# Veeam Backup & Replication Console
Use-InstallFunction -InstallFunction Package -InstallType MSI -Path "$MountDrive\Backup\Shell.x64.msi" -ProgramName "Veeam Backup & Replication Console"

# - Explorers -
# Veeam Explorer for Microsoft Active Directory
Use-InstallFunction -InstallFunction Explorer -InstallType MSI -Path "$MountDrive\Explorers\VeeamExplorerForActiveDirectory.msi" -ProgramName "Veeam Explorer for Microsoft Active Directory"

# Veeam Explorer for Microsoft Exchange
Use-InstallFunction -InstallFunction Explorer -InstallType MSI -Path "$MountDrive\Explorers\VeeamExplorerForExchange.msi" -ProgramName "Veeam Explorer for Microsoft Exchange"

# Veeam Explorer for Microsoft SharePoint
Use-InstallFunction -InstallFunction Explorer -InstallType MSI -Path "$MountDrive\Explorers\VeeamExplorerForSharePoint.msi" -ProgramName "Veeam Explorer for Microsoft SharePoint"

# Veeam Explorer for Microsoft SQL Server
Use-InstallFunction -InstallFunction Explorer -InstallType MSI -Path "$MountDrive\Explorers\VeeamExplorerForSQL.msi" -ProgramName "Veeam Explorer for Microsoft SQL Server"

# Veeam Explorer for Microsoft Teams
Use-InstallFunction -InstallFunction Explorer -InstallType MSI -Path "$MountDrive\Explorers\VeeamExplorerForTeams.msi" -ProgramName "Veeam Explorer for Microsoft Teams"

# Veeam Explorer for Oracle
Use-InstallFunction -InstallFunction Explorer -InstallType MSI -Path "$MountDrive\Explorers\VeeamExplorerForOracle.msi" -ProgramName "Veeam Explorer for Oracle"

# Veeam Explorer for PostgreSQL
Use-InstallFunction -InstallFunction Explorer -InstallType MSI -Path "$MountDrive\Explorers\VeeamExplorerForPostgreSQL.msi" -ProgramName "Veeam Explorer for PostgreSQL"

# - Redistribuables -
# Redistributable Package for Veeam Agent for Linux
Use-InstallFunction -InstallFunction Package -InstallType MSI -Path "$MountDrive\Packages\VALRedist.msi" -ProgramName "Redistributable Package for Veeam Agent for Linux"

# Redistributable Package for Veeam Agent for Mac
Use-InstallFunction -InstallFunction Package -InstallType MSI -Path "$MountDrive\Packages\VAMRedist.msi" -ProgramName "Redistributable Package for Veeam Agent for Mac"

# Redistributable Package for Veeam Agent for Microsoft Windows
Use-InstallFunction -InstallFunction Package -InstallType MSI -Path "$MountDrive\Packages\VAWRedist.msi" -ProgramName "Redistributable Package for Veeam Agent for Microsoft Windows"

# Redistributable Package for Veeam Agent for Unix
Use-InstallFunction -InstallFunction Package -InstallType MSI -Path "$MountDrive\Packages\VAURedist.msi" -ProgramName "Redistributable Package for Veeam Agent for Unix"

# - Service Packages -
# Veeam Distribution Service Package
Use-InstallFunction -InstallFunction Package -InstallType MSI -Path "$MountDrive\Packages\VeeamDistributionSvc.msi" -ProgramName "Veeam Distribution Service"

# Veeam Mount Service Package
Use-InstallFunction -InstallFunction Package -InstallType MSI -Path "$MountDrive\Packages\VeeamMountService.msi" -ProgramName "Veeam Mount Service"

# - Plugins -
# Kasten Kubernetes Plugins
Use-InstallFunction -InstallFunction Plugin -InstallType MSI -Path "$MountDrive\Plugins\Kasten\VeeamKastenPlugin.msi" -ProgramName "Kasten Kubernetes Plugin"
Use-InstallFunction -InstallFunction Plugin -InstallType MSI -Path "$MountDrive\Plugins\Kasten\VeeamKastenPluginUI.msi" -ProgramName "Kasten Kubernetes UI Plugin"

<#
    .Notes
    As of February/March 2023, Veeam has yet to release compatiable versions of AWS and Microsoft Azure plugins.
    The lines are prepared, but are currently comments until these are ready.

    https://helpcenter.veeam.com/docs/backup/vsphere/upgrade_vbr_byb.html?ver=120#integration-with-veeam-backup-for-public-clouds
#>
# AWS plugins
#UNCOMMENT_ME! Use-InstallFunction -InstallFunction Plugin -InstallType MSI -Path "$MountDrive\Plugins\AWS\AWSPlugin.msi" -ProgramName "AWS Plugin"
#UNCOMMENT_ME! Use-InstallFunction -InstallFunction Plugin -InstallType MSI -Path "$MountDrive\Plugins\AWS\AWSPluginUI.msi" -ProgramName "AWS UI Plugin"

# Microsoft Azure Plugins
#UNCOMMENT_ME! Use-InstallFunction -InstallFunction Plugin -InstallType MSI -Path "$MountDrive\Plugins\Microsoft Azure\MicrosoftAzurePlugin.msi" -ProgramName "Microsoft Azure Plugin"
#UNCOMMENT_ME! Use-InstallFunction -InstallFunction Plugin -InstallType MSI -Path "$MountDrive\Plugins\Microsoft Azure\MicrosoftAzurePluginUI.msi" -ProgramName "Microsoft Azure UI Plugin"

# Google Cloud Plugins
Use-InstallFunction -InstallFunction Plugin -InstallType MSI -Path "$MountDrive\Plugins\GCP\GCPPluginUI" -ProgramName "Google Cloud Plugin"
Use-InstallFunction -InstallFunction Plugin -InstallType MSI -Path "$MountDrive\Plugins\GCP\GCPPluginUI.msi" -ProgramName "Google Cloud UI Plugin"

# -- Other Optional plugins --
# Install Nutanix plugins if chosen
if ($Nutanix) {
    Use-InstallFunction -InstallFunction Plugin -InstallType MSI -Path "$MountDrive\Plugins\Nutanix AHV\NutanixAHVPlugin.msi" -ProgramName "Nutanix AHV Plugin"
    Use-InstallFunction -InstallFunction Plugin -InstallType MSI -Path "$MountDrive\Plugins\Nutanix AHV\NutanixAHVPluginProxy.msi" -ProgramName "Nutanix AHV Proxy Plugin"
    Use-InstallFunction -InstallFunction Plugin -InstallType MSI -Path "$MountDrive\Plugins\Nutanix AHV\NutanixAHVPluginUI.msi" -ProgramName "Nutanix AHV UI Plugin"
}

# Install RedHat virtualization plugins if chosen
if ($RedHat) {
    Use-InstallFunction -InstallFunction Plugin -InstallType MSI -Path "$MountDrive\Plugins\RHV\RHVPlugin.msi" -ProgramName "RedHat Virtulization Plugin"
    Use-InstallFunction -InstallFunction Plugin -InstallType MSI -Path "$MountDrive\Plugins\RHV\RHVPluginProxy.msi" -ProgramName "RedHat Virtulization Proxy Plugin"
    Use-InstallFunction -InstallFunction Plugin -InstallType MSI -Path "$MountDrive\Plugins\RHV\RHVPluginUI.msi" -ProgramName "RedHat Virtulization UI Plugin"
}

# -- Apply latest patch --
if ((Test-Path "$MountDrive\Updates") -ne $false) {
    Update-CumulativePatch -Exe "$MountDrive\Updates\$PatchName"
}

# -- Install Veeam Backup Enterprise Manager --
if ($VeeamEnterpriseManager) {
    Install-VeeamEnterpriseManager -Msi "$MountDrive\EnterpriseManager\BackupWeb_x64.msi" -License $License
}

# -- Post install actions --
Dismount-DiskImage -ImagePath $ISO | Out-Null
