## Stop / Disable intrusive diagnostics services
$services = @("diagtrack"
	"dmwappushservice"
	"Wecsvc"
	"DcpSvc"
	"diagnosticshub.standardcollector.service"
)

foreach ($service in $services) {
    Get-Service -Name $service | Stop-Service -Force
    Get-Service -Name $service | Set-Service -StartupType Disabled
}

## Remove diagnostic services

Disable-ScheduledTask -TaskPath "\Microsoft\Windows\AppID" -TaskName "SmartScreenSpecific"
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience" -TaskName "Microsoft Compatibility Appraiser"
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience" -TaskName "ProgramDataUpdater"
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Autochk" -TaskName "Proxy"
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program" -TaskName "Consolidator"
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program" -TaskName "KernelCeipTask"
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program" -TaskName "UsbCeip"
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\DiskDiagnostic" -TaskName "Microsoft-Windows-DiskDiagnosticDataCollector"
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\NetTrace" -TaskName "GatherNetworkInfo"
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Error Reporting" -TaskName "QueueReporting"

## Remove OneDrive 
taskkill /f /im OneDrive.exe
& $env:SystemRoot\SysWOW64\OneDriveSetup.exe /uninstall

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
Remove-Item -Path 'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Recurse
Remove-Item -Path 'HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Recurse

## Kill access to the Windows Store
If (-Not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore")) {
	New-Item -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" | Out-Null
}
New-ItemProperty -Force -Path HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore -Name RemoveWindowsStore -Type DWord -Value 1

## Block connection to Microsoft Accounts
If (-Not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")) {
	New-Item -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Out-Null
}
New-ItemProperty -Force -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name NoConnectedUser -Type DWord -Value 3

# Disable WiFi Sense
If (-Not (Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
	New-Item -Force -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" | Out-Null
}
New-ItemProperty -Force -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting -Name value -Type DWord -Value 0
If (-Not (Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
	New-Item -Force -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" | Out-Null
}
New-ItemProperty -Force -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots -Name value -Type DWord -Value 0

# Disable Windows Update peer to peer
If (-Not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
	New-Item -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
}
New-ItemProperty -Force -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config -Name DODownloadMode -Type DWord -Value 0

# Require Ctrl-Alt-Del to log on
If (-Not (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System")) {
	New-Item -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" | Out-Null
}
New-ItemProperty -Force -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableCAD -Type DWord -Value 0

# Block "Add features to Windows 10"
If (-Not (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\WAU")) {
	New-Item -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\WAU" | Out-Null
}
New-ItemProperty -Force -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\WAU -Name Disabled -Type DWord -Value 1

# Turn off Application Telemetry, Inventory Collector
If (-Not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat")) {
	New-Item -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" | Out-Null
}
New-ItemProperty -Force -Path HKLM:\Software\Policies\Microsoft\Windows\AppCompat -Name AITEnable -Type DWord -Value 0
New-ItemProperty -Force -Path HKLM:\Software\Policies\Microsoft\Windows\AppCompat -Name DisableInventory -Type DWord -Value 1

# Do not allow a Windows app to share application data between users
If (-Not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager")) {
	New-Item -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" | Out-Null
}
New-ItemProperty -Force -Path HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager -Name AllowSharedLocalAppData -Type DWord -Value 0

# Minimize Telemetry on Pro, disable on Enterprise
If (-Not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection")) {
	New-Item -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" | Out-Null
}
New-ItemProperty -Force -Path HKLM:\Software\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWord -Value 0

# Disable location services and device sensors
If (-Not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors")) {
	New-Item -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" | Out-Null
}
New-ItemProperty -Force -Path HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors -Name DisableLocation -Type DWord -Value 1
New-ItemProperty -Force -Path HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors -Name DisableSensors -Type DWord -Value 1

# Prevent the usage of OneDrive for file storage
If (-Not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows\OneDrive")) {
	New-Item -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\OneDrive" | Out-Null
}
New-ItemProperty -Force -Path HKLM:\Software\Policies\Microsoft\Windows\OneDrive -Name DisableFileSyncNGSC -Type DWord -Value 1

# Don't allow Microsoft to enable experimental features, Insider builds
If (-Not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds")) {
	New-Item -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds" | Out-Null
}
New-ItemProperty -Force -Path HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds -Name EnableConfigFlighting -Type DWord -Value 0
New-ItemProperty -Force -Path HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds -Name EnableExperimentation -Type DWord -Value 0
New-ItemProperty -Force -Path HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds -Name AllowBuildPreview -Type DWord -Value 0

# Disable cloud sync of settings between PC's
If (-Not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync")) {
	New-Item -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" | Out-Null
}
New-ItemProperty -Force -Path HKLM:\Software\Policies\Microsoft\Windows\SettingSync -Name DisableSettingSync -Type DWord -Value 2
New-ItemProperty -Force -Path HKLM:\Software\Policies\Microsoft\Windows\SettingSync -Name DisableSettingSyncUserOverride -Type DWord -Value 1

# Block Cortana
If (-Not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search")) {
	New-Item -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" | Out-Null
}
New-ItemProperty -Force -Path 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search' -Name AllowCortana -Type DWord -Value 0

# Configure Automatic Updates - Don't interrupt users, but install / reboot every Friday
If (-Not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
	New-Item -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" | Out-Null
}
New-ItemProperty -Force -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoUpdate -Type DWord -Value 0
New-ItemProperty -Force -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name AUOptions -Type DWord -Value 4
New-ItemProperty -Force -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name AutomaticMaintenanceEnabled -Type DWord -Value 1
New-ItemProperty -Force -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name ScheduledInstallDay -Type DWord -Value 6
New-ItemProperty -Force -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name ScheduledInstallTime -Type DWord -Value 3

# Disable the Customer Experience Improvement Program
If (-Not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient"))
{
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name SQMClient
}
If (-Not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"))
{
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient" -Name Windows
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name CEIPEnable -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows" -Name CEIPEnable -Type DWord -Value 0

# Disable Windows Defender Cloud reporting and sample submission

$definition = @"
using System;
using System.Runtime.InteropServices;
namespace Win32Api
{
    public class NtDll
    {
        [DllImport("ntdll.dll", EntryPoint="RtlAdjustPrivilege")]
        public static extern int RtlAdjustPrivilege(ulong Privilege, bool Enable, bool CurrentThread, ref bool Enabled);
    }
}
"@
 
        if (-not ("Win32Api.NtDll" -as [type])) 
        {
            Add-Type -TypeDefinition $definition -PassThru | out-null
        }
        else
        {
             ("Win32Api.NtDll" -as [type]) | Out-Null
        }
       
        $bEnabled = $false
        # Enable SeTakeOwnershipPrivilege
        $res = [Win32Api.NtDll]::RtlAdjustPrivilege(9, $true, $false, [ref]$bEnabled)

        $adminGroupSID = "S-1-5-32-544"

        $adminGroupName = (get-wmiobject -class "win32_account" -namespace "root\cimv2" | where-object{$_.sidtype -eq 4 -and $_.Sid -eq "$adminGroupSID"}).Name 

        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows Defender\Spynet", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::takeownership)
        $acl = $key.GetAccessControl()
        $acl.SetOwner([System.Security.Principal.NTAccount]$adminGroupName)
        $key.SetAccessControl($acl)

        $rule = New-Object System.Security.AccessControl.RegistryAccessRule ("$adminGroupName","FullControl","Allow")
        $acl.SetAccessRule($rule)
        $key.SetAccessControl($acl)


        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 0

        $acl.RemoveAccessRule($rule) | Out-Null
        $key.SetAccessControl($acl)

## Remove Pre-Provisioned Modern apps, provision the ones we want
$modernApps = @("Microsoft.Reader"
	"Microsoft.WindowsReadingList"
	"Microsoft.3DBuilder"
	"microsoft.windowscommunicationsapps"
	"Microsoft.BingFinance"
	"Microsoft.BingNews"
	"Microsoft.BingSports"
	"Microsoft.BingWeather"
	"Microsoft.BingTravel"
	"Microsoft.BingHealthAndFitness"
	"Microsoft.BingFoodAndDrink"
	"Microsoft.People"
	"Microsoft.WindowsPhone"
	"Microsoft.MicrosoftSolitaireCollection"
	"Microsoft.WindowsSoundRecorder"
	"Microsoft.XboxApp"
	"Microsoft.WindowsCamera"
	"Microsoft.ZuneMusic"
	"Microsoft.ZuneVideo"
	"Microsoft.Office.OneNote"
	"Microsoft.SkypeApp"
	"Microsoft.MicrosoftOfficeHub"
)

foreach ($modernApp in $modernApps) {
    Get-AppxProvisionedPackage -Online | 
	Where-Object {$_.PackageName -match $modernApp} | 
	Remove-AppxProvisionedPackage -Online

    Get-AppxPackage -Name $modernApp -AllUsers | Remove-AppxPackage
}



function add-registryKeys 
    {
        <#
            .SYNOPSIS
            Add registry keys
            .DESCRIPTION
            This function will add registry keys
            .EXAMPLE
            add-registryKeys -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "Windows" -Type "DWord" -Value 0
            .EXAMPLE
            This should be another example but instead I will state that brad-x sucks.
            .PARAMETER Path
            Registry path to be modified
            .PARAMETER Name
            Name of the registry key
            .PARAMETER Type
            Type of registry key
            .Parameter Value
            Value of the registry key
          #>
        [CmdletBinding(DefaultParameterSetName="")]
        Param(
            [Parameter(
                    Position=0,
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True
                    )]
                [string[]]
                [ValidateNotNullorEmpty]
                [ValidatePattern("HK[L|C][R|U|M]:\\\w")]
            $registryPath,

            [Parameter(
                    Posotion=0,
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True
                    )]
                [string[]]
                [ValidateNotNullorEmpty]
            $name,

            [Parameter(
                    Position=0,
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True
                    )]
                [string[]]
                [ValidateNotNullorEmpty]
            $type,

            [Parameter(
                    Position=0,
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True
                    )]
                [int[]]
                [ValidateNotNullorEmpty]
            $value
        )


        Begin
            {
                
            }

        Process
            {
                If (-Not (Test-Path $path))
                    {
	                    try 
                            {
                                New-Item -Force -Path $path | Out-Null
                            }
                        catch {}

                        try
                            {
                                New-ItemProperty -Force -Path $path -Name $name -Type $type -Value $value
                            }
                        catch {}
                    }
                else
                    {
                        try
                            {
                                New-ItemProperty -Force -Path $path -Name $name -Type $type -Value $value
                            }
                        catch {}
                    }
            }
        End
            {
                
            }
    }