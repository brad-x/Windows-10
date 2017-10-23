function add-registryKeys 
    {
        <#
            .SYNOPSIS
            Add registry keys
            .DESCRIPTION
            This function will add registry keys
            .EXAMPLE
            add-registryKeys -registryPath "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "Windows" -Type "DWord" -Value 0
            .PARAMETER registryPath
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
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True
                    )]
                [string]
                [ValidateNotNullorEmpty()]
                [ValidatePattern("HK[L|C][R|U|M]:\\\w")]
            $registryPath,

            [Parameter(
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True
                    )]
                [string]
                [ValidateNotNullorEmpty()]
            $name,

            [Parameter(
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True
                    )]
                [string]
                [ValidateNotNullorEmpty()]
            $type,

            [Parameter(
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True
                    )]
                [int]
                [ValidateNotNull()]
            $value
        )


        Begin
            {
                
            }

        Process
            {
                If (-Not (Test-Path $registryPath))
                    {
	                    try 
                            {
                                New-Item -Force -Path $registryPath | Out-Null
                           }
                        catch {}

                        try
                            {
                                New-ItemProperty -Force -Path $registryPath -Name $name -PropertyType $type -Value $value | out-null
                            }
                        catch {}
                    }
                else
                    {
                        try
                            {
                                New-ItemProperty -Force -Path $registryPath -Name $name -PropertyType $type -Value $value | out-null
                            }
                        catch {}
                    }
            }
        End
            {
                
            }
    }
    
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
#taskkill /f /im OneDrive.exe
$onedrive = get-process | where {$_.name -like "*onedrive*"}
Stop-Process $onedrive
& $env:SystemRoot\SysWOW64\OneDriveSetup.exe /uninstall

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
add-registryKeys -registryPath 'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name System.IsPinnedToNameSpaceTree -Type DWord -Value 0
add-registryKeys -registryPath 'HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name System.IsPinnedToNameSpaceTree -Type DWord -Value 0
#Remove-Item -Path 'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Recurse
#Remove-Item -Path 'HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Recurse

## Kill access to the Windows Store
add-registryKeys -registryPath HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore -Name RemoveWindowsStore -Type DWord -Value 0

## Block connection to Microsoft Accounts
add-registryKeys -registryPath HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name NoConnectedUser -Type DWord -Value 3

# Disable WiFi Sense
add-registryKeys -registryPath HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting -Name value -Type DWord -Value 0
add-registryKeys -registryPath HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots -Name value -Type DWord -Value 0

# Disable Windows Update peer to peer
add-registryKeys -registryPath HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config -Name DODownloadMode -Type DWord -Value 0

# Require Ctrl-Alt-Del to log on
add-registryKeys -registryPath HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableCAD -Type DWord -Value 1

# Block "Add features to Windows 10"
add-registryKeys -registryPath HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\WAU -Name Disabled -Type DWord -Value 1

# Turn off Application Telemetry, Inventory Collector
add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\AppCompat -Name AITEnable -Type DWord -Value 0
add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\AppCompat -Name DisableInventory -Type DWord -Value 1

# Do not allow a Windows app to share application data between users
add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager -Name AllowSharedLocalAppData -Type DWord -Value 0

# Minimize Telemetry on Pro, disable on Enterprise
add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWord -Value 0

# Disable location services and device sensors
add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors -Name DisableLocation -Type DWord -Value 1
add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors -Name DisableSensors -Type DWord -Value 1

# Prevent the usage of OneDrive for file storage
add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\OneDrive -Name DisableFileSyncNGSC -Type DWord -Value 1

# Don't allow Microsoft to enable experimental features, Insider builds
add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds -Name EnableConfigFlighting -Type DWord -Value 0
add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds -Name EnableExperimentation -Type DWord -Value 0
add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds -Name AllowBuildPreview -Type DWord -Value 0

# Disable cloud sync of settings between PC's
add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\SettingSync -Name DisableSettingSync -Type DWord -Value 2
add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\SettingSync -Name DisableSettingSyncUserOverride -Type DWord -Value 1

# Block Cortana
add-registryKeys -registryPath 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search' -Name AllowCortana -Type DWord -Value 0

# Configure Automatic Updates - Don't interrupt users, but install / reboot every Friday
add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoUpdate -Type DWord -Value 0
add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name AUOptions -Type DWord -Value 4
add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name AutomaticMaintenanceEnabled -Type DWord -Value 1
add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name ScheduledInstallDay -Type DWord -Value 6
add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name ScheduledInstallTime -Type DWord -Value 3

# Disable the Customer Experience Improvement Program
add-registryKeys -registryPath "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name CEIPEnable -Type DWord -Value 0
add-registryKeys -registryPath "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows" -Name CEIPEnable -Type DWord -Value 0

# Disable Consumer Features like suggested apps
add-registryKeys -registryPath "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableWindowsConsumerFeatures -Type DWord -Value 1

# Disable Steps Recorder
add-registryJeys -registryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Type DWord -Value 1

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
#	"Microsoft.WindowsSoundRecorder"
	"Microsoft.XboxApp"
#	"Microsoft.WindowsCamera"
	"Microsoft.ZuneMusic"
	"Microsoft.ZuneVideo"
	"Microsoft.Office.OneNote"
	"Microsoft.SkypeApp"
	"Microsoft.MicrosoftOfficeHub"
	"Microsoft.CommsPhone"
	"Microsoft.ConnectivityStore"
	"Microsoft.Messaging"
       "Microsoft.Appconnector"
       "Microsoft.FreshPaint"
       "Microsoft.Getstarted"
       "Microsoft.MicrosoftStickyNotes"
       "Microsoft.OneConnect"
#       "Microsoft.WindowsFeedbackHub"
        "Microsoft.MinecraftUWP"
#        "9E2F88E3.Twitter"
#        "PandoraMediaInc.29680B314EFC2"
#        "Flipboard.Flipboard"
#        "ShazamEntertainmentLtd.Shazam"
#        "king.com.*"
#        "ClearChannelRadioDigital.iHeartRadio"
#        "4DF9E0F8.Netflix"
#        "6Wunderkinder.Wunderlist"
#        "Drawboard.DrawboardPDF"
#        "2FE3CB00.PicsArt-PhotoStudio"
#        "D52A8D61.FarmVille2CountryEscape"
#        "TuneIn.TuneInRadio"
#        "GAMELOFTSA.Asphalt8Airborne"
#        "TheNewYorkTimes.NYTCrossword"
#        "DB6EA5DB.CyberLinkMediaSuiteEssentials"
#        "Facebook.Facebook"
#        "flaregamesGmbH.RoyalRevolt2"
#	"Microsoft.Office.Sway"
#	"9E2F88E3.Twitter"
#	"Flipboard.Flipboard"
#	"ShazamEntertainmentLtd.Shazam"
#	"king.com.CandyCrushSaga"
#	"ClearChannelRadioDigital.iHeartRadio"
#	"AdobeSystemsIncorporated.AdobePhotoshopExpress"
#	"ActiproSoftwareLLC.562882FEEB491"
#	"D5EA27B7.Duolingo-LearnLanguagesforFree"	
)


## Pass 1: Remove Microsoft bloat

foreach ($modernApp in $modernApps) {
    Get-AppxProvisionedPackage -Online | 
	Where-Object {$_.PackageName -match $modernApp} | 
	Remove-AppxProvisionedPackage -Online

    Get-AppxPackage -Name $modernApp -AllUsers | Remove-AppxPackage
}

## Pass 2: Remove everything else

Get-AppxPackage -AllUsers | where-object {$_.name –notlike “Microsoft*”} | Remove-AppxPackage
Get-AppXProvisionedPackage –online | where-object {$_.packagename –notlike “*Microsoft*”} | Remove-AppxProvisionedPackage –online


