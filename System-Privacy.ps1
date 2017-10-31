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
    
## Kill access to the Windows Store (Optional)
#add-registryKeys -registryPath HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore -Name RemoveWindowsStore -Type DWord -Value 0

## Block connection to Microsoft Accounts
#add-registryKeys -registryPath HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name NoConnectedUser -Type DWord -Value 3

# Require Ctrl-Alt-Del to log on
#add-registryKeys -registryPath HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableCAD -Type DWord -Value 1

# Block "Add features to Windows 10"
#add-registryKeys -registryPath HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\WAU -Name Disabled -Type DWord -Value 0

# Do not allow a Windows app to share application data between users
#add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager -Name AllowSharedLocalAppData -Type DWord -Value 0

# Disable location services
#add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors -Name DisableLocation -Type DWord -Value 1

# Don't allow Microsoft to enable experimental features, Insider builds
#add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds -Name EnableConfigFlighting -Type DWord -Value 0
#add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds -Name EnableExperimentation -Type DWord -Value 0
#add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds -Name AllowBuildPreview -Type DWord -Value 0

# Disable cloud sync of settings between PC's
#add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\SettingSync -Name DisableSettingSync -Type DWord -Value 2
#add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\SettingSync -Name DisableSettingSyncUserOverride -Type DWord -Value 1

# Configure Automatic Updates - Don't interrupt users, but install / reboot every Friday
#add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoUpdate -Type DWord -Value 0
#add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name AUOptions -Type DWord -Value 4
#add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name AutomaticMaintenanceEnabled -Type DWord -Value 1
#add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name ScheduledInstallDay -Type DWord -Value 6
#add-registryKeys -registryPath HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name ScheduledInstallTime -Type DWord -Value 3

# Disable Consumer Features like suggested apps
#add-registryKeys -registryPath "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableWindowsConsumerFeatures -Type DWord -Value 1

# Disable Handwriting Data Sharing
#add-registryKeys -registryPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type DWord -Value 1

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
#	"Microsoft.ZuneMusic"
#	"Microsoft.ZuneVideo"
	"Microsoft.Office.OneNote"
#	"Microsoft.SkypeApp"
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
)


## Pass 1: Remove Microsoft bloat

#foreach ($modernApp in $modernApps) {
#    Get-AppxProvisionedPackage -Online | 
#	Where-Object {$_.PackageName -match $modernApp} | 
#	Remove-AppxProvisionedPackage -Online
#
#    Get-AppxPackage -Name $modernApp -AllUsers | Remove-AppxPackage
#}

## Pass 2 (Optional): Remove everything else

#Get-AppxPackage -AllUsers | where-object {$_.name –notlike “Microsoft*”} | Remove-AppxPackage
#Get-AppXProvisionedPackage –online | where-object {$_.packagename –notlike “*Microsoft*”} | Remove-AppxProvisionedPackage –online


