## Stop / Disable intrusive diagnostics services
net stop diagtrack
Set-Service -Name diagtrack -StartupType disabled
Set-Service -Name dmwappushservice -StartupType disabled

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

## Remove Pre-Provisioned Modern apps, provision the ones we want
$modernApps = @("Microsoft.Reader","Microsoft.WindowsReadingList","Microsoft.3DBuilder","microsoft.windowscommunicationsapps","Microsoft.BingFinance","Microsoft.BingNews","Microsoft.BingSports","Microsoft.BingWeather","Microsoft.BingTravel","Microsoft.BingHealthAndFitness","Microsoft.BingFoodAndDrink","Microsoft.People","Microsoft.WindowsPhone","Microsoft.MicrosoftSolitaireCollection","Microsoft.WindowsSoundRecorder","Microsoft.XboxApp","Microsoft.WindowsCamera","Microsoft.ZuneMusic","Microsoft.ZuneVideo","Microsoft.Office.OneNote","Microsoft.SkypeApp","Microsoft.MicrosoftOfficeHub")
foreach ($modernApp in $modernApps) {
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -match $modernApp} | Remove-AppxProvisionedPackage -Online
}

Get-AppxPackage -AllUsers | Remove-AppxPackage

#### Acquired the below from https://msdn.microsoft.com/en-us/library/windows/hardware/mt185364(v=vs.85).aspx

## Get all the provisioned packages
$Packages = (get-item 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications') | Get-ChildItem

## Filter the list if provided a filter
$PackageFilter = $args[0] 
if ([string]::IsNullOrEmpty($PackageFilter))
{
	echo "No filter specified, attempting to re-register all provisioned apps."
}
else
{
	$Packages = $Packages | where {$_.Name -like $PackageFilter} 

	if ($Packages -eq $null)
	{
		echo "No provisioned apps match the specified filter."
		exit
	}
	else
	{
		echo "Registering the provisioned apps that match $PackageFilter"
	}
}

ForEach($Package in $Packages)
{
	## get package name & path
	$PackageName = $Package | Get-ItemProperty | Select-Object -ExpandProperty PSChildName
	$PackagePath = [System.Environment]::ExpandEnvironmentVariables(($Package | Get-ItemProperty | Select-Object -ExpandProperty Path))

	## register the package	
	echo "Attempting to register package: $PackageName"

	Add-AppxPackage -register $PackagePath -DisableDevelopmentMode                  
}
