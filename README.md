# Windows-10

An as complete as possible attempt to turn off the anti-privacy features of Windows 10. Tested on Windows 10 Pro and Windows 10 Enterprise. This script will have some beneficial effect on Windows 10 Home as well, though I have not yet tested whether that edition of Windows honors all of the 'Policies' registry keys.

This script will uninstall all of your modern apps and lock out the Windows store - to avoid this, comment out the following line: 

New-ItemProperty -Force -Path HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore -Name RemoveWindowsStore -Type DWord -Value 1

As well as everything below "Remove Pre-Provisioned Modern apps".
