@echo off
echo Cleaning!!

:: ~ Clean .NET Assemblies ~
FOR /D %%f IN (C:\Windows\assembly\Nati*.*) do rd /q /s "%%f" >nul 2>&1
FOR /D %%f IN (C:\Windows\assembly\Nati*.*) do del /q /s /f "%%f" >nul 2>&1

:: ~ Clean winSxS ~
dism /online /cleanup-image /startcomponentcleanup /resetbase >nul 2>&1

:: ~ Clean SoftwareDistribution ~
net stop wuauserv >nul 2>&1
net stop bits >nul 2>&1
del /q /f "C:\Windows\SoftwareDistribution\*" >nul 2>&1
FOR /D %%f IN (C:\Windows\SoftwareDistribution\*) do rd /q /s "%%f" >nul 2>&1
FOR /D %%f IN (C:\Windows\SoftwareDistribution\*) do del /q /s /f "%%f" >nul 2>&1

:: ~ Clean temp folder ~
del /q /f "C:\Windows\Temp\*" >nul 2>&1
FOR /D %%f IN (C:\Windows\temp\*) do rd /q /s "%%f" >nul 2>&1

:: ~ Clean Windows Defender Scans ~
del /q /f "C:\ProgramData\Microsoft\Windows Defender\Scans\mpcache*" >nul 2>&1

:: ~ Clean Manifest Cache ~
net stop trustedinstaller >nul 2>&1
Takeown /f C:\Windows\WinSxS\ManifestCache\* >nul 2>&1
Icacls C:\Windows\WinSxS\ManifestCache\* /GRANT administrators:F >nul 2>&1
del /q /f "C:\Windows\WinSxS\ManifestCache\*.bin" >nul 2>&1

:: Event log tweaks
wevtutil sl Microsoft-Windows-SleepStudy/Diagnostic /e:false >nul 2>&1
wevtutil sl Microsoft-Windows-Kernel-Processor-Power/Diagnostic /e:false >nul 2>&1
wevtutil sl Microsoft-Windows-UserModePowerService/Diagnostic /e:false >nul 2>&1

:: Clean up system and application temporary files
for %%d in ("%windir%\temp" "%temp%" "%localappdata%\Microsoft\Windows\INetCache\IE" "%localappdata%\Temp") do (
    if exist "%%d" (
        del /s /f /q "%%d\*.*" >NUL 2>&1
        rd /s /q "%%d" >NUL 2>&1
        md "%%d" >NUL 2>&1
    )
)

del /q /f "C:\ProgramData\ThermalOS\OpenShellSetup_4_4_195.exe" >nul 2>&1
del /q /f "C:\ProgramData\ThermalOS\ThermalPerformance.pow" >nul 2>&1
del /q /f "C:\ProgramData\ThermalOS\ThermalPerformanceIdleDisabled.pow" >nul 2>&1
del /q /f "C:\ProgramData\ThermalOS\VC_redist.x64.exe" >nul 2>&1

:: Delete Windows log files
del /s /f /q "%windir%\Logs\*.log" >NUL 2>&1
del /s /f /q "%windir%\*.log" >NUL 2>&1

:: Clear Windows Update download cache
if exist "C:\Windows\SoftwareDistribution\Download" (
    rd /s /q "C:\Windows\SoftwareDistribution\Download" >NUL 2>&1
)

:: Clearing Prefetch files
del /s /f /q "%windir%\Prefetch\*.*" >NUL 2>&1

:: Clearing the Recycle Bin using PowerShell
powershell -command "Clear-RecycleBin -Force" >NUL 2>&1

:: Cleaning firewall rules
::source: https://github.com/amitxv/PC-Tuning
Reg.exe delete "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f >nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f >nul 2>&1

:: Going further
del /s /f /q c:\windows\temp. >nul 2>&1
del /s /f /q C:\WINDOWS\Prefetch >nul 2>&1
del /s /f /q %temp%. >nul 2>&1
del /s /f /q %systemdrive%\*.tmp >nul 2>&1
del /s /f /q %systemdrive%\*._mp >nul 2>&1
del /s /f /q %systemdrive%\*.log >nul 2>&1
del /s /f /q %systemdrive%\*.gid >nul 2>&1
del /s /f /q %systemdrive%\*.chk >nul 2>&1
del /s /f /q %systemdrive%\*.old >nul 2>&1
del /s /f /q %systemdrive%\recycled\*.* >nul 2>&1
del /s /f /q %systemdrive%\$Recycle.Bin\*.* >nul 2>&1
del /s /f /q %windir%\*.bak >nul 2>&1
del /s /f /q %windir%\prefetch\*.* >nul 2>&1
del /s /f /q %LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db >nul 2>&1
del /s /f /q %LocalAppData%\Microsoft\Windows\Explorer\*.db >nul 2>&1
del /f /q %SystemRoot%\Logs\CBS\CBS.log >nul 2>&1
del /f /q %SystemRoot%\Logs\DISM\DISM.log >nul 2>&1
deltree /y c:\windows\tempor~1 >nul 2>&1
deltree /y c:\windows\temp >nul 2>&1
deltree /y c:\windows\tmp >nul 2>&1
deltree /y c:\windows\ff*.tmp >nul 2>&1
deltree /y c:\windows\history >nul 2>&1
deltree /y c:\windows\cookies >nul 2>&1
deltree /y c:\windows\recent >nul 2>&1
deltree /y c:\windows\spool\printers >nul 2>&1

echo Done! Press any key to close the script. It is recommended you restart your PC!
pause >nul