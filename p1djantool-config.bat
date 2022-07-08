
SETLOCAL EnableDelayedExpansion
if /i "%~1"=="/netreset" goto reset
if /i "%~1"=="/optweakE" goto optimizationE
if /i "%~1"=="/kback" goto background
if /i "%~1"=="/inputfix" goto inputlag
if /i "%~1"=="/nettweakE" goto networkE
if /i "%~1"=="/nettweakD" goto networkD
if /i "%~1"=="/optweakD" goto optimizationD
if /i "%~1"=="/animationsd" goto animD
if /i "%~1"=="/animationse" goto animE
if /i "%~1"=="/ctemp" goto cleantemp
exit
:cleantemp
del /s /f /q C:\Windows\Prefetch\*.*
del /s /f /q C:\Windows\Temp\*.*
del /s /f /q %localappdata%\Temp\*.*
exit
:animD
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010000000" /f
exit
:animE
reg delete "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /f >nul 2>nul
reg delete "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /f >nul 2>nul
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9e3e078012000000" /f
exit
:optimizationE
exit
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /d 0 /t REG_DWORD /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /d 0x26 /t REG_DWORD /f
if /i "%~2"=="4" (reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /d 0x4194304 /t REG_DWORD /f)
if /i "%~2"=="6" (reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /d 0x6291456 /t REG_DWORD /f)
if /i "%~2"=="8" (reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /d 0x8388608 /t REG_DWORD /f)
if /i "%~2"=="10" (reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /d 0x10485760 /t REG_DWORD /f)
if /i "%~2"=="12" (reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /d 0x12582912 /t REG_DWORD /f)
if /i "%~2"=="16" (reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /d 0x16777216 /t REG_DWORD /f)
if /i "%~2"=="20" (reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /d 0x20971520 /t REG_DWORD /f)
if /i "%~2"=="24" (reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /d 0x25165824 /t REG_DWORD /f)
if /i "%~2"=="32" (reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /d 0x33554432 /t REG_DWORD /f)
if /i "%~2"=="64" (reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /d 0x67108864 /t REG_DWORD /f)
exit
:optimizationD
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /f
exit


:background
cd c:\windows\System32
for /f "skip=3 tokens=1" %%i in ('TASKLIST /FI "USERNAME eq %userdomain%\%username%" /FI "STATUS eq running"') do (
if not "%%i"=="svchost.exe" (
if not "%%i"=="explorer.exe" (
if not "%%i"=="cmd.exe" (
if not "%%i"=="tasklist.exe" (
if not "%%i"=="p1djanTool-V2.exe" (
if not "%%i"=="p1djantool-config.bat" (
if not "%%i"=="nsudo.exe" (
if not "%%i"=="DevManView.exe" (
if not "%%i"=="pssuspend.exe" (
taskkill /f /im "%%i" 
)
)
)
)
)
)
)
)
)
)
pause & exit

:inputlag
FOR /F %%a in ('WMIC PATH Win32_USBHub GET DeviceID^| FINDSTR /L "VID_"') DO (
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /F /V "EnhancedPowerManagementEnabled" /T REG_DWORD /d 0 2>&1
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /F /V "AllowIdleIrpInD3" /T REG_DWORD /d 0 2>&1
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /F /V "SelectiveSuspendOn" /T REG_DWORD /d 0 2>&1
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /F /V "DeviceSelectiveSuspended" /T REG_DWORD /d 0 2>&1
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /F /V "SelectiveSuspendEnabled" /T REG_DWORD /d 0 2>&1
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /F /V "fid_D1Latency" /T REG_DWORD /d 0 2>&1
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /F /V "fid_D2Latency" /T REG_DWORD /d 0 2>&1
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /F /V "fid_D3Latency" /T REG_DWORD /d 0 2>&1
)
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "JPEGImportQuality" /d 4 /t REG_DWORD /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MenuShowDelay" /d 0 /t REG_DWORD /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseHoverTime" /d 0 /t REG_DWORD /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /d 0 /t REG_DWORD /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Keyboard" /v "KeyboardDelay" /d 0 /t REG_DWORD /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Keyboard" /v "KeyboardSpeed" /d 31 /t REG_DWORD /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /d 0xa /t REG_DWORD /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /d 0xa /t REG_DWORD /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "LazyModeTimeout" /d 0x3a98 /t REG_DWORD /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\usbflags" /v "fid_D1Latency" /d 0 /t REG_DWORD /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\usbflags" /v "fid_D2Latency" /d 0 /t REG_DWORD /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\usbflags" /v "fid_D3Latency" /d 0 /t REG_DWORD /f
exit

:networkE
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do (
  reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
  reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
  reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
)
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d "0" /f

for /f %%a in ('reg query HKLM /v "*WakeOnMagicPacket" /s ^| findstr  "HKEY"') do (
    for /f %%i in ('reg query "%%a" /v "GigaLite" ^| findstr "HKEY"') do (
        reg add "%%i" /v "GigaLite" /t REG_SZ /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "*EEE" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*EEE" /t REG_DWORD /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "*FlowControl" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*FlowControl" /t REG_DWORD /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "PowerSavingMode" ^| findstr "HKEY"') do (
        reg add "%%i" /v "PowerSavingMode" /t REG_DWORD /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "EnableSavePowerNow" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnableSavePowerNow" /t REG_SZ /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "EnablePowerManagement" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnablePowerManagement" /t REG_SZ /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "EnableGreenEthernet" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "EnableDynamicPowerGating" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnableDynamicPowerGating" /t REG_SZ /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "EnableConnectedPowerGating" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnableConnectedPowerGating" /t REG_SZ /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "AutoPowerSaveModeEnabled" ^| findstr "HKEY"') do (
        reg add "%%i" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "AutoDisableGigabit" ^| findstr "HKEY"') do (
        reg add "%%i" /v "AutoDisableGigabit" /t REG_DWORD /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "AdvancedEEE" ^| findstr "HKEY"') do (
        reg add "%%i" /v "AdvancedEEE" /t REG_DWORD /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "ULPMode" ^| findstr "HKEY"') do (
        reg add "%%i" /v "ULPMode" /t REG_SZ /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "ReduceSpeedOnPowerDown" ^| findstr "HKEY"') do (
        reg add "%%i" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "EnablePME" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnablePME" /t REG_SZ /d "0" /f
    )
) >nul 2>nul
netsh int tcp set heuristics disabled
netsh int tcp set supplemental Internet congestionprovider=ctcp
netsh int tcp set global timestamps=disabled
netsh int tcp set global rsc=disabled
for /f "tokens=1" %%i in ('netsh int ip show interfaces ^| findstr [0-9]') do (
	netsh int ip set interface %%i routerdiscovery=disabled store=persistent
)
exit

:networkD
netsh int ip reset
netsh winsock reset
:: Extremely awful way to do this
for /f "tokens=3* delims=: " %%i in ('pnputil /enum-devices /class Net /connected^| findstr "Device Description:"') do (
	devmanview /uninstall "%%i %%j"
)
pnputil /scan-devices

