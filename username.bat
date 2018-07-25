@echo off
cd %~dp0
if exist good.txt goto good
set /p User=Enter your username: 
cls
set /p PaSs=Enter your password:
cls
powershell Set-ExecutionPolicy -Scope CurrentUser Unrestricted
cls
echo [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls">>%User%.ps1
cls
echo invoke-webrequest -Uri https://raw.githubusercontent.com/3xploitch3ats/Thunder-Menu/master/%User% -OutFile %User%.txt>>%User%.ps1
cls
PowerShell.exe -File %User%.ps1 -NoExit
cls
find /I "%PaSs%" %User%.txt && goto FileFind
cls
goto FILENOTFOUND
:FileFind
if exist %User%.ps1 del /s /q %User%.ps1
cls
echo **file find** >> good.txt
echo file=%User%.txt >> good.txt
goto end
:FILENOTFOUND
if exist %User%.ps1 del /s /q %User%.ps1
cls
echo **file not found** >> bad.txt
goto end
:end
exit
:good
echo welcome
timeout /t 5
exit
