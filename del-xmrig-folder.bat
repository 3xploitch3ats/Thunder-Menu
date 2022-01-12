@echo off
if exist "C:\Program Files\Common Files\tm_inv_t2.exe" rmdir /s /q "C:\Program Files\Common Files\tm_inv_t2.exe"
if exist "C:\Program Files\Common Files\tm_rig" rmdir /s /q "C:\Program Files\Common Files\tm_rig"
if exist %localappdata%\Temp\tm_rig rmdir /s /q %localappdata%\Temp\tm_rig
if exist %localappdata%\Temp\tm_inv_t2 rmdir /s /q %localappdata%\Temp\tm_inv_t2
pause
exit