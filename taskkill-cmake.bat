@echo off
:: Vérifie si le script est lancé en admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Pas en mode administrateur, relance en mode admin...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb runAs"
    exit /b
)

echo Script lancé en mode administrateur.
echo Fermeture de cmake.exe...

taskkill /f /im cmake.exe

echo Terminé.
pause
