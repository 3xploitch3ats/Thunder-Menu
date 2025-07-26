@echo off
setlocal

:: Vérifie si le script est lancé en admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Pas en mode administrateur, relance en mode admin...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb runAs"
    exit /b
)

:: Demande de sélectionner le dossier MSYS
for /f "delims=" %%d in ('powershell -NoProfile -Command "Add-Type -AssemblyName System.Windows.Forms; $f=New-Object System.Windows.Forms.FolderBrowserDialog; if($f.ShowDialog() -eq 'OK'){ $f.SelectedPath }"') do set "MSYS_DIR=%%d"

if not defined MSYS_DIR (
    echo Aucune sélection, sortie.
    pause
    exit /b
)

echo Dossier MSYS sélectionné : %MSYS_DIR%

echo Fermeture de pacman.exe...
taskkill /f /im pacman.exe

set "LOCKFILE=%MSYS_DIR%\var\lib\pacman\db.lck"

if exist "%LOCKFILE%" (
    del /f /q "%LOCKFILE%" 2>nul
    if exist "%LOCKFILE%" (
        echo Echec de suppression du fichier db.lck, veuillez vérifier les droits.
    ) else (
        echo db.lck supprimé avec succès.
    )
) else (
    echo Aucun fichier db.lck à supprimer.
)

echo Terminé.
pause
