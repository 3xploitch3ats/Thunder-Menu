@echo off
setlocal

rem Ouvre une fenêtre pour choisir un dossier, récupère dans MSYS_DIR
for /f "delims=" %%d in ('powershell -NoProfile -Command "Add-Type -AssemblyName System.Windows.Forms; $f=New-Object System.Windows.Forms.FolderBrowserDialog; if($f.ShowDialog() -eq 'OK'){ $f.SelectedPath }"') do set "MSYS_DIR=%%d"

if not defined MSYS_DIR (
    echo Aucune sélection, sortie.
    pause
    exit /b
)

echo Dossier MSYS sélectionné : %MSYS_DIR%

rem Supprimer les fichiers binaires numpy conflictuels
del /f /q "%MSYS_DIR%\mingw64\bin\f2py.exe"
del /f /q "%MSYS_DIR%\mingw64\bin\numpy-config.exe"

rem Supprimer le dossier include numpy
set "INCLUDE_NPY=%MSYS_DIR%\mingw64\include\python3.12\numpy"
echo Suppression du dossier include numpy : %INCLUDE_NPY%
rmdir /s /q "%INCLUDE_NPY%"

rem Nettoyage des dossiers numpy dans site-packages
set "SITE_PACKAGES=%MSYS_DIR%\mingw64\lib\python3.12\site-packages"
echo Nettoyage de numpy dans site-packages : %SITE_PACKAGES%

rem Ferme python.exe si en cours d'exécution
taskkill /f /im python.exe >nul 2>&1

rmdir /s /q "%SITE_PACKAGES%\numpy"
rmdir /s /q "%SITE_PACKAGES%\numpy-*.dist-info"
rmdir /s /q "%SITE_PACKAGES%\numpy-*.egg-info"

echo Nettoyage terminé.
pause
