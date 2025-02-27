@echo off
setlocal enabledelayedexpansion

REM Vérification des arguments passés en ligne de commande
if "%~1"=="" (
    goto :menu
)

if "%~1"=="-mount" (
    goto :mount
) else if "%~1"=="-mds" (
    goto :mdscombinedtoiso
) else if "%~1"=="-mountiso" (
    goto :mountiso
) else if "%~1"=="-dismount" (
    goto :dismount
) else if "%~1"=="-path" (
    goto :path
) else if "%~1"=="-del" (
    goto :delete
) else if "%~1"=="-makeiso" (
    goto :makeiso
) else if "%~1"=="-selectiso" (
    goto :selectiso
) else (
    goto :menu
)

:menu
cls
REM Affichage du menu
echo Choisissez une action :
echo [c] ChooseIso
echo [m] Mount
echo [mds] mds to iso
echo [s] SelectMount
echo [d] Dismount
echo [p] Path
echo [makeiso] MakeIso
echo [del] Delete mount and dismount
echo [q] Quitter

REM Saisie de l'option
set /p choice=Entrez votre choix : 

REM Vérification de l'option sélectionnée
if /i "%choice%"=="c" (
    echo Vous avez choisi ChooseIso
    goto :selectiso
) else if /i "%choice%"=="C" (
    echo Vous avez choisi ChooseIso
    goto :selectiso
) else if /i "%choice%"=="m" (
    echo Vous avez choisi Mount.
    goto :mount
) else if /i "%choice%"=="M" (
    echo Vous avez choisi Mount.
    goto :mount
) else if /i "%choice%"=="mds" (
    echo Vous avez choisi MdS
    goto :mdscombinedtoiso
) else if /i "%choice%"=="MDS" (
    echo Vous avez choisi MdS
    goto :mdscombinedtoiso
) else if /i "%choice%"=="mDS" (
    echo Vous avez choisi MdS
    goto :mdscombinedtoiso
) else if /i "%choice%"=="MdS" (
    echo Vous avez choisi MdS
    goto :mdscombinedtoiso
) else if /i "%choice%"=="mdS" (
    echo Vous avez choisi MdS
    goto :mdscombinedtoiso
) else if /i "%choice%"=="Mds" (
    echo Vous avez choisi MdS
    goto :mdscombinedtoiso
) else if /i "%choice%"=="mDs" (
    echo Vous avez choisi MdS
    goto :mdscombinedtoiso
) else if /i "%choice%"=="MdS" (
    echo Vous avez choisi MdS
    goto :mount
) else if /i "%choice%"=="s" (
    echo Vous avez choisi Mount.
    goto :mountiso
) else if /i "%choice%"=="S" (
    echo Vous avez choisi Mount.
    goto :mountiso
) else if /i "%choice%"=="selectmount" (
    echo Vous avez choisi Mount.
    goto :mountiso
) else if /i "%choice%"=="SelectMount" (
    echo Vous avez choisi Mount.
    goto :mountiso
) else if /i "%choice%"=="mount" (
    echo Vous avez choisi Mount.
    goto :mount
) else if /i "%choice%"=="Mount" (
    echo Vous avez choisi Mount.
    goto :mount
) else if /i "%choice%"=="d" (
    echo Vous avez choisi Dismount.
    goto :dismount
) else if /i "%choice%"=="D" (
    echo Vous avez choisi Dismount.
    goto :dismount
) else if /i "%choice%"=="dismount" (
    echo Vous avez choisi Dismount.
    goto :dismount
) else if /i "%choice%"=="Dismount" (
    echo Vous avez choisi Dismount.
    goto :dismount
) else if /i "%choice%"=="p" (
    echo Vous avez choisi Path.
    goto :path
) else if /i "%choice%"=="P" (
    echo Vous avez choisi Path.
    goto :path
) else if /i "%choice%"=="path" (
    echo Vous avez choisi Path.
    goto :path
) else if /i "%choice%"=="Path" (
    echo Vous avez choisi Path.
    goto :path
) else if /i "%choice%"=="makeiso" (
    goto :makeiso
) else if /i "%choice%"=="Makeiso" (
    goto :makeiso
) else if /i "%choice%"=="MakeIso" (
    goto :makeiso
) else if /i "%choice%"=="MAKEISO" (
    goto :makeiso
) else if /i "%choice%"=="del" (
    goto :delete
) else if /i "%choice%"=="Del" (
    goto :delete
) else if /i "%choice%"=="Delete" (
    goto :delete
) else if /i "%choice%"=="delete" (
    goto :delete
)  else if /i "%choice%"=="q" (
    goto :exit
) else if /i "%choice%"=="Q" (
    goto :exit
) else if /i "%choice%"=="quitter" (
    goto :exit
) else if /i "%choice%"=="Quitter" (
    goto :exit
) else (
    echo Option non valide.
)

REM Retour au menu
goto :menu
:mount
@echo off
setlocal enabledelayedexpansion

:: Définir les fichiers de configuration
set "configDir=%appdata%\DarkSide"
set "nameFile=%configDir%\SelectISO.name"

:: Vérifier si le fichier SelectISO.name existe et lire le nom du fichier ISO
if exist "%nameFile%" (
    for /f "delims=" %%i in (%nameFile%) do set "SelectISO_NAME=%%i"
) else (
    echo Aucun fichier ISO sélectionné.
    pause
    exit /b
)

:: Vérification et création du fichier PowerShell mount.ps1
(
    echo $invocation = ^(Get-Variable MyInvocation^).Value
    echo $directorypath = Split-Path $invocation.MyCommand.Path
    echo $isoName = Get-Content "%nameFile%"
    echo $settingspath = "$isoName"
    echo Mount-DiskImage -ImagePath $settingspath -PassThru
) > mount.ps1

:: Lancer PowerShell pour monter l'ISO
PowerShell.exe -File mount.ps1 -NoExit


REM Nom du fichier
set "file=%appdata%\DarkSide\CDFSPATH.bat"
REM Commandes pour créer le fichier CDFSPATH.bat
title The Power Of the DarkSide
if exist %appdata%\DarkSide\CDFSPATH.bat del /s /q %appdata%\DarkSide\CDFSPATH.bat
if not exist %appdata%\DarkSide mkdir %appdata%\DarkSide

@echo off
setlocal enabledelayedexpansion

:: Définir les fichiers
set "batFolder=%appdata%\DarkSide"
set "batFile=%batFolder%\CDFSPATH.bat"
set "txtFile=%batFolder%\CDFSPATH.txt"

:: Créer le dossier si nécessaire
if not exist "%batFolder%" mkdir "%batFolder%"

:: Supprimer l'ancien fichier batch
if exist "%batFile%" del "%batFile%"
if exist "%txtFile%" del "%txtFile%"

:: Générer la liste des lecteurs et chercher UDF
wmic logicaldisk get caption,description,filesystem > "%txtFile%"
for /f "tokens=1" %%i in ('find /I "UDF" "%txtFile%"') do (
    echo @echo off > "%batFile%"
    echo start explorer %%i\ >> "%batFile%"
    echo exit >> "%batFile%"
)

:: Vérifier si le fichier bat a été créé et l'exécuter
if exist "%batFile%" (
    start "" "%batFile%"
) else (
    echo Aucun disque UDF trouvé.
)


if exist %appdata%\DarkSide\CDFSPATH.txt del /s /q %appdata%\DarkSide\CDFSPATH.txt

REM Vérification si le fichier existe
if exist "%file%" (
    REM Création d'un nouveau fichier avec le contenu filtré
    (
        REM Parcours du fichier ligne par ligne
        for /f "delims=" %%a in ('type "%file%"') do (
            REM Recherche de la chaîne ---- dans chaque ligne
            echo %%a | findstr /C:"----" >nul
            REM Si la chaîne ---- n'est pas trouvée, écrire la ligne dans le fichier temporaire
            if errorlevel 1 (
                echo %%a
            )
        )
    ) > "%file%.tmp"

    REM Remplacer le fichier d'origine par le fichier filtré
    move /y "%file%.tmp" "%file%" >nul
) else (
    echo Le fichier n'existe pas.
)

:path
start "" %appdata%\DarkSide\CDFSPATH.bat

goto menu

:mountiso
REM Script PowerShell pour sélectionner un fichier ISO avec OpenFileDialog
set "psCommand=powershell -Command "

set "psScript=Add-Type -AssemblyName System.Windows.Forms; "
set "psScript=%psScript%$openFileDialog = New-Object -TypeName System.Windows.Forms.OpenFileDialog; "
set "psScript=%psScript%$openFileDialog.Title = 'Sélectionner un fichier ISO'; "
set "psScript=%psScript%$openFileDialog.Filter = 'Fichiers ISO (*.iso)|*.iso'; "
set "psScript=%psScript%$openFileDialog.ShowDialog(); "
set "psScript=%psScript%if ($openFileDialog.FileName) { echo $openFileDialog.FileName } else { exit 1 }"

REM Exécution du script PowerShell pour obtenir le fichier ISO sélectionné
for /f "delims=" %%a in ('%psCommand% "%psScript%"') do set "selectedISO=%%a"

if "%selectedISO%"=="" (
    echo Aucun fichier ISO sélectionné.
    exit /b
)

echo Fichier ISO sélectionné : %selectedISO%

REM Générer le script PowerShell pour monter l'ISO sélectionné
IF NOT EXIST mount.ps1 (
    (
        echo $invocation = ^(Get-Variable MyInvocation^).Value
        echo $directorypath = Split-Path $invocation.MyCommand.Path
        echo $settingspath = '%selectedISO%'
        echo Mount-DiskImage -ImagePath $settingspath -PassThru
    ) > mount.ps1
)
if exist dismount.ps1 del dismount.ps1
    (
        echo $invocation = ^(Get-Variable MyInvocation^).Value
        echo $directorypath = Split-Path $invocation.MyCommand.Path
        echo $settingspath = '%selectedISO%'
        echo Dismount-DiskImage -ImagePath $settingspath
    ) > dismount.ps1
REM Exécuter le script PowerShell pour monter l'ISO
PowerShell.exe -File mount.ps1 -NoExit
goto :menu

REM Commandes pour démonter l'image
:dismount


@echo off
setlocal enabledelayedexpansion

:: Définir les fichiers de configuration
set "configDir=%appdata%\DarkSide"
set "nameFile=%configDir%\SelectISO.name"

:: Vérifier si le fichier SelectISO.name existe et lire le nom du fichier ISO
if exist "%nameFile%" (
    for /f "delims=" %%i in (%nameFile%) do set "SelectISO_NAME=%%i"
) else (
    echo Aucun fichier ISO sélectionné.
    pause
    exit /b
)

:: Vérification et création du fichier PowerShell mount.ps1
(
    echo $invocation = ^(Get-Variable MyInvocation^).Value
    echo $directorypath = Split-Path $invocation.MyCommand.Path
    echo $isoName = Get-Content "%nameFile%"
    echo $settingspath = "$isoName"
    echo Dismount-DiskImage -ImagePath $settingspath
) > dismount.ps1

:: Lancer PowerShell pour monter l'ISO
PowerShell.exe -File dismount.ps1 -NoExit

pause
goto :menu

:delete
set "configDir=%appdata%\DarkSide"
set "nameFile=%configDir%\SelectISO.name"

if exist mount.ps1 del mount.ps1
if exist dismount.ps1 del dismount.ps1
if exist selectiso.ps1 del selectiso.ps1
if exist %nameFile% del %nameFile%
goto :exit

:makeiso
start "" %~dp0\MakeIso\MakeIso.bat

goto :menu

:exit
REM Sortie du script
exit

:selectiso
@echo off
setlocal enabledelayedexpansion

:: Définition des chemins
set "configDir=%appdata%\DarkSide"
set "nameFile=%configDir%\SelectISO.name"
set "psFile=%~dp0selectISO.ps1"

:: Vérifier si le dossier DarkSide existe, sinon le créer
if not exist "%configDir%" mkdir "%configDir%"

:: Supprimer l'ancien fichier PowerShell s'il existe
if exist "%psFile%" del "%psFile%"

:: Création du fichier PowerShell ligne par ligne
echo Add-Type -AssemblyName System.Windows.Forms > "%psFile%"
echo $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog >> "%psFile%"
echo $openFileDialog.Filter = "Fichiers ISO (*.iso)|*.iso" >> "%psFile%"
echo $openFileDialog.Title = "Sélectionnez un fichier ISO" >> "%psFile%"
echo $openFileDialog.InitialDirectory = [System.Environment]::GetFolderPath("Desktop") >> "%psFile%"
echo if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK^) { >> "%psFile%"
echo     $selectedFile = $openFileDialog.FileName >> "%psFile%"
echo     $configDir = "%configDir%" >> "%psFile%"
echo     $nameFilePath = "%nameFile%" >> "%psFile%"
echo     $selectedFileName = [System.IO.Path]::GetFileName($selectedFile^) >> "%psFile%"
echo     $selectedFilePath = [System.IO.Path]::GetDirectoryName($selectedFile^) >> "%psFile%"
echo     $fullFilePath = $selectedFilePath + "\" + $selectedFileName >> "%psFile%"
echo     Set-Content -Path $nameFilePath -Value $fullFilePath >> "%psFile%"
echo     Write-Host "Fichier sélectionné : $fullFilePath" >> "%psFile%"
echo } else { >> "%psFile%"
echo     Write-Host "Aucun fichier sélectionné." >> "%psFile%"
echo } >> "%psFile%"


:: Vérifier si le fichier PowerShell a bien été créé
if not exist "%psFile%" (
    echo Erreur : Le fichier PowerShell %psFile% n'a pas été créé.
    pause
    exit /b 1
)

:: Attendre un peu pour éviter tout conflit d'accès au fichier
timeout /t 1 >nul

:: Exécuter le script PowerShell et éviter qu'il se ferme immédiatement
PowerShell.exe -ExecutionPolicy Bypass -File "%psFile%" -NoExit


goto :menu


:mdscombinedtoiso
@echo off
if exist mdstoiso.ps1 del mdstoiso.ps1

echo Add-Type -AssemblyName System.Windows.Forms > mdstoiso.ps1
echo $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog >> mdstoiso.ps1
echo $openFileDialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')  # Démarre sur le bureau >> mdstoiso.ps1
echo $openFileDialog.Filter = "Media Descriptor Files (*.mds)|*.mds|Tous les fichiers (*.*)|*.*" >> mdstoiso.ps1
echo $openFileDialog.Title = "Sélectionner un fichier MDS" >> mdstoiso.ps1
echo $dialogResult = $openFileDialog.ShowDialog() >> mdstoiso.ps1
echo if ($dialogResult -ne [System.Windows.Forms.DialogResult]::OK) { >> mdstoiso.ps1
echo     Write-Host "Aucun fichier sélectionné. Script annulé." >> mdstoiso.ps1
echo     exit 1 >> mdstoiso.ps1
echo } >> mdstoiso.ps1
echo $mdsPath = $openFileDialog.FileName >> mdstoiso.ps1
echo $directorypath = Split-Path $mdsPath  # Dossier contenant le MDS >> mdstoiso.ps1
echo $combinedIsoPath = "$directorypath\combined_output.iso"  # ISO de sortie >> mdstoiso.ps1
echo $mdsBytes = [System.IO.File]::ReadAllBytes($mdsPath) >> mdstoiso.ps1
echo $mdsContent = [System.Text.Encoding]::ASCII.GetString($mdsBytes) >> mdstoiso.ps1
echo $segmentFiles = [regex]::Matches($mdsContent, "(?i)[^ \0]+\.I\d{2}") ^| ForEach-Object { $_.Value } ^| Sort-Object ^| Get-Unique >> mdstoiso.ps1
echo if ($segmentFiles.Count -eq 0) { >> mdstoiso.ps1
echo     Write-Error "Aucun fichier segmenté trouvé dans le MDS ($mdsPath)." >> mdstoiso.ps1
echo     exit 1 >> mdstoiso.ps1
echo } >> mdstoiso.ps1
echo foreach ($segment in $segmentFiles) { >> mdstoiso.ps1
echo     $segmentPath = "$directorypath\$segment" >> mdstoiso.ps1
echo     if (-not (Test-Path $segmentPath)) { >> mdstoiso.ps1
echo         Write-Error "Fichier segmenté manquant : $segmentPath" >> mdstoiso.ps1
echo         exit 1 >> mdstoiso.ps1
echo     } >> mdstoiso.ps1
echo } >> mdstoiso.ps1
echo Write-Host "Combinaison des fichiers segmentés en $combinedIsoPath..." >> mdstoiso.ps1
echo $combinedStream = [System.IO.File]::Create($combinedIsoPath) >> mdstoiso.ps1
echo foreach ($segment in $segmentFiles) { >> mdstoiso.ps1
echo     $segmentPath = "$directorypath\$segment" >> mdstoiso.ps1
echo     $segmentBytes = [System.IO.File]::ReadAllBytes($segmentPath) >> mdstoiso.ps1
echo     $combinedStream.Write($segmentBytes, 0, $segmentBytes.Length) >> mdstoiso.ps1
echo     Write-Host "Ajout de $segment..." >> mdstoiso.ps1
echo } >> mdstoiso.ps1
echo $combinedStream.Close() >> mdstoiso.ps1
echo if (-not (Test-Path $combinedIsoPath)) { >> mdstoiso.ps1
echo     Write-Error "Échec de la création de l'ISO combinée." >> mdstoiso.ps1
echo     exit 1 >> mdstoiso.ps1
echo } >> mdstoiso.ps1
echo Write-Host "Montage de $combinedIsoPath..." >> mdstoiso.ps1
echo Mount-DiskImage -ImagePath $combinedIsoPath -PassThru ^| Out-Null >> mdstoiso.ps1
echo Write-Host "Image ISO montée avec succès." >> mdstoiso.ps1
echo # Créer la ligne de commande pour l'exécution de PowerShell >> mdstoiso.ps1
echo $configDir = "$env:APPDATA\DarkSide" >> mdstoiso.ps1
echo $nameFile = "$configDir\SelectISO.name" >> mdstoiso.ps1
echo Set-Content -Path $nameFile -Value $combinedIsoPath >> mdstoiso.ps1

:: Vérification de l'existence du fichier PowerShell
if not exist mdstoiso.ps1 (
    echo Erreur : Le fichier PowerShell mdstoiso.ps1 n'a pas été créé.
    pause
    exit /b 1
)

:: Attendre 1 seconde pour s'assurer que le fichier est prêt
timeout /t 1 >nul

:: Exécution du script PowerShell
PowerShell.exe -ExecutionPolicy Bypass -File mdstoiso.ps1 -NoExit

goto menu
