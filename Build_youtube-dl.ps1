<#
.SYNOPSIS
Installation et compilation automatique sous MSYS2 + Python + PyInstaller pour youtube-dl.

.PARAMETER BuildType
Type de build (par défaut Release).

.PARAMETER IsAdminCompile
Indique si lancé en admin (interne).
#>

param(
    [string]$BuildType = "Release",
    [switch]$IsAdminCompile = $false
)

function Show-Message {
    param(
        [string]$Message,
        [ConsoleColor]$Color = "White"
    )
    $timestamp = Get-Date -Format 'HH:mm:ss'
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
}

function Pause-IfInteractive {
    if ($Host.Name -eq 'ConsoleHost') {
        Write-Host
        Write-Host "Appuyez sur une touche pour continuer..." -ForegroundColor Yellow
        [void][System.Console]::ReadKey($true)
    }
}

function Load-MSYS2Config {
    $ConfigFile = Join-Path $PSScriptRoot "msys2_config.json"
    if (Test-Path $ConfigFile) {
        try {
            $conf = Get-Content $ConfigFile -Raw | ConvertFrom-Json
            $msysPath = $conf.MSYS2Path
            if (Test-Path (Join-Path $msysPath "msys2.exe")) {
                return $msysPath
            }
        } catch {
            Show-Message "Erreur lors du chargement du fichier de config MSYS2." Red
            Pause-IfInteractive
            exit 1
        }
    }
    return $null
}

function Save-MSYS2Config($msysPath) {
    $ConfigFile = Join-Path $PSScriptRoot "msys2_config.json"
    $obj = @{
        MSYS2Path = $msysPath
        LastUpdated = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
    $obj | ConvertTo-Json -Depth 3 | Out-File $ConfigFile -Encoding UTF8
}

function Select-MSYS2 {
    Add-Type -AssemblyName System.Windows.Forms
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "MSYS2 Executable (msys2.exe)|msys2.exe"
    $dialog.Title = "Sélectionnez le fichier msys2.exe"
    if ($dialog.ShowDialog() -eq "OK") {
        $path = Split-Path $dialog.FileName
        Save-MSYS2Config $path
        return $path
    } else {
        Show-Message "Sélection annulée par l'utilisateur." Red
        Pause-IfInteractive
        exit 1
    }
}

function Get-MSYS2Path {
    $stored = Load-MSYS2Config
    if ($stored) {
        Show-Message "Configuration MSYS2 trouvée en cache : $stored" Cyan
        return $stored
    }

    $defaults = @(
        "C:\msys64",
        "$env:ProgramFiles\msys64",
        "$env:ProgramFiles(x86)\msys64"
    )

    foreach ($d in $defaults) {
        if (Test-Path (Join-Path $d "msys2.exe")) {
            Show-Message "MSYS2 détecté dans $d" Green
            Save-MSYS2Config $d
            return $d
        }
    }

    Show-Message "MSYS2 non détecté automatiquement, demande de sélection..." Yellow
    return Select-MSYS2
}

function Backup-And-Change-Mirrors {
    param ([string]$msysPath)

    $mirrorFileMSYS = Join-Path $msysPath "etc\pacman.d\mirrorlist.msys"
    $mirrorFileMINGW64 = Join-Path $msysPath "etc\pacman.d\mirrorlist.mingw64"
    $backupMSYS = "$mirrorFileMSYS.bak"
    $backupMINGW64 = "$mirrorFileMINGW64.bak"

    if (-not (Test-Path $backupMSYS)) {
        Copy-Item $mirrorFileMSYS $backupMSYS -Force
        Show-Message "Sauvegarde mirrorlist.msys effectuée" Green
    }
    if (-not (Test-Path $backupMINGW64)) {
        Copy-Item $mirrorFileMINGW64 $backupMINGW64 -Force
        Show-Message "Sauvegarde mirrorlist.mingw64 effectuée" Green
    }

    $newMirrorsMSYS = @"
Server = https://mirror.msys2.org/msys/x86_64
"@

    $newMirrorsMINGW64 = @"
Server = https://mirror.msys2.org/mingw/x86_64
"@

    Set-Content -Path $mirrorFileMSYS -Value $newMirrorsMSYS -Encoding ASCII
    Set-Content -Path $mirrorFileMINGW64 -Value $newMirrorsMINGW64 -Encoding ASCII

    Show-Message "Miroirs MSYS2 mis à jour vers mirror.msys2.org" Yellow
}

function Convert-PathToMSYS {
    param([string]$winPath)
    $winPath = $winPath -replace '\\', '/'
    if ($winPath -match '^(.:)(/.*)') {
        $drive = $matches[1].Substring(0,1).ToLower()
        $rest = $matches[2]
        return "/$drive$rest"
    }
    return $winPath
}

function Ensure-PythonInstalled {
    param([string]$bashExe)

    Show-Message "Vérification de Python MSYS et MinGW64..." Cyan

    $resMSYS = & $bashExe -lc "pacman -Qs python | grep '^local/python '"
    if (-not $resMSYS) {
        Show-Message "Python MSYS non installé, installation en cours..." Yellow
        & $bashExe -lc "pacman -S --needed --noconfirm python python-pip python-setuptools"
        if ($LASTEXITCODE -ne 0) {
            Show-Message "Échec installation Python MSYS" Red
            Pause-IfInteractive
            exit 1
        }
        Show-Message "Python MSYS installé." Green
    } else {
        Show-Message "Python MSYS déjà installé." Green
    }

    $resMinGW = & $bashExe -lc "pacman -Qs mingw-w64-x86_64-python"
    if (-not $resMinGW) {
        Show-Message "Python MinGW64 non installé, installation en cours..." Yellow
        & $bashExe -lc "pacman -S --needed --noconfirm mingw-w64-x86_64-python mingw-w64-x86_64-python-pip mingw-w64-x86_64-python-setuptools mingw-w64-x86_64-python-wheel"
        if ($LASTEXITCODE -ne 0) {
            Show-Message "Échec installation Python MinGW64" Red
            Pause-IfInteractive
            exit 1
        }
        Show-Message "Python MinGW64 installé." Green
    } else {
        Show-Message "Python MinGW64 déjà installé." Green
    }

    $bashRc = Join-Path $env:USERPROFILE ".bashrc"
    $aliasCmd = "alias python=python3"
    if (-not (Test-Path $bashRc)) {
        New-Item -Path $bashRc -ItemType File -Force | Out-Null
        Show-Message ".bashrc créé." Yellow
    }
    $content = Get-Content $bashRc -Raw -ErrorAction SilentlyContinue
    if ($content -notmatch [regex]::Escape($aliasCmd)) {
        Add-Content -Path $bashRc -Value $aliasCmd
        Show-Message "Alias python ajouté dans .bashrc" Green
    } else {
        Show-Message "Alias python déjà présent dans .bashrc" Cyan
    }
}

function Update-MSYS2Packages {
    param([string]$bashExe)

    $maxRetries = 3
    for ($i=1; $i -le $maxRetries; $i++) {
        Show-Message "Tentative $i : mise à jour base paquets (pacman -Sy)..." Yellow
        & $bashExe -lc "pacman -Sy --noconfirm"
        if ($LASTEXITCODE -eq 0) { break }
        elseif ($i -lt $maxRetries) {
            Show-Message "Erreur lors de la synchronisation, retry dans 5s..." Red
            Start-Sleep -Seconds 5
        } else {
            Show-Message "Échec synchronisation des paquets après plusieurs tentatives." Red
            Pause-IfInteractive
            exit 1
        }
    }
    Show-Message "Mise à jour complète des paquets (pacman -Su)..." Yellow
    & $bashExe -lc "pacman -Su --noconfirm"
    if ($LASTEXITCODE -ne 0) {
        Show-Message "Erreur lors de la mise à jour complète des paquets." Red
        Pause-IfInteractive
        exit 1
    }
}

function Install-MinGW64Packages {
    param([string]$bashExe)

    $requiredMingwPackages = @(
        "mingw-w64-x86_64-python",
        "mingw-w64-x86_64-python-setuptools",
        "mingw-w64-x86_64-python-wheel",
        "mingw-w64-x86_64-toolchain",
        "mingw-w64-x86_64-gcc",
        "mingw-w64-x86_64-cmake",
        "make",
        "zip",
        "git"
    )
    foreach ($pkg in $requiredMingwPackages) {
        Show-Message "Installation du paquet : $pkg" Cyan
        & $bashExe -lc "pacman -S --needed --noconfirm $pkg"
        if ($LASTEXITCODE -ne 0) {
            Show-Message "Échec installation du paquet $pkg" Red
            Pause-IfInteractive
            exit 1
        }
    }
}

function Configure-MSYS2Environment {
    param([string]$msysPath)

    $bashProfile = Join-Path $env:USERPROFILE ".bashrc"
    $linesToAdd = @(
        'export PATH=/mingw64/bin:$PATH',
        'alias python=python3',
        '[[ $MSYSTEM != "MINGW64" ]] && exec bash --login -i -c "MSYSTEM=MINGW64 bash"',
        'export PATH=$PATH:"/c/Program Files/Pandoc"',
		'export MSYSTEM=MINGW64'
    )

    if (-not (Test-Path $bashProfile)) {
        New-Item -Path $bashProfile -ItemType File -Force | Out-Null
        Show-Message ".bashrc créé." Yellow
    }

    $currentContent = Get-Content -Path $bashProfile -Raw

    foreach ($line in $linesToAdd) {
        if ($currentContent -notmatch [regex]::Escape($line)) {
            Add-Content -Path $bashProfile -Value $line
            Show-Message "Ajouté à .bashrc : $line" Green
        } else {
            Show-Message "Déjà présent dans .bashrc : $line" Cyan
        }
    }
}

function Install-PandocIfMissing {
    $pandocExe = "$env:ProgramFiles\Pandoc\pandoc.exe"
    if (-not (Test-Path $pandocExe)) {
        Show-Message "Pandoc non trouvé, téléchargement en cours..." Yellow
        $pandocInstaller = Join-Path $PSScriptRoot "pandoc-installer.msi"
        Invoke-WebRequest -Uri "https://github.com/jgm/pandoc/releases/latest/download/pandoc-3.2.0-windows-x86_64.msi" -OutFile $pandocInstaller -UseBasicParsing
        Start-Process msiexec.exe -Wait -ArgumentList "/i `"$pandocInstaller`" /quiet"
        Remove-Item $pandocInstaller -Force
        Show-Message "Pandoc installé avec succès." Green

        # Ajout du chemin Pandoc dans la variable PATH utilisateur
        powershell.exe -Command '$path = [Environment]::GetEnvironmentVariable("Path", "User"); if (-not ($path.Split(";") -contains "C:\Program Files\Pandoc")) { [Environment]::SetEnvironmentVariable("Path", $path + ";C:\Program Files\Pandoc", "User"); Write-Host "✅ Chemin ajouté au PATH utilisateur." } else { Write-Host "ℹ️ Chemin déjà présent dans le PATH." }'
    } else {
        Show-Message "Pandoc déjà installé." Green
    }
}
# Fonction pour convertir un chemin Windows en chemin MSYS2
function Convert-ToMsysPath {
    param([string]$winPath)
    $drive = $winPath.Substring(0,1).ToLower()
    $rest = $winPath.Substring(2) -replace '\\', '/'
    return "/$drive/$rest"
}
function ConvertTo-UnixPath {
    param([string]$path)
    $path = $path -replace '\\','/'
    if ($path -match '^([a-zA-Z]):(/.*)') {
        $drive = $matches[1].ToLower()
        $rest = $matches[2]
        return "/$drive$rest"
    }
    return $path
}

# ----------- MAIN -----------

try {
    $msysPath = Get-MSYS2Path
    $bashExe = Join-Path $msysPath "usr\bin\bash.exe"
    $mingw64Exe = Join-Path $msysPath "mingw64.exe"
    if (-not (Test-Path $bashExe)) {
        Show-Message "bash.exe introuvable dans $msysPath" Red
        Pause-IfInteractive
        exit 1
    }
    if (-not (Test-Path $mingw64Exe)) {
        Show-Message "mingw64.exe introuvable dans $msysPath" Red
        Pause-IfInteractive
        exit 1
    }
    Show-Message "MSYS2 détecté à : $msysPath" Cyan

    Backup-And-Change-Mirrors -msysPath $msysPath
    Update-MSYS2Packages -bashExe $bashExe
    Ensure-PythonInstalled -bashExe $bashExe
    Install-MinGW64Packages -bashExe $bashExe
    Configure-MSYS2Environment -msysPath $msysPath
    Install-PandocIfMissing

    $sourceDir = Join-Path $PSScriptRoot "youtube-dl"

    # Clonage ou mise à jour git
    if (-not (Test-Path $sourceDir)) {
        Show-Message "Clonage de youtube-dl depuis GitHub dans $sourceDir..." Cyan
        git clone --recursive https://github.com/ytdl-org/youtube-dl.git $sourceDir
        if ($LASTEXITCODE -ne 0) {
            Show-Message "Échec du clonage git." Red
            Pause-IfInteractive
            exit 1
        }
    } else {
        Show-Message "Mise à jour de youtube-dl dans $sourceDir..." Cyan
        Push-Location $sourceDir
        git pull
        if ($LASTEXITCODE -ne 0) {
            Pop-Location
            Show-Message "Échec mise à jour git." Red
            Pause-IfInteractive
            exit 1
        }
        Pop-Location
    }
# --- Ajout python setup.py install ---
$sourceDirMSYS = Convert-ToMsysPath $sourceDir

Show-Message "Installation python setup.py install dans $sourceDir..." Cyan
& $bashExe -lc "cd '$sourceDirMSYS' && python3 setup.py install"
if ($LASTEXITCODE -ne 0) {
    Show-Message "Erreur lors de python setup.py install." Red
    Pause-IfInteractive
    exit 1
}

if (Test-Path (Join-Path $sourceDir "Makefile")) {
    Show-Message "Lancement de make install dans $sourceDir..." Cyan
    $sourceDirMSYS = $sourceDir -replace '^([A-Za-z]):', { "/$($args[0].ToLower())" } -replace '\\', '/'
    $command = "cd '$sourceDirMSYS' && make install"
    & $bashExe -c "MSYSTEM=MINGW64 bash --login -c `"$command`""
    if ($LASTEXITCODE -ne 0) {
        Show-Message "Erreur lors de make install." Red
        Pause-IfInteractive
        exit 1
    }
} else {
    Show-Message "Pas de Makefile trouvé, make install ignoré." Yellow
}


    Show-Message "Recherche récursive du fichier __main__.py ou main.py dans $sourceDir..." Cyan
    #$mainPy = Get-ChildItem -Path $sourceDir -Recurse -File -Include "__main__.py","main.py" -ErrorAction SilentlyContinue | Select-Object -First 1
$sourceDirR = Join-Path $PSScriptRoot "youtube-dl"
$targetDirR = Join-Path $sourceDirR "youtube_dl"

Write-Host "Je vais dans le dossier : $targetDir"
Set-Location $targetDirR

$mainPy = Get-ChildItem -Path . -Recurse -File -Include "__main__.py","main.py" -ErrorAction SilentlyContinue | Select-Object -First 1

	if (-not $mainPy) {
        Show-Message "Erreur : fichier __main__.py ou main.py introuvable dans $sourceDir ni ses sous-dossiers." Red
        Pause-IfInteractive
        exit 1
    }
    Show-Message "Fichier trouvé : $($mainPy.FullName)" Green

    $mainPyUnix = ConvertTo-UnixPath $mainPy.FullName
    $sourceDirUnix = ConvertTo-UnixPath $sourceDir

    Show-Message "Création / mise à jour de l'environnement virtuel Python..." Cyan
    $venvPath = Join-Path $sourceDir "venv"
    $venvPathUnix = ConvertTo-UnixPath $venvPath
    # Création venv avec bash
    & $bashExe -lc "python3 -m venv --copies '$venvPathUnix'"
    if ($LASTEXITCODE -ne 0) {
        Show-Message "Échec création venv" Red
        Pause-IfInteractive
        exit 1
    }


    Show-Message "Mise à jour pip, setuptools, wheel dans venv..." Cyan
    & $bashExe -lc "'$venvPathUnix/bin/python' -m pip install --upgrade pip setuptools wheel"
    if ($LASTEXITCODE -ne 0) {
        Show-Message "Échec mise à jour pip setuptools wheel" Red
        Pause-IfInteractive
        exit 1
    }

    Show-Message "Installation de nose (pour nosetests) dans venv..." Cyan
    & $bashExe -lc "'$venvPathUnix/bin/python' -m pip install nose"
    if ($LASTEXITCODE -ne 0) {
        Show-Message "Échec installation de nose" Red
        Pause-IfInteractive
        exit 1
    }

    #Show-Message "Installation de pyinstaller dans venv..." Cyan
    #& $bashExe -lc "'$venvPathUnix/bin/python' -m pip install pyinstaller"
    #if ($LASTEXITCODE -ne 0) {
       # Show-Message "Échec installation de pyinstaller" Red
      #  Pause-IfInteractive
     #   exit 1
    #}
#Show-Message "Vérification de PyInstaller dans le venv..." Cyan
#$res = & $bashExe -lc "'$venvPathUnix/bin/python' -m pip show pyinstaller" 2>$null
#if ([string]::IsNullOrWhiteSpace($res)) {
#    Show-Message "PyInstaller non présent, installation via pip..." Yellow
#	& $bashExe -lc "export MSYSTEM=MINGW64; bash --login -c '$venvPathUnix/bin/pip install pyinstaller==6.12.0'"
#	#& $bashExe -lc "MSYSTEM=MINGW64 bash --login -c '$venvPathUnix/bin/pip install pyinstaller==6.12.0'"
#    if ($LASTEXITCODE -ne 0) {
#        Show-Message "Échec installation PyInstaller" Red
#        Pause-IfInteractive
#        exit 1
#    } else {
#        Show-Message "PyInstaller installé avec succès." Green
#    }


#} else {
#    Show-Message "PyInstaller déjà installé dans le venv." Green
#}
$pythonScript = @"
#!/usr/bin/env python3
import os
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, messagebox

def check_and_install_pyinstaller():
    try:
        import PyInstaller
    except ImportError:
        print("[INFO] PyInstaller n'est pas installé. Installation...")
        result = subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller==6.12.0"])
        if result.returncode != 0:
            messagebox.showerror("Erreur", "Échec de l'installation de pyinstaller.")
            sys.exit(1)
        print("[✅] PyInstaller installé avec succès.")

def compile_file(file_path):
    script_dir = os.path.dirname(file_path)
    script_name = os.path.basename(file_path)
    exe_name = os.path.splitext(script_name)[0] + ".exe"

    command = [
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "--onefile",
        "--distpath", script_dir,
        "--workpath", os.path.join(script_dir, "build"),
        "--specpath", script_dir,
        file_path
    ]

    print(f"[INFO] Compilation de : {script_name}")
    print(f"[CMD] {' '.join(command)}")

    try:
        subprocess.run(command, check=True)
        print(f"[✅] Fichier compilé : {os.path.join(script_dir, exe_name)}")
        messagebox.showinfo("Succès", f"Compilation réussie :\n{exe_name}")
    except subprocess.CalledProcessError:
        messagebox.showerror("Erreur", "Échec de la compilation.")

def select_and_compile():
    root = tk.Tk()
    root.withdraw()

    file_path = filedialog.askopenfilename(
        title="Sélectionne un fichier Python",
        filetypes=[("Fichiers Python", "*.py")]
    )

    if not file_path:
        messagebox.showinfo("Annulé", "Aucun fichier sélectionné.")
        return

    compile_file(file_path)

if __name__ == "__main__":
    check_and_install_pyinstaller()
    if len(sys.argv) > 1:
        compile_file(sys.argv[1])
    else:
        select_and_compile()
"@

$scriptPath = Join-Path (Get-Location) "pyinstaller_builder.py"
Set-Content -Path $scriptPath -Value $pythonScript -Encoding UTF8

Write-Host "Script Python créé : $scriptPath"
Write-Host "Pour l'exécuter, lancez : $scriptPath"


    $distPath = Join-Path $sourceDir "dist"
    $buildPath = Join-Path $sourceDir "build"
    $specFile = Join-Path $sourceDir "youtube_dl.spec"
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $distPath,$buildPath,$specFile

    Show-Message "Compilation youtube-dl avec PyInstaller..." Cyan
    Push-Location $sourceDir

    #$pyInstallerCmd = "'$venvPathUnix/bin/python' -m PyInstaller --clean -y --onefile '$mainPyUnix'"

    # Appel via mingw64.exe -lc "<commande>"
    #& $mingw64Exe -lc $pyInstallerCmd
#$sourceDir = $PSScriptRoot
#$pyBuilderPath = Join-Path $sourceDir "pyinstaller_builder.py"
#$pyBuilderPathUnix = $pyBuilderPath -replace '\\', '/'
#if ($pyBuilderPathUnix -match '^([A-Za-z]):') {
#    $drive = $matches[1].ToLower()
#    $pyBuilderPathUnix = $pyBuilderPathUnix -replace '^[A-Za-z]:', "/$drive"
#}
#$cmd = "`"$pyBuilderPathUnix`" `"$mainPyUnix`""
#& $bashExe -lc "chmod +x '$pyBuilderPathUnix'"
#& $mingw64Exe -lc $cmd
#    $mainPy = Get-ChildItem -Path $sourceDir -Recurse -File -Include "__main__.py","main.py" -ErrorAction SilentlyContinue | Select-Object -First 1
$sourceDirR = Join-Path $PSScriptRoot "youtube-dl"
$targetDirR = Join-Path $sourceDirR "youtube_dl"

Write-Host "Je vais dans le dossier : $targetDir"
Set-Location $targetDirR

$mainPy = Get-ChildItem -Path . -Recurse -File -Include "__main__.py","main.py" -ErrorAction SilentlyContinue | Select-Object -First 1

$sourceDir = $PSScriptRoot
$pyBuilderPath = Join-Path $sourceDir "pyinstaller_builder.py"
$mainPyPath = $mainPy.FullName  # chemin complet Windows du main.py

# Construire la commande pour cmd.exe en gardant chemins Windows
$cmd = "cmd.exe /c `"$pyBuilderPath`" `"$mainPyPath`""

Write-Host "Lancement via cmd.exe : $cmd"

Invoke-Expression $cmd

    if ($LASTEXITCODE -ne 0) {
        Pop-Location
        Show-Message "Erreur lors de la compilation avec PyInstaller." Red
        Pause-IfInteractive
        exit 1
    }
    Pop-Location

    Show-Message "Compilation terminée. Exécutable disponible dans $distPath" Green
    Pause-IfInteractive
}
catch {
    Show-Message "Erreur inattendue : $_" Red
    Pause-IfInteractive
    exit 1
}
