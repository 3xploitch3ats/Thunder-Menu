param()

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Show($msg, $color="White") {
    Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] $msg" -ForegroundColor $color
}

$installerUrl = "https://repo.msys2.org/distrib/msys2-x86_64-latest.exe"
$installerPath = Join-Path $PSScriptRoot "msys2-latest.exe"

try {
    Show "Téléchargement de MSYS2 (dernier installateur officiel) dans : $installerPath" Cyan
    Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing
    Show "Téléchargement terminé avec succès." Green

    Show "Lancement de l’installateur MSYS2..." Cyan
    Start-Process -FilePath $installerPath
} catch {
    Show "Erreur lors du téléchargement ou lancement : $_" Red
}

pause
