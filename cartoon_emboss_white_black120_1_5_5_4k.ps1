# Chemin vers FFmpeg (modifiez si nécessaire)
$ffmpegPath = ".\Ffmpeg\Ffmpeg\ffmpeg.exe"

# Sélection du fichier MP4
Add-Type -AssemblyName System.Windows.Forms
$fileDialog = New-Object System.Windows.Forms.OpenFileDialog
$fileDialog.Filter = "Tous les fichiers|*.*"
$fileDialog.Title = "Tous les fichiers"

if ($fileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    $inputFile = $fileDialog.FileName
    $outputFile = [System.IO.Path]::ChangeExtension($inputFile, "cartoon_emboss_white_black120_1_5_5_4k.mp4")

    Write-Host "Fichier sélectionné : $inputFile"
    Write-Host "Fichier de sortie : $outputFile"

$ffmpegCommand = "& `"$ffmpegPath`" -i `"$inputFile`" -vf `"format=gbrp, scale=3840:2160, frei0r=emboss, curves=all='0/0.1 0.3/0.5 0.7/0.5 1/1', lutrgb=r='if(lt(val,120),0,255)':g='if(lt(val,120),0,255)':b='if(lt(val,120),0,255)'`" -c:v libx264 -crf 18 -preset slow -c:a copy `"$outputFile`""

    Write-Host "Commande FFmpeg : $ffmpegCommand"
    
    # Exécution de la commande FFmpeg
    Invoke-Expression $ffmpegCommand

    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Conversion terminée : $outputFile"
    } else {
        Write-Host "❌ Erreur lors de la conversion. Code de sortie : $LASTEXITCODE"
    }
} else {
    Write-Host "Aucun fichier sélectionné."
}

# Pauser le script pour que la fenêtre reste ouverte
Read-Host -Prompt "Appuyez sur Entrée pour fermer"
