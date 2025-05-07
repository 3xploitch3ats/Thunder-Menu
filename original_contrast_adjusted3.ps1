# Chemin vers FFmpeg (modifiez si nécessaire)
$ffmpegPath = ".\ffmpeg\ffmpeg\ffmpeg.exe"

# Sélection du fichier MP4
Add-Type -AssemblyName System.Windows.Forms
$fileDialog = New-Object System.Windows.Forms.OpenFileDialog
$fileDialog.Filter = "Tous les fichiers|*.*"
$fileDialog.Title = "Tous les fichiers"

if ($fileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    $inputFile = $fileDialog.FileName
    $outputFile = [System.IO.Path]::ChangeExtension($inputFile, "Original_Contrast.mp4")

    Write-Host "Fichier sélectionné : $inputFile"
    Write-Host "Fichier de sortie : $outputFile"


# $ffmpegCommand = "& `"$ffmpegPath`" -i `"$inputFile`" -vf scale=3840:2160 -c:v libx264 -preset slow -crf 18 -c:a aac -b:a 192k `"$outputFile`""

    $ffmpegCommand = "& `"$ffmpegPath`" -i `"$inputFile`" -vf `"format=gbrp, scale=3840:2160, frei0r=cartoon, curves=all='0/0.2 0.3/0.5 0.7/0.5 1/1', lutrgb=r='if(gt(val,120),val+50,val-50)':g='if(gt(val,120),val+50,val-50)':b='if(gt(val,120),val+50,val-50)'`" -c:v libx264 -crf 18 -preset slow -c:a copy `"$outputFile`""


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
