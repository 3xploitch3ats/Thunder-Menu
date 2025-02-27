# Chemin vers FFmpeg (modifiez si nécessaire)
$ffmpegPath = ".\Ffmpeg\Ffmpeg\ffmpeg.exe"

# Ajouter les types nécessaires pour l'interface graphique Windows Forms
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Créer un formulaire
$form = New-Object System.Windows.Forms.Form
$form.Text = "Conversion DVD en MP4 4K"
$form.Size = New-Object System.Drawing.Size(500, 300)

# Ajouter un label
$label = New-Object System.Windows.Forms.Label
$label.Text = "Sélectionnez un dossier VIDEO_TS"
$label.Size = New-Object System.Drawing.Size(250, 20)
$label.Location = New-Object System.Drawing.Point(10, 10)
$form.Controls.Add($label)

# Ajouter un ComboBox pour afficher les fichiers VOB
$comboBox = New-Object System.Windows.Forms.ComboBox
$comboBox.Size = New-Object System.Drawing.Size(450, 20)
$comboBox.Location = New-Object System.Drawing.Point(10, 40)
$form.Controls.Add($comboBox)

# Ajouter une barre de progression
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Size = New-Object System.Drawing.Size(450, 20)
$progressBar.Location = New-Object System.Drawing.Point(10, 80)
$progressBar.Style = "Marquee"
$form.Controls.Add($progressBar)

# Ajouter un bouton pour sélectionner le dossier VIDEO_TS
$buttonBrowse = New-Object System.Windows.Forms.Button
$buttonBrowse.Text = "Sélectionner VIDEO_TS"
$buttonBrowse.Size = New-Object System.Drawing.Size(120, 30)
$buttonBrowse.Location = New-Object System.Drawing.Point(10, 120)
$form.Controls.Add($buttonBrowse)

# Ajouter un bouton pour démarrer la conversion
$buttonConvert = New-Object System.Windows.Forms.Button
$buttonConvert.Text = "Démarrer la Conversion"
$buttonConvert.Size = New-Object System.Drawing.Size(150, 30)
$buttonConvert.Location = New-Object System.Drawing.Point(150, 120)
$form.Controls.Add($buttonConvert)

# Fonction de sélection du dossier VIDEO_TS
$buttonBrowse.Add_Click({
    $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderDialog.Description = "Sélectionnez le dossier VIDEO_TS du DVD"

    if ($folderDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $videoTS = $folderDialog.SelectedPath
        Write-Host "Dossier VIDEO_TS sélectionné : $videoTS"

        # Trouver tous les fichiers VOB dans le dossier VIDEO_TS uniquement (pas de sous-dossiers)
        $vobFiles = Get-ChildItem -Path "$videoTS" -Filter "*.vob" | Sort-Object FullName

        # Vérifier s'il y a des fichiers VOB
        if ($vobFiles.Count -eq 0) {
            Write-Host "❌ Aucun fichier VOB trouvé dans VIDEO_TS."
            [System.Windows.Forms.MessageBox]::Show("Aucun fichier VOB trouvé dans VIDEO_TS.")
            return
        }

        # Ajouter les fichiers VOB à la ComboBox avec le chemin complet
        $comboBox.Items.Clear()
        $vobFiles | ForEach-Object {
            $comboBox.Items.Add($_.FullName)  # Ajoute le chemin complet du fichier VOB
        }

        Write-Host "✅ Fichiers VOB ajoutés à la ComboBox."
    } else {
        Write-Host "🚫 Aucun dossier sélectionné."
    }
})

# Fonction de conversion et suivi avec ProgressBar
$buttonConvert.Add_Click({
    if ($comboBox.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Veuillez sélectionner des fichiers VOB.")
        return
    }

    # Créer un fichier texte pour concaténer tous les fichiers VOB
    $concatListPath = "$videoTS\fileList.txt"
    $comboBox.Items | ForEach-Object {
        $vobPath = $_
        Add-Content -Path $concatListPath -Value "file '$vobPath'"
    }

    # Ajouter un SaveFileDialog pour sélectionner l'emplacement du fichier de sortie
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "Fichier MP4|*.mp4"
    $saveFileDialog.DefaultExt = "mp4"
    $saveFileDialog.FileName = "DVD_4K.mp4"

    if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $outputFile = $saveFileDialog.FileName
        Write-Host "Fichier de sortie sélectionné : $outputFile"
# #1
        # # Commande FFmpeg pour la conversion en 4K
        # $ffmpegCommand = "& `"$ffmpegPath`" -f concat -safe 0 -i `"$concatListPath`" -vf `"scale=3840:2160`" -c:v libx264 -crf 18 -preset slow -c:a aac -b:a 192k `"$outputFile`""        
       #  Write-Host "Commande FFmpeg : $ffmpegCommand"       
    # Invoke-Expression $ffmpegCommand
# #2
        # Exécution de la commande FFmpeg avec suivi du progrès
       $process = Start-Process -FilePath $ffmpegPath -ArgumentList "-f concat -safe 0 -i `"$concatListPath`" -vf scale=3840:2160 -c:v libx264 -crf 18 -preset slow -c:a aac -b:a 192k `"$outputFile`"" -PassThru -NoNewWindow

        # Mettre à jour la barre de progression
        $process.WaitForExit()
        
        # Fin de la conversion
        if ($process.ExitCode -eq 0) {
            Write-Host "✅ Conversion terminée : $outputFile"
            [System.Windows.Forms.MessageBox]::Show("Conversion terminée avec succès : $outputFile")
        } else {
            Write-Host "❌ Erreur lors de la conversion."
            [System.Windows.Forms.MessageBox]::Show("Erreur lors de la conversion.")
        }

        # Supprimer le fichier de liste de concaténation après la conversion
        Remove-Item -Path $concatListPath
    } else {
        Write-Host "🚫 Aucun fichier de sortie sélectionné."
    }
})

# Afficher le formulaire
$form.ShowDialog()
pause
