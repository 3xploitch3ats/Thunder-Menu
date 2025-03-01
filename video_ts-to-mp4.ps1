# Chemin vers FFmpeg (modifiez si nécessaire)
$ffmpegPath = ".\Ffmpeg\Ffmpeg\ffmpeg.exe"

# Ajouter les types nécessaires pour l'interface graphique Windows Forms
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Créer un formulaire
$form = New-Object System.Windows.Forms.Form
$form.Text = "Conversion DVD/Blu-ray en MP4"
$form.Size = New-Object System.Drawing.Size(600, 500)

# Ajouter un label pour la sélection du dossier VIDEO_TS
$label = New-Object System.Windows.Forms.Label
$label.Text = "Sélectionnez un dossier VIDEO_TS ou Blu-ray"
$label.Size = New-Object System.Drawing.Size(300, 20)
$label.Location = New-Object System.Drawing.Point(10, 10)
$form.Controls.Add($label)

# Ajouter un ComboBox pour afficher les fichiers VOB ou Blu-ray
$comboBox = New-Object System.Windows.Forms.ComboBox
$comboBox.Size = New-Object System.Drawing.Size(550, 20)
$comboBox.Location = New-Object System.Drawing.Point(10, 40)
$form.Controls.Add($comboBox)

# Ajouter une barre de progression
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Size = New-Object System.Drawing.Size(550, 20)
$progressBar.Location = New-Object System.Drawing.Point(10, 80)
$progressBar.Style = "Marquee"
$form.Controls.Add($progressBar)

# Ajouter un label pour la méthode audio
$labelAudioMethod = New-Object System.Windows.Forms.Label
$labelAudioMethod.Text = "Méthode Audio :"
$labelAudioMethod.Size = New-Object System.Drawing.Size(100, 20)
$labelAudioMethod.Location = New-Object System.Drawing.Point(10, 160)
$form.Controls.Add($labelAudioMethod)

# Ajouter un ComboBox pour sélectionner la méthode audio
$comboBoxAudioMethod = New-Object System.Windows.Forms.ComboBox
$comboBoxAudioMethod.Size = New-Object System.Drawing.Size(150, 20)
$comboBoxAudioMethod.Location = New-Object System.Drawing.Point(120, 160)
$comboBoxAudioMethod.Items.Add("ac3")
$comboBoxAudioMethod.Items.Add("aac")
$comboBoxAudioMethod.Items.Add("mp2")
$comboBoxAudioMethod.SelectedIndex = 0  # Sélectionner "ac3" par défaut
$form.Controls.Add($comboBoxAudioMethod)

# Ajouter un label pour la résolution
$labelResolution = New-Object System.Windows.Forms.Label
$labelResolution.Text = "Résolution :"
$labelResolution.Size = New-Object System.Drawing.Size(100, 20)
$labelResolution.Location = New-Object System.Drawing.Point(10, 200)
$form.Controls.Add($labelResolution)

# Ajouter un ComboBox pour sélectionner la résolution
$comboBoxResolution = New-Object System.Windows.Forms.ComboBox
$comboBoxResolution.Size = New-Object System.Drawing.Size(150, 20)
$comboBoxResolution.Location = New-Object System.Drawing.Point(120, 200)
$comboBoxResolution.Items.Add("4K (3840x2160)")
$comboBoxResolution.Items.Add("1080p (1920x1080)")
$comboBoxResolution.Items.Add("720p (1280x720)")
$comboBoxResolution.SelectedIndex = 0  # Sélectionner "4K" par défaut
$form.Controls.Add($comboBoxResolution)

# Ajouter un label pour le format de pixel
$labelPixelFormat = New-Object System.Windows.Forms.Label
$labelPixelFormat.Text = "Format de pixel :"
$labelPixelFormat.Size = New-Object System.Drawing.Size(100, 20)
$labelPixelFormat.Location = New-Object System.Drawing.Point(10, 240)
$form.Controls.Add($labelPixelFormat)

# Ajouter un ComboBox pour sélectionner le format de pixel
$comboBoxPixelFormat = New-Object System.Windows.Forms.ComboBox
$comboBoxPixelFormat.Size = New-Object System.Drawing.Size(150, 20)
$comboBoxPixelFormat.Location = New-Object System.Drawing.Point(120, 240)
$comboBoxPixelFormat.Items.Add("yuv420p")  # Pour DVD-R
$comboBoxPixelFormat.Items.Add("yuv422p")  # Pour Blu-ray
$comboBoxPixelFormat.Items.Add("yuv444p")  # Pour Blu-ray
$comboBoxPixelFormat.SelectedIndex = 0  # Sélectionner "yuv420p" par défaut
$form.Controls.Add($comboBoxPixelFormat)

# Ajouter un CheckBox pour DVD-R
$checkBoxDvd = New-Object System.Windows.Forms.CheckBox
$checkBoxDvd.Text = "DVD-R"
$checkBoxDvd.Size = New-Object System.Drawing.Size(100, 20)
$checkBoxDvd.Location = New-Object System.Drawing.Point(10, 280)
$checkBoxDvd.Checked = $true  # Coché par défaut
$form.Controls.Add($checkBoxDvd)

# Ajouter un CheckBox pour Blu-ray
$checkBoxBluray = New-Object System.Windows.Forms.CheckBox
$checkBoxBluray.Text = "Blu-ray"
$checkBoxBluray.Size = New-Object System.Drawing.Size(100, 20)
$checkBoxBluray.Location = New-Object System.Drawing.Point(120, 280)
$checkBoxBluray.Checked = $false  # Non coché par défaut
$form.Controls.Add($checkBoxBluray)

# Ajouter un bouton pour sélectionner le dossier VIDEO_TS ou Blu-ray
$buttonBrowse = New-Object System.Windows.Forms.Button
$buttonBrowse.Text = "Sélectionner un dossier"
$buttonBrowse.Size = New-Object System.Drawing.Size(150, 30)
$buttonBrowse.Location = New-Object System.Drawing.Point(10, 320)
$form.Controls.Add($buttonBrowse)

# Ajouter un bouton pour démarrer la conversion
$buttonConvert = New-Object System.Windows.Forms.Button
$buttonConvert.Text = "Démarrer la Conversion"
$buttonConvert.Size = New-Object System.Drawing.Size(150, 30)
$buttonConvert.Location = New-Object System.Drawing.Point(170, 320)
$form.Controls.Add($buttonConvert)

# Fonction de sélection du dossier VIDEO_TS ou Blu-ray
$buttonBrowse.Add_Click({
    $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderDialog.Description = "Sélectionnez le dossier VIDEO_TS ou Blu-ray"

    if ($folderDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $videoTS = $folderDialog.SelectedPath
        Write-Host "Dossier sélectionné : $videoTS"

        # Trouver tous les fichiers VOB ou Blu-ray dans le dossier
        if ($checkBoxDvd.Checked) {
            $files = Get-ChildItem -Path "$videoTS" -Filter "*.vob" | Sort-Object FullName
        } else {
            $files = Get-ChildItem -Path "$videoTS" -Filter "*.m2ts" | Sort-Object FullName
        }

        # Vérifier s'il y a des fichiers
        if ($files.Count -eq 0) {
            Write-Host "❌ Aucun fichier trouvé dans le dossier."
            [System.Windows.Forms.MessageBox]::Show("Aucun fichier trouvé dans le dossier.")
            return
        }

        # Ajouter les fichiers à la ComboBox avec le chemin complet
        $comboBox.Items.Clear()
        $global:concatList = @()  # Initialiser la liste globale des fichiers à convertir
        $files | ForEach-Object {
            $comboBox.Items.Add($_.FullName)  # Ajoute le chemin complet du fichier
            $global:concatList += $_.FullName  # Ajoute directement le fichier à la liste globale
        }

        Write-Host "✅ Fichiers ajoutés à la ComboBox et à la liste globale."
    } else {
        Write-Host "❌ Aucun dossier sélectionné."
    }
})

# Fonction de conversion et suivi avec ProgressBar
$buttonConvert.Add_Click({
    if ($comboBox.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Veuillez sélectionner des fichiers.")
        return
    }

    # Ajouter un SaveFileDialog pour sélectionner l'emplacement du fichier de sortie
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "Fichier MP4|*.mp4"
    $saveFileDialog.DefaultExt = "mp4"
    $saveFileDialog.FileName = "Output.mp4"

    if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $outputFile = $saveFileDialog.FileName
        Write-Host "Fichier de sortie sélectionné : $outputFile"

        # Créer un fichier temporaire contenant la liste des fichiers à concaténer
        $tempListFile = [System.IO.Path]::GetTempFileName()
        $global:concatList | ForEach-Object {
            Add-Content -Path $tempListFile -Value "file '$($_)'"
        }

        # Récupérer les paramètres sélectionnés
        $audioMethod = $comboBoxAudioMethod.SelectedItem
        $resolution = $comboBoxResolution.SelectedItem
        $pixelFormat = $comboBoxPixelFormat.SelectedItem

        # Déterminer la résolution
        switch ($resolution) {
            "4K (3840x2160)" { $scale = "scale=3840:2160" }
            "1080p (1920x1080)" { $scale = "scale=1920:1080" }
            "720p (1280x720)" { $scale = "scale=1280:720" }
        }

        # Créer la commande FFmpeg
        $ffmpegArgs = "-f concat -safe 0 -i $tempListFile -c:v libx264 -preset slow -crf 22 -c:a $audioMethod -strict experimental -y $outputFile"

        # Lancer la conversion
        Start-Process $ffmpegPath -ArgumentList $ffmpegArgs -NoNewWindow -Wait

        # Supprimer le fichier temporaire
        Remove-Item -Path $tempListFile

        [System.Windows.Forms.MessageBox]::Show("Conversion terminée !")
    }
})

# Afficher le formulaire
$form.ShowDialog()
