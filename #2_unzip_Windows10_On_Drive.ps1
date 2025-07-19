# Charger les assemblies nécessaires
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.Windows.Forms

# Fonction pour sélectionner le fichier ZIP
function Select-ZipFile {
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Filter = "Fichiers ZIP (*.zip)|*.zip"
    $OpenFileDialog.Title = "Sélectionnez un fichier ZIP"
    
    if ($OpenFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        return $OpenFileDialog.FileName
    }
    return $null
}

# Fonction pour sélectionner le dossier de destination
function Select-DestinationFolder {
    $FolderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $FolderBrowserDialog.Description = "Sélectionnez un dossier de destination"
    
    if ($FolderBrowserDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        return $FolderBrowserDialog.SelectedPath
    }
    return $null
}

# Fonction pour décompresser le fichier ZIP
function Unzip-File {
    param (
        [string]$zipFilePath,
        [string]$extractFolder
    )

    try {
        # Décompression
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFilePath, $extractFolder)
        [System.Windows.Forms.MessageBox]::Show("Décompression réussie dans : $extractFolder", "Succès")
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Erreur lors de la décompression : $($_.Exception.Message)", "Erreur")
    }
}

# Main script
$zipFilePath = Select-ZipFile
if (-not $zipFilePath) {
    [System.Windows.Forms.MessageBox]::Show("Aucun fichier ZIP sélectionné.", "Avertissement")
    exit
}

$extractFolder = Select-DestinationFolder
if (-not $extractFolder) {
    [System.Windows.Forms.MessageBox]::Show("Aucun dossier de destination sélectionné.", "Avertissement")
    exit
}

Unzip-File -zipFilePath $zipFilePath -extractFolder $extractFolder
