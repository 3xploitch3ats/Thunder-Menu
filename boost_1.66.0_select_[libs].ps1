# Charger l'assembly nécessaire pour utiliser Windows Forms
Add-Type -AssemblyName 'System.Windows.Forms'

# Obtenir le répertoire où le script est lancé (dossier de destination)
$sourceDirectory = (Get-Location).Path
Write-Host "Dossier source : $sourceDirectory"

# Ouvrir une boîte de dialogue pour sélectionner un dossier source où se trouvent les fichiers à copier
$folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
$folderBrowser.Description = "Sélectionnez le dossier source pour les fichiers boost"
$folderBrowser.SelectedPath = $sourceDirectory  # Initialiser avec le dossier où le script est lancé
$folderBrowser.ShowNewFolderButton = $false

# Si l'utilisateur sélectionne un dossier, continuez
if ($folderBrowser.ShowDialog() -eq "OK") {
    $sourceDirectory = $folderBrowser.SelectedPath  # Mettre à jour la source selon ce que l'utilisateur sélectionne
    Write-Host "Dossier source sélectionné : $sourceDirectory"

    # Le sous-dossier où vous souhaitez copier les fichiers boost (dans le dossier où le script est lancé)
    $targetDirectory = (Get-Location).Path
    $targetBoostDirectory = Join-Path -Path $targetDirectory -ChildPath "boost"

    # Vérifier si le dossier cible boost existe déjà
    if (-not (Test-Path -Path $targetBoostDirectory)) {
        # Si le dossier cible n'existe pas, le créer
        New-Item -ItemType Directory -Path $targetBoostDirectory
        Write-Host "Dossier boost créé dans le dossier de destination : $targetBoostDirectory"
    } else {
        Write-Host "Le dossier boost existe déjà : $targetBoostDirectory"
    }

    # Rechercher tous les dossiers boost dans le répertoire source
    $boostDirectories = Get-ChildItem -Path $sourceDirectory -Recurse -Directory | Where-Object { $_.FullName -match '\\[^\\]+\\[^\\]+\\boost$' }

    foreach ($dir in $boostDirectories) {
        Write-Host "Copie des fichiers depuis : $($dir.FullName)"

        # Copier tous les fichiers et sous-dossiers dans le dossier cible boost
        Get-ChildItem -Path $dir.FullName -Recurse | ForEach-Object {
            # Calculer le chemin relatif du fichier ou dossier à copier sous boost (ignorer les chemins avant boost)
            $relativePath = $_.FullName.Substring($dir.FullName.Length).TrimStart("\")
            $destinationPath = Join-Path -Path $targetBoostDirectory -ChildPath $relativePath

            # Vérifier si le fichier source et le fichier de destination sont les mêmes
            if ($_.FullName -ne $destinationPath) {
                # Si c'est un dossier, créer le dossier dans le dossier cible
                if ($_.PSIsContainer) {
                    # Assurez-vous que tous les sous-dossiers existent avant de copier
                    if (-not (Test-Path -Path $destinationPath)) {
                        New-Item -ItemType Directory -Path $destinationPath
                    }
                } else {
                    # Si c'est un fichier, assurez-vous que tous les sous-dossiers existent avant de copier
                    $destinationDir = [System.IO.Path]::GetDirectoryName($destinationPath)
                    if (-not (Test-Path -Path $destinationDir)) {
                        New-Item -ItemType Directory -Path $destinationDir
                    }
                    # Copier le fichier dans le répertoire cible
                    Copy-Item -Path $_.FullName -Destination $destinationPath -Force
                }
            } else {
                Write-Host "Le fichier $($_.FullName) existe déjà dans le répertoire cible, pas besoin de le copier."
            }
        }
    }

    Write-Host "Tous les fichiers et dossiers ont été copiés dans $targetBoostDirectory."
} else {
    Write-Host "Aucun dossier sélectionné. Le script est annulé."
}
