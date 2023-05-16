Add-Type -AssemblyName System.Windows.Forms

# Demande à l'utilisateur de saisir le mot à rechercher
$motRecherche = Read-Host "Entrez le mot à rechercher"

# Crée une instance de OpenFileDialog
$openDialog = New-Object System.Windows.Forms.OpenFileDialog

# Définit les filtres pour les types de fichiers
$openDialog.Filter = "Fichiers texte (*.txt)|*.txt|Tous les fichiers (*.*)|*.*"

# Affiche la boîte de dialogue et attend la sélection d'un fichier
$resultat = $openDialog.ShowDialog()

if ($resultat -eq 'OK') {
    # Récupère le chemin du fichier sélectionné
    $cheminFichier = $openDialog.FileName
    
    # Récupère le contenu du fichier dans une variable
    $contenuFichier = Get-Content -Path $cheminFichier
    
    # Initialise une liste pour stocker les résultats
    $resultats = @()
    
    # Parcours chaque ligne du fichier
    for ($i = 0; $i -lt $contenuFichier.Length; $i++) {
        $ligne = $contenuFichier[$i]
        
        # Vérifie si la ligne contient le mot recherché
        if ($ligne -match $motRecherche) {
            # Copie la ligne courante
            $resultat = $ligne
            
            # Ajoute les 2 lignes suivantes avec une ligne vide entre chaque résultat
            for ($j = 1; $j -le 2; $j++) {
                if (($i + $j) -lt $contenuFichier.Length) {
                    $resultat += "`r`n" + $contenuFichier[$i + $j]
                }
            }
            
            # Ajoute le résultat à la liste
            $resultats += $resultat
        }
    }
    
    if ($resultats.Count -gt 0) {
        # Crée une instance de SaveFileDialog
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        
        # Définit les filtres pour les types de fichiers
        $saveDialog.Filter = "Fichiers texte (*.txt)|*.txt|Tous les fichiers (*.*)|*.*"
        
        # Affiche la boîte de dialogue et attend la sélection du chemin de destination
        $saveResult = $saveDialog.ShowDialog()
        
        if ($saveResult -eq 'OK') {
            # Récupère le chemin du fichier de destination
            $cheminDestination = $saveDialog.FileName
            
            # Enregistre les résultats dans un nouveau fichier texte
            $resultats | Out-File -FilePath $cheminDestination -Encoding UTF8
            
            Write-Host "Les résultats ont été enregistrés dans le fichier : $cheminDestination"
        }
    }
    else {
        Write-Host "Aucun résultat trouvé."
    }
}
