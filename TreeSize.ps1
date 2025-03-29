Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Créer le formulaire principal
$form = New-Object System.Windows.Forms.Form
$form.Text = "Explorateur de Fichiers et Dossiers"
$form.Size = New-Object System.Drawing.Size(1000, 700)

# Créer un ComboBox pour sélectionner le lecteur
$labelDrive = New-Object System.Windows.Forms.Label
$labelDrive.Text = "Sélectionnez un lecteur:"
$labelDrive.Location = New-Object System.Drawing.Point(10, 20)
$labelDrive.AutoSize = $true
$form.Controls.Add($labelDrive)

$comboBoxDrive = New-Object System.Windows.Forms.ComboBox
$comboBoxDrive.Location = New-Object System.Drawing.Point(150, 20)
$comboBoxDrive.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$comboBoxDrive.Width = 100

# Remplir le ComboBox avec les lecteurs disponibles
Get-PSDrive -PSProvider FileSystem | ForEach-Object {
    $comboBoxDrive.Items.Add($_.Root)
}
$comboBoxDrive.SelectedIndex = 0
$form.Controls.Add($comboBoxDrive)

# Créer un bouton "Scan" pour lancer la recherche
$buttonScan = New-Object System.Windows.Forms.Button
$buttonScan.Text = "Scan"
$buttonScan.Location = New-Object System.Drawing.Point(260, 20)
$buttonScan.AutoSize = $true
$form.Controls.Add($buttonScan)

# Créer une zone de texte pour afficher le chemin actuel
$textBoxPath = New-Object System.Windows.Forms.TextBox
$textBoxPath.Location = New-Object System.Drawing.Point(10, 60)
$textBoxPath.Size = New-Object System.Drawing.Size(960, 20)
$textBoxPath.ReadOnly = $true
$form.Controls.Add($textBoxPath)

# Créer un ListView pour afficher les fichiers et dossiers
$listView = New-Object System.Windows.Forms.ListView
$listView.Location = New-Object System.Drawing.Point(10, 90)
$listView.Size = New-Object System.Drawing.Size(960, 500)
$listView.View = [System.Windows.Forms.View]::Details
$listView.FullRowSelect = $true
$listView.MultiSelect = $true
$listView.Columns.Add("Nom", 400)
$listView.Columns.Add("Type", 100)
$listView.Columns.Add("Taille (Mo)", 100)
$form.Controls.Add($listView)

# Créer un menu contextuel (clic droit)
$contextMenu = New-Object System.Windows.Forms.ContextMenuStrip

# Options du menu contextuel
$menuCopy = $contextMenu.Items.Add("Copier")
$menuCut = $contextMenu.Items.Add("Couper")
$menuPaste = $contextMenu.Items.Add("Coller")
$menuDelete = $contextMenu.Items.Add("Supprimer")

# Variables pour gérer le presse-papiers
$clipboard = @{
    Action = "" # "Copy" ou "Cut"
    Items  = @()
}

# Variable pour stocker le chemin actuel
$script:currentPath = $null
$script:lastSortedColumn = -1
$script:sortOrder = "None"

# Fonction pour mettre à jour la liste des fichiers et dossiers
function Update-ListView {
    param ($path)
    $listView.Items.Clear()
    $textBoxPath.Text = $path
    $script:currentPath = $path
    
    try {
        # Ajouter un élément pour remonter d'un niveau (sauf à la racine)
        if ($path -ne $comboBoxDrive.SelectedItem) {
            $parentItem = New-Object System.Windows.Forms.ListViewItem("..")
            $parentItem.SubItems.Add("Dossier")
            $parentItem.SubItems.Add("")
            $listView.Items.Add($parentItem)
        }

        # Récupérer les dossiers et fichiers
        Get-ChildItem -Path $path | ForEach-Object {
            $item = $_
            $itemType = if ($item.PSIsContainer) { "Dossier" } else { "Fichier" }
            $size = if ($item.PSIsContainer) {
                try {
                    $folderSize = (Get-ChildItem -Path $item.FullName -Recurse -File -ErrorAction Stop | Measure-Object -Property Length -Sum).Sum / 1MB
                    [math]::Round($folderSize, 2)
                } catch {
                    "Accès Refusé"
                }
            } else {
                [math]::Round($item.Length / 1MB, 2)
            }
            $listItem = New-Object System.Windows.Forms.ListViewItem($item.Name)
            $listItem.SubItems.Add($itemType)
            $listItem.SubItems.Add($size)
            $listView.Items.Add($listItem)
        }
        
        # Réappliquer le tri si une colonne était sélectionnée
        if ($script:lastSortedColumn -ne -1) {
            Sort-ListViewColumn -ColumnIndex $script:lastSortedColumn -SortOrder $script:sortOrder
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Erreur : $_", "Erreur", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

# Fonction pour trier une colonne
function Sort-ListViewColumn {
    param(
        [int]$ColumnIndex,
        [string]$SortOrder
    )
    
    $items = @()
    foreach ($item in $listView.Items) {
        $items += $item
    }
    
    if ($ColumnIndex -eq 0) { # Tri par nom
        if ($SortOrder -eq "Ascending") {
            $sortedItems = $items | Sort-Object { $_.Text }
        } else {
            $sortedItems = $items | Sort-Object { $_.Text } -Descending
        }
    }
    elseif ($ColumnIndex -eq 1) { # Tri par type
        if ($SortOrder -eq "Ascending") {
            $sortedItems = $items | Sort-Object { $_.SubItems[1].Text }
        } else {
            $sortedItems = $items | Sort-Object { $_.SubItems[1].Text } -Descending
        }
    }
    elseif ($ColumnIndex -eq 2) { # Tri par taille
        if ($SortOrder -eq "Ascending") {
            $sortedItems = $items | Sort-Object { 
                $sizeText = $_.SubItems[2].Text
                if ($sizeText -eq "Accès Refusé" -or $sizeText -eq "") { 
                    [double]::MinValue 
                } else { 
                    [double]$sizeText 
                }
            }
        } else {
            $sortedItems = $items | Sort-Object { 
                $sizeText = $_.SubItems[2].Text
                if ($sizeText -eq "Accès Refusé" -or $sizeText -eq "") { 
                    [double]::MinValue 
                } else { 
                    [double]$sizeText 
                }
            } -Descending
        }
    }
    
    $listView.BeginUpdate()
    $listView.Items.Clear()
    $listView.Items.AddRange($sortedItems)
    $listView.EndUpdate()
    
    $script:lastSortedColumn = $ColumnIndex
    $script:sortOrder = $SortOrder
}

# Événement pour trier les colonnes
$listView.Add_ColumnClick({
    param($sender, $e)
    
    $column = $e.Column
    
    # Déterminer l'ordre de tri
    if ($column -eq $script:lastSortedColumn) {
        # Inverser l'ordre si c'est la même colonne
        $sortOrder = if ($script:sortOrder -eq "Ascending") { "Descending" } else { "Ascending" }
    } else {
        # Nouvelle colonne, tri ascendant par défaut
        $sortOrder = "Ascending"
    }
    
    # Trier la colonne
    Sort-ListViewColumn -ColumnIndex $column -SortOrder $sortOrder
})

# Événement pour lancer la recherche lors du clic sur "Scan"
$buttonScan.Add_Click({
    $script:currentPath = $comboBoxDrive.SelectedItem
    if (-not $script:currentPath) {
        [System.Windows.Forms.MessageBox]::Show("Veuillez sélectionner un lecteur.", "Erreur", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    Update-ListView -path $script:currentPath
})

# Événement pour naviguer dans les dossiers
$listView.Add_DoubleClick({
    if ($listView.SelectedItems.Count -eq 0) { return }
    
    $selectedItem = $listView.SelectedItems[0]
    
    if ($selectedItem.Text -eq "..") {
        # Remonter d'un niveau
        $script:currentPath = Split-Path -Path $script:currentPath -Parent
    } else {
        # Naviguer dans le dossier sélectionné
        $selectedPath = Join-Path -Path $script:currentPath -ChildPath $selectedItem.Text
        if (Test-Path -Path $selectedPath -PathType Container) {
            $script:currentPath = $selectedPath
        } else {
            # Si c'est un fichier, on ne fait rien ou on l'ouvre
            try {
                Invoke-Item -Path $selectedPath
                return
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Impossible d'ouvrir le fichier : $_", "Erreur", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                return
            }
        }
    }
    Update-ListView -path $script:currentPath
})

# Événement pour le clic droit
$listView.Add_MouseClick({
    if ($_.Button -eq [System.Windows.Forms.MouseButtons]::Right) {
        $contextMenu.Show($listView, $_.Location)
    }
})

# Événement pour l'option "Copier"
$menuCopy.Add_Click({
    $clipboard.Action = "Copy"
    $clipboard.Items = $listView.SelectedItems | ForEach-Object { Join-Path -Path $script:currentPath -ChildPath $_.Text }
})

# Événement pour l'option "Couper"
$menuCut.Add_Click({
    $clipboard.Action = "Cut"
    $clipboard.Items = $listView.SelectedItems | ForEach-Object { Join-Path -Path $script:currentPath -ChildPath $_.Text }
})

# Événement pour l'option "Coller"
$menuPaste.Add_Click({
    foreach ($item in $clipboard.Items) {
        $destination = Join-Path -Path $script:currentPath -ChildPath (Split-Path -Leaf $item)
        if ($clipboard.Action -eq "Copy") {
            Copy-Item -Path $item -Destination $destination -Recurse -Force
        } elseif ($clipboard.Action -eq "Cut") {
            Move-Item -Path $item -Destination $destination -Force
        }
    }
    Update-ListView -path $script:currentPath
})

# Événement pour l'option "Supprimer"
$menuDelete.Add_Click({
    $selectedItems = $listView.SelectedItems
    foreach ($item in $selectedItems) {
        $itemPath = Join-Path -Path $script:currentPath -ChildPath $item.Text
        try {
            if (Test-Path -Path $itemPath) {
                Remove-Item -Path $itemPath -Recurse -Force -ErrorAction Stop
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Erreur lors de la suppression : $_", "Erreur", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
    Update-ListView -path $script:currentPath
})

# Afficher le formulaire
$form.ShowDialog()