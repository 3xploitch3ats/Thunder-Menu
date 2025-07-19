# Charger les assemblies nécessaires
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Fonction pour vérifier si le script est exécuté en tant qu'administrateur
function Test-IsAdmin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Fonction pour obtenir une lettre de lecteur aléatoire disponible
function Get-RandomDriveLetter {
    $usedLetters = Get-Volume | Select-Object -ExpandProperty DriveLetter
    $alphabet = 65..90 | ForEach-Object { [char]$_ }
    $availableLetters = $alphabet | Where-Object { -not ($usedLetters -contains $_) }

    if ($availableLetters.Count -gt 0) {
        return Get-Random -InputObject $availableLetters
    } else {
        return $null  # Retourner null si aucune lettre de lecteur n'est disponible
    }
}

# Fonction pour créer une partition principale de 4,8 Go et l'assigner une lettre
function Create-PrimaryPartition {
    param (
        [string]$diskNumber
    )

    # Créer des commandes diskpart pour une partition principale de 4.8 Go
    $sizeInMB = 4800  # 4.8 Go en Mo
    $randomDriveLetter = Get-RandomDriveLetter

    if ($randomDriveLetter -ne $null) {
        $diskpartCommands = @"
select disk $diskNumber
create partition primary size=$sizeInMB
format fs=fat32 quick label="Windows10_Installation"
assign letter=$randomDriveLetter
"@

        # Démarrer le processus Diskpart
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = "diskpart.exe"
        $processInfo.UseShellExecute = $false
        $processInfo.RedirectStandardInput = $true
        $processInfo.Verb = "runas"  # Exécuter en tant qu'administrateur

        # Démarrer le processus
        $process = [System.Diagnostics.Process]::Start($processInfo)

        # Écrire les commandes diskpart dans l'entrée standard
        $process.StandardInput.WriteLine($diskpartCommands)
        $process.StandardInput.Close()

        # Attendre la fin du processus
        $process.WaitForExit()

        # Informer l'utilisateur de la lettre de lecteur assignée
        [System.Windows.Forms.MessageBox]::Show("Partition de 4,8 Go créée avec succès sur le disque $diskNumber avec la lettre $randomDriveLetter.")
    } else {
        [System.Windows.Forms.MessageBox]::Show("Aucune lettre de lecteur disponible.")
    }
}

# Vérifier si le script s'exécute en tant qu'administrateur ; sinon, redémarrer le script
if (-not (Test-IsAdmin)) {
    # Obtenir le chemin du script
    $scriptPath = $MyInvocation.MyCommand.Path
    # Redémarrer le script avec des privilèges administratifs
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
    exit
}

# Créer le formulaire
$form = New-Object System.Windows.Forms.Form
$form.Text = "Sélectionnez le disque"
$form.Width = 300
$form.Height = 200

# Créer ComboBox
$comboBox = New-Object System.Windows.Forms.ComboBox
$comboBox.Location = New-Object System.Drawing.Size(20, 20)
$comboBox.Width = 240

# Remplir ComboBox avec les disques
$disks = Get-Disk | Sort-Object Size -Descending
foreach ($disk in $disks) {
    $comboBox.Items.Add("Disk $($disk.Number): Size $([math]::Round($disk.Size / 1GB, 2)) GB - Partitions: $($disk.PartitionCount) - GPT: $($disk.Gpt)")
}

$form.Controls.Add($comboBox)

# Créer le bouton
$button = New-Object System.Windows.Forms.Button
$button.Text = "Créer une partition principale de 4.8 Go"
$button.Location = New-Object System.Drawing.Size(20, 60)

# Événement de clic du bouton
$button.Add_Click({
    $selectedDisk = $comboBox.SelectedItem
    if ($selectedDisk -match "Disk (\d+):") {
        $diskNumber = $matches[1]

        # Créer la partition sur le disque sélectionné
        Create-PrimaryPartition -diskNumber $diskNumber
    } else {
        [System.Windows.Forms.MessageBox]::Show("Veuillez sélectionner un disque valide.")
    }
})

$form.Controls.Add($button)

# Afficher le formulaire
$form.ShowDialog()