# RedÃ©marrage en administrateur si nÃ©cessaire
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
  $arguments = "& '" + $myinvocation.mycommand.definition + "'"
  Start-Process powershell -Verb runAs -ArgumentList $arguments
  exit
}

Add-Type -AssemblyName System.Windows.Forms

$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.RootFolder = [System.Environment+SpecialFolder]::MyComputer
$dialog.Description = "SÃ©lectionnez le dossier Ã  parcourir pour extraire les classes"

if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    $folder_path = $dialog.SelectedPath
} else {
    exit
}

$output_file = "output.txt"
Remove-Item $output_file -ErrorAction SilentlyContinue


# Fonction pour ajouter une classe au dictionnaire
function Add-Class($class_name, $parent_name) {
    if (-not $classes.ContainsKey($class_name)) {
        $classes[$class_name] = @{
            Parent = $parent_name
            Content = ""
            Depth = 0
        }
        if ($parent_name) {
            $depth = $classes[$parent_name].Depth + 1
            $classes[$class_name]["Depth"] = $depth
        }
    }
}

# Fonction pour ajouter le contenu d'une classe au dictionnaire
function Add-Class-Content($class_name, $class_content) {
    $classes[$class_name]["Content"] = $class_content
}

# Fonction pour obtenir la hiérarchie des classes
function Get-Class-Hierarchy($class_name) {
    $parent_name = $classes[$class_name]["Parent"]
    if ($parent_name) {
        $parent_hierarchy = Get-Class-Hierarchy $parent_name
        $parent_hierarchy += $parent_name
        return ,$parent_hierarchy
    } else {
        return ,$class_name
    }
}

# Dictionnaire pour stocker les classes
$classes = @{}

# Parcourir les fichiers hpp dans le dossier et ses sous-dossiers
Get-ChildItem -Path $folder_path -Recurse -Include *.h | ForEach-Object {
    $file_content = Get-Content -Path $_.FullName -Raw

# Extraire les classes et les templates de classe du fichier
$class_blocks = [Regex]::Matches($file_content, "(?:(?:\s*template\s*<[^{}]*>\s*)?(?:\s*(?:enum|struct|class|enum\s+class)\s+))+\s*(\S+)\s*(?::\s*\S+)?\s*(?::\s*.*)?\s*(?:{\s*(?>[^{}]+|(?<open>{)|(?<-open>}))*(?(open)(?!))\s*};)")

foreach ($class_block in $class_blocks) {
    $class_content = $class_block.Value
    $class_name_match = [Regex]::Match($class_content, "(?:(?:\s*template\s*<[^{}]*>\s*)?(?:\s*(?:enum|struct|class|enum\s+class)\s+))+\s*(\S+)\s*")

    if ($class_name_match.Success) {
        $class_name = $class_name_match.Groups[1].Value.Trim()

        # Trouver le nom de la classe parente, s'il y en a une
        $parent_name_match = [Regex]::Match($class_content, "(?<=^\s*:\s*)\S+")
        if ($parent_name_match.Success) {
            $parent_name = $parent_name_match.Value.Trim()
        } else {
            $parent_name = $null
        }
    }

    # Ajouter la classe au dictionnaire
    Add-Class $class_name $parent_name

    # Ajouter le contenu de la classe au dictionnaire
    Add-Class-Content $class_name $class_content
}

}


# Trier les classes par ordre hiérarchique
foreach ($class_name in $classes.Keys) {
    $class_hierarchy = Get-Class-Hierarchy $class_name
    $classes[$class_name]["Depth"] = $class_hierarchy.Count
}

$classes_sorted = $classes.GetEnumerator() | Sort-Object Depth, Key

# Écrire les classes dans le fichier de sortie
foreach ($class_entry in $classes_sorted) {
    $class_name = $class_entry.Key
    $class_depth = $class_entry.Value.Depth

    # Ajouter des espaces selon la profondeur de la classe
    $class_indent = " " * ($class_depth * 4)

    # Écrire le nom de la classe et son contenu dans le fichier
    Add-Content -Path $output_file -Value "$($class_entry.Value.Content)`n"
}
pause

#GetClass
#https://github.com/Yimura/GTAV-Classes 
#https://pastebin.com/MGftkz0B