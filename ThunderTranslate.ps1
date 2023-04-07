Add-Type -AssemblyName System.Web
# Vérifier si l'exécution se fait en tant qu'administrateur
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
  Exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
# Définir le dictionnaire de langues supportées

$languages = @{
    'af' = 'Afrikaans';
    'sq' = 'Albanian';
    'am' = 'Amharic';
    'ar' = 'Arabic';
    'hy' = 'Armenian';
    'az' = 'Azerbaijani';
    'eu' = 'Basque';
    'be' = 'Belarusian';
    'bn' = 'Bengali';
    'bs' = 'Bosnian';
    'bg' = 'Bulgarian';
    'ca' = 'Catalan';
    'ceb' = 'Cebuano';
    'ny' = 'Chichewa';
    'zh-cn' = 'Chinese (Simplified)';
    'zh-tw' = 'Chinese (Traditional)';
    'co' = 'Corsican';
    'hr' = 'Croatian';
    'cs' = 'Czech';
    'da' = 'Danish';
    'nl' = 'Dutch';
    'en' = 'English';
    'eo' = 'Esperanto';
    'et' = 'Estonian';
    'tl' = 'Filipino';
    'fi' = 'Finnish';
    'fr' = 'French';
    'fy' = 'Frisian';
    'gl' = 'Galician';
    'ka' = 'Georgian';
    'de' = 'German';
    'el' = 'Greek';
    'gu' = 'Gujarati';
    'ht' = 'Haitian Creole';
    'ha' = 'Hausa';
    'haw' = 'Hawaiian';
    'iw' = 'Hebrew';
    'he' = 'Hebrew';
    'hi' = 'Hindi';
    'hmn' = 'Hmong';
    'hu' = 'Hungarian';
    'is' = 'Icelandic';
    'ig' = 'Igbo';
    'id' = 'Indonesian';
    'ga' = 'Irish';
    'it' = 'Italian';
    'ja' = 'Japanese';
    'jw' = 'Javanese';
    'kn' = 'Kannada';
    'kk' = 'Kazakh';
    'km' = 'Khmer';
    'rw' = 'Kinyarwanda';
    'ko' = 'Korean';
    'ku' = 'Kurdish (Kurmanji)';
    'ky' = 'Kyrgyz';
    'lo' = 'Lao';
    'la' = 'Latin';
    'lv' = 'Latvian';
    'lt' = 'Lithuanian';
    'lb' = 'Luxembourgish';
    'mk' = 'Macedonian';
    'mg' = 'Malagasy';
    'ms' = 'Malay';
    'ml' = 'Malayalam';
    'mt' = 'Maltese';
    'mi' = 'Maori';
    'mr' = 'Marathi';
    'mn' = 'Mongolian';
    'my' = 'Myanmar (Burmese)';
    'ne' = 'Nepali';
    'no' = 'Norwegian';
    'or' = 'Odia (Oriya)';
    'ps' = 'Pashto';
    'pl' = 'Polish';
    'pt' = 'Portuguese';
    'pa' = 'Punjabi';
    'ro' = 'Romanian';
    'ru' = 'Russian';
    'sm' = 'Samoan';
    'gd' = 'Scottish Gaelic';
    'sr' = 'Serbian';
    'st' = 'Sesotho';
    'sn' = 'Shona';
    'sd' = 'Sindhi';
    'si' = 'Sinhala (Sinhalese)';
    'sk' = 'Slovak';
    'sl' = 'Slovenian';
    'so' = 'Somali';
    'es' = 'Spanish';
    'su' = 'Sundanese';
    'sw' = 'Swahili';
    'sv' = 'Swedish';
    'tg' = 'Tajik';
    'ta' = 'Tamil';
    'tt' = 'Tatar';
    'te' = 'Telugu';
    'th' = 'Thai';
    'tr' = 'Turkish';
    'tk' = 'Turkmen';
    'uk' = 'Ukrainian';
    'ur' = 'Urdu';
    'ug' = 'Uyghur';
    'uz' = 'Uzbek';
    'vi' = 'Vietnamese';
    'cy' = 'Welsh';
    'xh' = 'Xhosa';
    'yi' = 'Yiddish';
    'yo' = 'Yoruba';
    'zu' = 'Zulu';
}

# Création du formulaire
$form = New-Object System.Windows.Forms.Form
$form.Text = "Choose a language"
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
$form.MaximizeBox = $false
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

# Création du ComboBox pour les langues
$languageBox = New-Object System.Windows.Forms.ComboBox
$languageBox.Location = New-Object System.Drawing.Point(10, 10)
$languageBox.Size = New-Object System.Drawing.Size(200, 25)
$languageBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList

# Ajout des langues dans le ComboBox
foreach ($language in $languages.GetEnumerator() | Sort-Object Value) {
    $languageBox.Items.Add($language.Value) | Out-Null
}

# Événement SelectedIndexChanged pour récupérer la valeur sélectionnée dans le ComboBox
$languageBox.Add_SelectedIndexChanged({
$global:targetLanguage = ($languages.GetEnumerator() | Where-Object { $_.Value -eq $languageBox.SelectedItem.ToString() } | Select-Object -First 1).Key

    #$targetLanguage = ($languages.GetEnumerator() | Where-Object { $_.Value -eq $languageBox.SelectedItem.ToString() } | Select-Object -First 1).Key
    $form.Close()
})


# Ajout du ComboBox au formulaire
$form.Controls.Add($languageBox)


# Affichage du formulaire et récupération du résultat
$result = $form.ShowDialog()

# Si le formulaire a été fermé par l'utilisateur (et non par le code)
if ($result -eq [System.Windows.Forms.DialogResult]::None) {
    $targetLanguage = $null
}

# Suppression du ComboBox et du formulaire
$form.Controls.Remove($languageBox)
$form.Dispose()

# Demander les langages source et cible à l'utilisateur
$sourceLanguage = "en"
#$targetLanguage = Read-Host "Enter the target language code"

# Charger le fichier de texte à traduire
$urlVO = "https://raw.githubusercontent.com/3xploitch3ats/Thunder-Menu/langage/VO.langage"
$outputFilePath = "$PSScriptRoot\langage.langage"
$voContent = Invoke-WebRequest -Uri $urlVO -UseBasicParsing | Select-Object -ExpandProperty Content

function Translate-Text {
    param (
        [Parameter(Mandatory)]
        [string]$sourceLanguage,
        [Parameter(Mandatory)]
        [string]$targetLanguage,
        [Parameter(Mandatory)]
        [string]$text
    )

    $encodedText = [System.Uri]::EscapeUriString($text)
    $url = "https://translate.google.com/translate_a/single?client=gtx&sl=$sourceLanguage&tl=$targetLanguage&dt=t&q=$encodedText"

    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing
        $translation = ($response.Content | ConvertFrom-Json)[0][0][0]
        return $translation
    }
    catch {
        Write-Error "An error occurred while translating the text: $($_.Exception.Message)"
    }
}

# Traduire chaque ligne de texte et les ajouter à un fichier de sortie
foreach ($line in $voContent -split "`n") {
    $translation = Translate-Text -sourceLanguage $sourceLanguage -targetLanguage $targetLanguage -text $line
    $lineResult = $translation
    Add-Content -Path $outputFilePath -Value $lineResult -Encoding UTF8
}

#Write-Output "La traduction a été effectuée avec succès."
