@echo off
title HWID Modifier

REM Définition du chemin du script PowerShell temporaire
set "psScript=%temp%\hwid_modifier.ps1"

REM Création du script PowerShell temporaire
echo $regPath = "HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001" > "%psScript%"
echo $currentHWID = Get-ItemProperty -Path "Registry::$regPath" -Name "HwProfileGuid" ^| Select-Object -ExpandProperty HwProfileGuid >> "%psScript%"
echo. >> "%psScript%"
echo # Interface utilisateur PowerShell >> "%psScript%"
echo Add-Type -AssemblyName System.Windows.Forms >> "%psScript%"
echo $form = New-Object System.Windows.Forms.Form >> "%psScript%"
echo $form.Text = "HWID Modifier" >> "%psScript%"
echo $form.Size = New-Object System.Drawing.Size(400,200) >> "%psScript%"
echo $form.StartPosition = "CenterScreen" >> "%psScript%"
echo. >> "%psScript%"
echo $labelHWID = New-Object System.Windows.Forms.Label >> "%psScript%"
echo $labelHWID.Location = New-Object System.Drawing.Point(10,20) >> "%psScript%"
echo $labelHWID.Size = New-Object System.Drawing.Size(200,20) >> "%psScript%"
echo $labelHWID.Text = "Current HWID:" >> "%psScript%"
echo $form.Controls.Add($labelHWID) >> "%psScript%"
echo. >> "%psScript%"
echo $textboxHWID = New-Object System.Windows.Forms.TextBox >> "%psScript%"
echo $textboxHWID.Location = New-Object System.Drawing.Point(10,40) >> "%psScript%"
echo $textboxHWID.Size = New-Object System.Drawing.Size(300,20) >> "%psScript%"
echo $textboxHWID.Text = $currentHWID >> "%psScript%"
echo $textboxHWID.ReadOnly = $true >> "%psScript%"
echo $form.Controls.Add($textboxHWID) >> "%psScript%"
echo. >> "%psScript%"
echo $labelLastFour = New-Object System.Windows.Forms.Label >> "%psScript%"
echo $labelLastFour.Location = New-Object System.Drawing.Point(10,70) >> "%psScript%"
echo $labelLastFour.Size = New-Object System.Drawing.Size(200,20) >> "%psScript%"
echo $labelLastFour.Text = "New Last Four Digits:" >> "%psScript%"
echo $form.Controls.Add($labelLastFour) >> "%psScript%"
echo. >> "%psScript%"
echo $textboxLastFour = New-Object System.Windows.Forms.TextBox >> "%psScript%"
echo $textboxLastFour.Location = New-Object System.Drawing.Point(10,90) >> "%psScript%"
echo $textboxLastFour.Size = New-Object System.Drawing.Size(100,20) >> "%psScript%"
echo $form.Controls.Add($textboxLastFour) >> "%psScript%"
echo. >> "%psScript%"
echo $buttonSave = New-Object System.Windows.Forms.Button >> "%psScript%"
echo $buttonSave.Location = New-Object System.Drawing.Point(10,130) >> "%psScript%"
echo $buttonSave.Size = New-Object System.Drawing.Size(80,30) >> "%psScript%"
echo $buttonSave.Text = "Save" >> "%psScript%"
echo $buttonSave.Add_Click({ >> "%psScript%"
echo     $newLastFour = $textboxLastFour.Text >> "%psScript%"
echo     if ($newLastFour.Length -eq 4) { >> "%psScript%"
echo         $newHWID = $currentHWID.Substring(0, $currentHWID.Length - 4) + $newLastFour + "}" >> "%psScript%"
echo         Set-ItemProperty -Path "Registry::$regPath" -Name "HwProfileGuid" -Value $newHWID -Type String -Force >> "%psScript%"
echo         [System.Windows.Forms.MessageBox]::Show("HWID updated successfully!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) >> "%psScript%"
echo     } else { >> "%psScript%"
echo         [System.Windows.Forms.MessageBox]::Show("Please enter a valid last four digits.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) >> "%psScript%"
echo     } >> "%psScript%"
echo }) >> "%psScript%"
echo $form.Controls.Add($buttonSave) >> "%psScript%"
echo. >> "%psScript%"
echo $form.ShowDialog() >> "%psScript%"
echo $form.Dispose() >> "%psScript%"

REM Exécution du script PowerShell temporaire
powershell.exe -ExecutionPolicy Bypass -File "%psScript%"

REM Suppression du script PowerShell temporaire
del "%psScript%"
pause
exit /b
