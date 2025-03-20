# Path to the config file storing mingw64.exe location
$configFile = "mingw64_path.txt"

# Function to select mingw64.exe using a file dialog
function Select-Mingw64 {
    Add-Type -AssemblyName System.Windows.Forms
    $fileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $fileDialog.Filter = 'Executable Files (*.exe)|*.exe'
    $fileDialog.Title = 'Select mingw64.exe'
    
    if ($fileDialog.ShowDialog() -eq 'OK') {
        $mingw64Path = $fileDialog.FileName
    }
    else {
        Write-Host "❌ No file selected. Exiting."
        pause
        exit 1
    }

    # Validate the selected file: ensure it exists and has a .exe extension
    if (-not (Test-Path $mingw64Path) -or ((Get-Item $mingw64Path).Extension -ne ".exe")) {
        Write-Host "❌ Invalid mingw64.exe path. Please select the correct executable."
        pause
        exit 1
    }
    
    # Save the mingw64.exe path into the config file
    Set-Content -Path $configFile -Value $mingw64Path
    Write-Host "✅ mingw64.exe location saved in $configFile."
    return $mingw64Path
}

# Load the mingw64.exe path from the config file if it exists
if (Test-Path $configFile) {
    $mingw64Path = Get-Content $configFile
    if (-not (Test-Path $mingw64Path) -or ((Get-Item $mingw64Path).Extension -ne ".exe")) {
        Write-Host "❌ Invalid mingw64.exe path in $configFile. Please select it again."
        $mingw64Path = Select-Mingw64
    }
} else {
    $mingw64Path = Select-Mingw64
}

# Launch mingw64.exe directly (without cmd or additional arguments)
Write-Host "Launching mingw64..."
# & $mingw64Path
# Get the directory of the PowerShell script
$scriptDir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

# Change to the directory of the script where build.sh is located
Set-Location -Path $scriptDir

# Launch mingw64.exe in the same directory and run the build.sh script
Write-Host "Launching mingw64 in directory: $scriptDir"
& $mingw64Path $scriptDir/./build.sh

# Wait for a user input to keep the PowerShell window open for debugging
Write-Host "Press any key to exit."
[System.Console]::ReadKey() | Out-Null
