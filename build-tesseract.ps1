param(
    [string]$BuildType = "Release"
)

function Show-Message {
    param([string]$Message, [string]$Color = "White")
    $timestamp = Get-Date -Format 'HH:mm:ss'
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
}

$ConfigFile = Join-Path $PSScriptRoot "msys2_config.json"

function Load-MSYS2Config {
    if (Test-Path $ConfigFile) {
        try {
            $conf = Get-Content $ConfigFile -Raw | ConvertFrom-Json
            $msysPath = $conf.MSYS2Path
            if (Test-Path (Join-Path $msysPath "msys2.exe")) {
                return $msysPath
            }
        } catch {}
    }
    return $null
}

function Save-MSYS2Config($msysPath) {
    $obj = @{ MSYS2Path = $msysPath; LastUpdated = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") }
    $obj | ConvertTo-Json | Out-File $ConfigFile -Encoding UTF8
}

function Select-MSYS2 {
    Add-Type -AssemblyName System.Windows.Forms
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "MSYS2 (msys2.exe)|msys2.exe"
    $dialog.Title = "Select msys2.exe"
    if ($dialog.ShowDialog() -eq "OK") {
        $path = Split-Path $dialog.FileName
        Save-MSYS2Config $path
        return $path
    } else {
        Show-Message "Aborted." Red
        exit 1
    }
}

function Get-MSYS2Path {
    $stored = Load-MSYS2Config
    if ($stored) { return $stored }

    $defaults = @("C:\msys64", "$env:ProgramFiles\msys64", "$env:ProgramFiles(x86)\msys64")
    foreach ($d in $defaults) {
        if (Test-Path (Join-Path $d "msys2.exe")) {
            Save-MSYS2Config $d
            return $d
        }
    }
    return Select-MSYS2
}

# ----- Initialisation -----
$msysPath = Get-MSYS2Path
$mingwPath = "$msysPath\mingw64"
$cmakeExe = "$mingwPath\bin\cmake.exe"
$bashExe = "$msysPath\usr\bin\bash.exe"

if (-not (Test-Path $bashExe)) {
    Show-Message "bash.exe not found!" Red
    pause; exit 1
}
Show-Message "Using MSYS2 at $msysPath" Cyan

# ----- Liste des paquets requis -----
$RequiredPackages = @(
    "git",
    "cmake",
    "ninja",
    "make",
	"mingw-w64-x86_64-cmake",
    "mingw-w64-x86_64-toolchain",
    "mingw-w64-x86_64-leptonica",
    "mingw-w64-x86_64-icu",
    "mingw-w64-x86_64-libarchive",
    "mingw-w64-x86_64-pango",
    "mingw-w64-x86_64-cairo",
    "mingw-w64-x86_64-fontconfig",
    "mingw-w64-x86_64-glib2",
    "mingw-w64-x86_64-libjpeg-turbo",
    "mingw-w64-x86_64-libpng",
    "mingw-w64-x86_64-libtiff",
    "mingw-w64-x86_64-zlib"
)

# ----- Vérification et installation si besoin -----
function Check-And-Install-Packages {
    Show-Message "Checking and installing required MSYS2 packages..." Yellow
    $missing = @()
    foreach ($pkg in $RequiredPackages) {
        $check = & $bashExe -lc "pacman -Qi $pkg >/dev/null 2>&1; echo \$?"
        if ($check.Trim() -ne "0") {
            $missing += $pkg
        }
    }

    if ($missing.Count -gt 0) {
        Show-Message "Missing packages detected: $($missing -join ', ')" Cyan
        Show-Message "→ Running: pacman -Syu" Yellow
        & $bashExe -lc "pacman -Syu --noconfirm"
        foreach ($pkg in $missing) {
            Show-Message "→ Installing $pkg" Cyan
            & $bashExe -lc "pacman -S --needed --noconfirm $pkg"
        }
    } else {
        Show-Message "All required packages already installed." Green
    }
}

Check-And-Install-Packages

# ----- Clone & Build -----
$installDir = "$PSScriptRoot\tesseract-install"
$sourceDir = "$PSScriptRoot\tesseract-src"
$buildDir = "$PSScriptRoot\tesseract-build"
$tesseractRepo = "https://github.com/tesseract-ocr/tesseract.git"

if (-not (Test-Path $sourceDir)) {
    Show-Message "Cloning Tesseract..."
    git clone --recursive $tesseractRepo $sourceDir
} else {
    Show-Message "Updating Tesseract..."
    Push-Location $sourceDir
    git pull
    git submodule update --init --recursive
    Pop-Location
}

if (Test-Path $buildDir) {
    Remove-Item $buildDir -Recurse -Force
}
New-Item $buildDir -ItemType Directory | Out-Null

$env:Path = "$mingwPath\bin;$env:Path"
$cmakeArgs = @(
    "-G", "Ninja",
    "-S", "$sourceDir",
    "-B", "$buildDir",
    "-DCMAKE_BUILD_TYPE=$BuildType",
    "-DCMAKE_INSTALL_PREFIX=$installDir",
    "-DBUILD_SHARED_LIBS=ON",
    "-DBUILD_TRAINING_TOOLS=OFF",
    "-DBUILD_TESTS=OFF",
    "-DBUILD_DOCS=OFF",
    "-DENABLE_TRAINING=OFF",
    "-DLeptonica_DIR=$mingwPath\lib\cmake\leptonica",
    "-DSW_BUILD=OFF",
    "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY"
)

Show-Message "Running CMake configuration..." Cyan
& $cmakeExe @cmakeArgs
if ($LASTEXITCODE -ne 0) {
    Show-Message "CMake failed." Red
    pause; exit 1
}

Show-Message "Building..." Cyan
& $cmakeExe --build $buildDir --parallel 4
if ($LASTEXITCODE -ne 0) {
    Show-Message "Build failed." Red
    pause; exit 1
}

Show-Message "Installing to $installDir" Cyan
& $cmakeExe --install $buildDir

$tessExe = "$installDir\bin\tesseract.exe"
if (Test-Path $tessExe) {
    $v = & $tessExe --version
    Show-Message "Installed version: $v" Green
} else {
    Show-Message "❌ tesseract.exe not found after install!" Red
}

pause
exit 0
