#!/bin/bash

# Ensure that PyInstaller is installed
if ! command -v pyinstaller &> /dev/null
then
    echo "❌ PyInstaller could not be found, installing it..."
    pip install pyinstaller
fi

# Run the PyInstaller command with the necessary flags
echo "Packaging the Python script with PyInstaller..."
pyinstaller --onefile --clean \
  --add-data "choose-mingw64.ps1;." \
  --add-data "build.sh;." \
  --add-data "CMakeLists.txt;." \
  --add-data "mingw64_path.txt;." \
  setup.py

echo "✔ Packaging complete!"
