#!/bin/bash

set -x  # Enable debugging by showing executed commands

# Define working directories for Boost
BOOST_VERSION="1.66.0"
BOOST_REPO="https://github.com/boostorg/boost.git"
BOOST_DIR="$(cd "$(dirname "$0")" && pwd)/boost_$BOOST_VERSION"

# Define the config file for mingw64 path
CONFIG_FILE="mingw64_path.txt"  # Save mingw64.exe path to a file

# Function to request the mingw64.exe path if not found
function ask_for_mingw64_path() {
    echo "Mingw64.exe path not found. Please provide the full path to mingw64.exe (e.g., C:/path/to/mingw64.exe):"
    read -p "Enter path: " MINGW64_PATH
    # Save the path to the config file
    echo "$MINGW64_PATH" > "$CONFIG_FILE"
    echo "Mingw64.exe path saved to $CONFIG_FILE."
}

# Load mingw64.exe path from the config file if it exists
if [[ -f "$CONFIG_FILE" ]]; then
    MINGW64_PATH=$(cat "$CONFIG_FILE")
    if [[ -z "$MINGW64_PATH" || ! -f "$MINGW64_PATH" ]]; then
        echo "Invalid mingw64.exe path in $CONFIG_FILE. Please select it again."
        ask_for_mingw64_path
    fi
else
    echo "Mingw64.exe path not found. Please provide the path."
    ask_for_mingw64_path
fi

# Check if the script is running in Git Bash (MINGW32_NT)
if [[ "$(uname -s)" == *"MINGW32_NT"* ]]; then
    echo "Warning: Running in Git Bash! Restarting with mingw64.exe..."

    # Convert the script path to Windows format
    WIN_SCRIPT=$(cygpath -w "$0")

    # Launch the script with mingw64 using PowerShell for elevated privileges
    powershell -Command "
    Start-Process '$MINGW64_PATH' -ArgumentList '--login', '-c', '\"$WIN_SCRIPT\"' -Verb RunAs -Wait"
    
    exit 0  # Exit to prevent further execution in Git Bash
fi

# Add mingw64 to PATH if not already present
MINGW_DIR=$(dirname "$MINGW64_PATH")
if [[ ":$PATH:" != *":$MINGW_DIR:"* ]]; then
    export PATH="$MINGW_DIR:$PATH"
fi

# Wait for 5 seconds before starting the clone
echo "Waiting for 5 seconds before starting the download from GitHub..."
sleep 5

# Clone Boost if not already present
if [ ! -d "$BOOST_DIR" ]; then
    echo "Cloning Boost $BOOST_VERSION from GitHub..."
    git clone --recursive "$BOOST_REPO" "$BOOST_DIR"
fi

# Checkout the correct Boost version (1.66.0)
echo "Checking out Boost version $BOOST_VERSION..."
cd "$BOOST_DIR" || exit 1
git checkout boost-${BOOST_VERSION}

# Bootstrap Boost (configure the build system)
echo "Running bootstrap to configure Boost..."
./bootstrap.sh

# Install Boost
echo "Installing Boost..."
./b2 --build-type=complete --prefix="$BOOST_DIR/install" install

echo "Boost installation completed."

# End of script
read -p "Press Enter to continue..."
