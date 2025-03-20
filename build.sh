#!/bin/bash

set -x  # Enable debugging by showing executed commands

# Define working directories
FFMPEG_DIR="$(cd "$(dirname "$0")" && pwd)/FFmpeg"
FREI0R_DIR="${FFMPEG_DIR}/frei0r"  # Frei0r will be cloned into FFmpeg/frei0r
FREI0R_INSTALL_DIR="${FFMPEG_DIR}"  # Install Frei0r into FFmpeg/lib/frei0r-1
CONFIG_FILE="mingw64_path.txt"  # Save mingw64.exe path to a file

# Load mingw64.exe path from the config file if it exists
if [[ -f "$CONFIG_FILE" ]]; then
    MINGW64_PATH=$(cat "$CONFIG_FILE")
    if [[ -z "$MINGW64_PATH" || ! -f "$MINGW64_PATH" ]]; then
        echo "Invalid mingw64.exe path in $CONFIG_FILE. Please select it again."
        exit 1
    fi
else
    echo "Mingw64.exe path not found. Exiting."
    exit 1
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

# Clone FFmpeg if not already present
if [ ! -d "$FFMPEG_DIR" ]; then
    git clone https://github.com/FFmpeg/FFmpeg.git "$FFMPEG_DIR"
fi

# Clone Frei0r into FFmpeg directory if not already present
if [ ! -d "$FREI0R_DIR" ]; then
    git clone https://github.com/dyne/frei0r.git "$FREI0R_DIR"
fi

# Build and install Frei0r
cd "$FREI0R_DIR"
# mkdir -p build && cd build
# cmake -G "Visual Studio 17 2022" -A x64
cmake -G "Unix Makefiles" -DCMAKE_INSTALL_PREFIX="${FREI0R_INSTALL_DIR}"

make -j$(nproc)
make install
cd ../ # ../  # Return to root directory

# Build and configure FFmpeg
cd "$FFMPEG_DIR"
./configure \
    --prefix="./FFmpeg" \
    --enable-dxva2 \
    --enable-d3d11va \
    --enable-fontconfig \
    --enable-frei0r \
    --enable-gmp \
    --enable-gnutls \
    --enable-gpl \
    --enable-iconv \
    --enable-libaom \
    --enable-libass \
    --enable-libbluray \
    --enable-libcaca \
    --enable-libdav1d \
    --enable-libfreetype \
    --enable-libfribidi \
    --enable-libgme \
    --enable-libgsm \
    --enable-libmodplug \
    --enable-libmp3lame \
    --enable-libopencore_amrnb \
    --enable-libopencore_amrwb \
    --enable-libopenjpeg \
    --enable-libopus \
    --enable-librsvg \
    --enable-librtmp \
    --enable-libssh \
    --enable-libsoxr \
    --enable-libspeex \
    --enable-libsrt \
    --enable-libtheora \
    --enable-libvidstab \
    --enable-libvorbis \
    --enable-libx264 \
    --enable-libx265 \
    --enable-libxvid \
    --enable-libvpx \
    --enable-libwebp \
    --enable-libxml2 \
    --enable-libzimg \
    --enable-openal \
    --enable-pic \
    --enable-postproc \
    --enable-runtime-cpudetect \
    --enable-swresample \
    --enable-version3 \
    --enable-zlib \
    --enable-librav1e \
    --enable-libvpl \
    --enable-libsvtav1 \
    --enable-shared \
    --extra-cflags="-I${FREI0R_DIR}/include" \
  --extra-ldflags="-L${FREI0R_INSTALL_DIR}./frei0r/src/filter/*/Release"
    # --extra-ldflags="-L${FREI0R_INSTALL_DIR}/lib/frei0r~1"

# Build and install FFmpeg
make -j$(nproc)
make install
cd ..

echo "Installation complete. Frei0r installed in ${FREI0R_INSTALL_DIR}."
echo "FFmpeg, ffplay, and ffprobe installed in ${FFMPEG_DIR}/FFmpeg."
