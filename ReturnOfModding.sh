#!/bin/bash
git clone --recursive https://github.com/return-of-modding/ReturnOfModding.git
cd ReturnOfModding
cmake -G "Visual Studio 17 2022" -A x64 .
read -p "Appuyez sur Entrée pour continuer..."
