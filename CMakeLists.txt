cmake_minimum_required(VERSION 3.14)
project(frei0r)

# Configuration options
set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/../../FFmpeg/lib/frei0r-1" CACHE PATH "Installation directory")

# Add source files
file(GLOB SOURCES "src/*.cpp" "src/*.h")

# Create shared library
add_library(frei0r SHARED ${SOURCES})

# Install the library and headers
install(TARGETS frei0r DESTINATION lib/frei0r-1)
install(FILES "include/frei0r.h" DESTINATION include)