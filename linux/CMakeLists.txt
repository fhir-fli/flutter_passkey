cmake_minimum_required(VERSION 3.10)

project(flutter_passkey LANGUAGES CXX)

# Explicitly opt into modern CMake behaviors to avoid warnings.
cmake_policy(SET CMP0063 NEW)

# Load bundled libraries from the lib/ directory relative to the binary.
set(CMAKE_INSTALL_RPATH "$ORIGIN/lib")

if(FLUTTER_TARGET_PLATFORM_SYSROOT)
  set(CMAKE_SYSROOT ${FLUTTER_TARGET_PLATFORM_SYSROOT})
  set(CMAKE_FIND_ROOT_PATH ${CMAKE_SYSROOT})
  set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
  set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE "Debug" CACHE
    STRING "Flutter build mode" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
    "Debug" "Profile" "Release")
endif()

function(APPLY_STANDARD_SETTINGS TARGET)
  target_compile_features(${TARGET} PUBLIC cxx_std_14)
  # Remove -Werror so that any warnings won't block the build
  target_compile_options(${TARGET} PRIVATE -Wall)
  target_compile_options(${TARGET} PRIVATE "$<$<NOT:$<CONFIG:Debug>>:-O3>")
  target_compile_definitions(${TARGET} PRIVATE "$<$<NOT:$<CONFIG:Debug>>:NDEBUG>")
endfunction()

find_package(PkgConfig REQUIRED)

# Find GTK
pkg_check_modules(GTK REQUIRED IMPORTED_TARGET gtk+-3.0)

# Find GLib (for g_base64_encode, g_free, etc.)
pkg_check_modules(GLIB REQUIRED glib-2.0)

# Find jsoncpp
find_package(jsoncpp REQUIRED)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

add_library(flutter_passkey_plugin SHARED
  src/flutter_passkey_plugin.cc
)

# Include directories from our plugin's source, plus GLIB includes
target_include_directories(flutter_passkey_plugin PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/flutter_passkey"
  ${GLIB_INCLUDE_DIRS}
)

function(link_glib TARGET)
  # Link GLib libraries. Also add any needed link flags from pkg-config.
  target_link_libraries(${TARGET} PRIVATE ${GLIB_LIBRARIES})
  target_compile_definitions(${TARGET} PRIVATE ${GLIB_CFLAGS_OTHER})
  if(GLIB_LIBRARY_DIRS)
    target_link_directories(${TARGET} PRIVATE ${GLIB_LIBRARY_DIRS})
  endif()
endfunction()

apply_standard_settings(flutter_passkey_plugin)

# Link all needed libraries
target_link_libraries(flutter_passkey_plugin PRIVATE
  flutter
  PkgConfig::GTK
  jsoncpp
  OpenSSL::SSL
  OpenSSL::Crypto
)

# Add GLib explicitly
link_glib(flutter_passkey_plugin)

add_dependencies(flutter_passkey_plugin flutter_assemble)

install(TARGETS flutter_passkey_plugin LIBRARY DESTINATION lib)
install(DIRECTORY include/flutter_passkey DESTINATION include)
