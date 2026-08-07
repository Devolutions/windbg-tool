cmake_minimum_required(VERSION 3.16)

project(ttd_replay_bridge LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT DEFINED TTD_APIS_PACKAGE_DIR)
    set(TTD_APIS_PACKAGE_DIR "${CMAKE_CURRENT_LIST_DIR}/../../target/nuget/Microsoft.TimeTravelDebugging.Apis.0.9.5")
endif()

find_package(
    Microsoft.TimeTravelDebugging.Apis
    CONFIG
    REQUIRED
    PATHS "${TTD_APIS_PACKAGE_DIR}/CMake"
    NO_DEFAULT_PATH
)

add_library(ttd_replay_bridge SHARED ttd_replay_bridge.cpp)

target_compile_definitions(ttd_replay_bridge
    PRIVATE
        TTD_MCP_USE_TTD_REPLAY
        NOMINMAX
        WIN32_LEAN_AND_MEAN
)

target_link_libraries(ttd_replay_bridge
    PRIVATE
        Microsoft.TimeTravelDebugging.Apis::TTDReplay
)

set_target_properties(ttd_replay_bridge PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)