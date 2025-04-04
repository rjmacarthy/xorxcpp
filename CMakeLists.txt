cmake_minimum_required(VERSION 3.10)
project(KademliaDHT)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add compiler flags
add_compile_options(-Wall -Wextra -pedantic -g)

# Set build type to Debug if not specified
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})

# Source files
set(SOURCES
    main.cpp
    src/node.cpp
    src/routing_table.cpp
    src/holepunch.cpp
    src/kademlia.cpp
    src/utils.cpp
    src/dht_key.cpp
)

# Create executable
add_executable(kademlia_dht ${SOURCES})

# Link libraries
target_link_libraries(kademlia_dht ${OPENSSL_LIBRARIES} Threads::Threads)

# Install
install(TARGETS kademlia_dht DESTINATION bin)