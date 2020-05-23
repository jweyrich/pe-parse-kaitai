cmake_minimum_required (VERSION 3.11)
project (demo LANGUAGES CXX VERSION 1.0)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(demo src/main.cpp src/microsoft_pe.cpp)

#add_subdirectory (src/subdir)

# Add zlib library
find_package(ZLIB)
if(ZLIB_FOUND)
    include_directories(${ZLIB_INCLUDE_DIRS})
    target_link_libraries(demo PUBLIC ${ZLIB_LIBRARIES})
else()
    message(FATAL_ERROR "zlib not found")
endif()

# Add iconv library
find_package(Iconv)
if(Iconv_FOUND)
    include_directories(${Iconv_INCLUDE_DIRS})
    target_link_libraries(demo PUBLIC ${Iconv_LIBRARIES})
else()
    message(FATAL_ERROR "iconv not found")
endif()

# Add kaitai library
add_library (kaitai STATIC EXCLUDE_FROM_ALL "${PROJECT_SOURCE_DIR}/lib/kaitai/kaitai/kaitaistream.cpp")
target_include_directories(kaitai SYSTEM PUBLIC "${PROJECT_SOURCE_DIR}/lib/kaitai")
target_compile_definitions(kaitai PRIVATE KS_STR_ENCODING_NONE)
target_link_libraries(demo PUBLIC kaitai)

# Get the current working branch
execute_process(
  COMMAND git rev-parse --abbrev-ref HEAD
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_BRANCH
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET
)
if(NOT GIT_BRANCH)
  set(GIT_BRANCH "unknown")
endif()
message(STATUS "Git branch: ${GIT_BRANCH}")

# Get the latest abbreviated commit hash of the working branch
execute_process(
  COMMAND git log -1 --format=%h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_COMMIT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET
)
if(NOT GIT_COMMIT_HASH)
    set(GIT_COMMIT_HASH "unknown")
endif()
message(STATUS "Git commit: ${GIT_COMMIT_HASH}")