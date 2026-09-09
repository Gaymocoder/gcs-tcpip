cmake_minimum_required(VERSION 3.31)
project(gcstcpip
        VERSION     0.3.0
        DESCRIPTION "Учебный стек TCP/IP поверх Ethernet"
        LANGUAGES   C)

block()
    include(${CMAKE_CURRENT_LIST_DIR}/cmake/gcst/utils.cmake)
    include(${CMAKE_CURRENT_LIST_DIR}/cmake/gcs/warnings_c.cmake)

    set(CMAKE_C_STANDARD          11)
    set(CMAKE_C_STANDARD_REQUIRED ON)
    set(CMAKE_C_EXTENSIONS        ON)   # нужен для TUNSETIFF из linux/if_tun.h

    set(GCST_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include")
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

    gcst_message("Проект ${PROJECT_NAME} ${PROJECT_VERSION}, стандарт C${CMAKE_C_STANDARD}")

    add_subdirectory(src)
    add_subdirectory(app)
endblock()
