add_executable(noxssh
    main.c
)

target_include_directories(noxssh
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/common
)

target_link_libraries(noxssh
    PRIVATE
        netnox_ssh
)

if(WIN32)
    target_link_libraries(noxssh PRIVATE ws2_32)
endif()
