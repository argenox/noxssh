add_executable(noxsshd
    main.c
    daemon_runtime.c
)

target_include_directories(noxsshd
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/common
)

target_link_libraries(noxsshd
    PRIVATE
        netnox_ssh
)

if(WIN32)
    target_link_libraries(noxsshd PRIVATE ws2_32)
endif()
