add_executable(test_server_init
    test_server_init.c
)
target_include_directories(test_server_init
    PRIVATE
        ${CMAKE_SOURCE_DIR}/common
)
target_link_libraries(test_server_init
    PRIVATE
        netnox_ssh
)
add_test(NAME server_init COMMAND test_server_init)
