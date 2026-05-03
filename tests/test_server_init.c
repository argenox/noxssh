#include <stdlib.h>
#include "noxssh_server.h"

int main(void)
{
    netnox_ssh_server_t s;
    if(netnox_ssh_server_init(&s) != NETNOX_RETURN_SUCCESS) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
