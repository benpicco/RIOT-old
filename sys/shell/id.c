#include <stdio.h>
#include <string.h>
#include <config.h>
#include <stdlib.h>

void _id_handler(char *id) {
    long newid;

    newid = atoi(id+3);
    if (strlen(id) < 3) {
#ifdef MODULE_CONFIG
        printf("Current id: %u\n", sysconfig.id);
#endif
    }
    else {
        printf("Setting new id %lu\n", newid);
#ifdef MODULE_CONFIG
        sysconfig.id = newid;
        if (!config_save()) {
            puts("ERROR setting new id");
        }
#endif
    }
}
