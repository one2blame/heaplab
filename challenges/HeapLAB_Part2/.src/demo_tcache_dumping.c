#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {

    void* array[14];
    for(int i=0; i<sizeof(array)/sizeof(void*); i++)
        array[i] = malloc(0x18);

    for(int i=0; i<sizeof(array)/sizeof(void*); i++)
        free(array[i]);

    for(int i=0; i<7; i++)
        malloc(0x18);

    malloc(0x18);

    return 0;
}
