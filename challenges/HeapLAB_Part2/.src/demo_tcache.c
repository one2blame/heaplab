#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {

    void* a = malloc(0x18);
    void* b = malloc(0x18);

    free(a);
    free(b);

    void* c = malloc(0x18);
    void* d = malloc(0x18);

    void* e = malloc(0x408);
    free(e);

    void* f = malloc(0x418);
    malloc(0x18);
    free(f);

    return 0;
}
