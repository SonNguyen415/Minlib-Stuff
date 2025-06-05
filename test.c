#include <stdio.h>
#include <stdlib.h>
struct data {
    union {
        int a;
        char b;
    };
    unsigned long arr[10];
};

struct data unused_var = { .a = 5, .arr = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9} };
int used_var = 4095;
int bss_var;
short bss_unused;

struct data *fn() {
    struct data *d = malloc(sizeof(struct data));
    d->a = 17;
    d->arr[0] = 13;
    return d;
}

void unused_fn() {
    printf("Hello from fn1\n");
}


int main() {
    bss_var = 175; // Initialize BSS variable
    
    struct data * struct1 = fn();
    printf("Data a: %d\n", struct1->a);
    printf("Global variable: %d\n", used_var);
    printf("BSS variable: %d\n", bss_var);

    free(struct1);
    return 0;
}
