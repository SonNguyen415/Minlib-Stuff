#include <stdio.h>
#include <stdlib.h>
struct data {
    union {
        int a;
        char b;
    };
    unsigned long arr[10];
};

int unused_var = 42;
int used_var = 4095;
int bss_var;
int bss_unused;

struct data *fn() {
    struct data *d = malloc(sizeof(struct data));
    d->a = 10;
    d->arr[0] = 10;
    return d;
}

void unused_fn() {
    printf("Hello from fn1\n");
}


int main() {
    bss_var = 100; // Initialize BSS variable
    
    struct data * struct1 = fn();
    printf("Data a: %d\n", struct1->a);
    printf("Global variable: %d\n", used_var);
    printf("BSS variable: %d\n", bss_var);

    free(struct1);
    return 0;
}
