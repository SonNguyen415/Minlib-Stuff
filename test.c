#include <stdio.h>
#include <stdlib.h>
struct data {
    union {
        int a;
        char b;
    };
    unsigned long arr[10];
};

int unused_global;

struct data *fn1() {
    struct data *d = malloc(sizeof(struct data));
    d->a = 10;
    d->arr[0] = 10;
    return d;
}

void fn2(struct data *d) {
    if (d) {
        d->a = 20;
    }
}

void unused() {
    int unused_variable;
    unused_global = 42; // This variable is unused
    printf("Hello from fn1\n");
}

int main() {
    printf("Hello, World!\n");
    struct data *d = fn1();
    fn2(d);
    printf("%d\n", d->a);
    return 0;
}
