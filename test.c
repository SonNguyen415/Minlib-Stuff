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
int used_var = 100;

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
    printf("Hello from fn1\n");
}

int main() {
    printf("Hello, World!\n");
    struct data *d = fn1();
    fn2(d);
    printf("Global variable: %d\n", used_var);

    printf("%d\n", d->a);
    return 0;
}
