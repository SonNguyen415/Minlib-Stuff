
// // int arr[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
#include <stdio.h>
#include <stdlib.h>

struct data {
    union {
        int a;
        char b;
    };
    unsigned long arr[10];
};

struct data * fn1() {
    struct data *d = (struct data *)malloc(sizeof(struct data));
    d->a = 10;
    d->arr[0] = 10;
    return d;
}

static void fn2(struct data * d) {
    if(d) {
        d->a = 20;
    }
}

void fn3(struct data *d) {
    if(d) {
        d->a = 30;
    }
}

void unused() 
{
    printf("Hello from fn1\n");
}

int main()
{
    printf("Hello, World!\n");
    struct data *d = fn1();
    fn2(d);
    printf("%d\n", d->a);
    return 0;
}