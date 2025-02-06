#include <stdio.h>
#include <stdlib.h>

// Function prototypes
void function1();
void function2();
void function3();
void function4();

int hmm = 20;

struct test {
    char something[24];
    unsigned long data;
};

int main() {
    int x = 50;
    struct test * test = malloc(sizeof(struct test));
    test->data = 25;

    printf("Calling function1...\n");
    function1();

    printf("Calling function2...\n");
    function2();

    printf("Calling function3...\n");
    function3();

    printf("Calling function4...\n");
    function4();

    printf("Data: %ld\n", test->data);

    free(test);

    return 0;
}

// Function definitions
void function1() {
    printf("This is function1.\n");
}

void function2() {
    printf("This is function2.\n");
}

void function3() {
    printf("This is function3.\n");
}

void function4() {
    printf("This is function4.\n");
}
