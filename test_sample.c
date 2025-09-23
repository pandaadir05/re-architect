#include <stdio.h>
#include <string.h>

int add_numbers(int a, int b) {
    return a + b;
}

int multiply_numbers(int x, int y) {
    return x * y;
}

void greet_user(char* name) {
    printf("Hello, %s!\n", name);
}

int main() {
    int result1 = add_numbers(5, 3);
    int result2 = multiply_numbers(4, 6);
    
    printf("Addition result: %d\n", result1);
    printf("Multiplication result: %d\n", result2);
    
    char name[] = "World";
    greet_user(name);
    
    return 0;
}