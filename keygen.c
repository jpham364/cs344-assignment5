#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// For generating numbers
// https://www.geeksforgeeks.org/generating-random-number-range-c/
#include <time.h>

// Using code from Assignment 1 to handle input/output

int main(int argc, char* argv[]){

    srand(time(0));

    if(argc != 2){
        // Using fprintf() to print to stderr
        // https://www.delftstack.com/howto/c/c-print-to-stderr/
        fprintf(stderr, "You must follow the format of keygen to create a key!\n");
        fprintf(stderr, "Example: keygen 145\n");
        return EXIT_FAILURE;
    }

    // Convert string to int
    int numChars = atoi(argv[1]);

    int i = 0;

    for(i = 0; i < numChars; i++){

        // get random number first
        int randomChar = rand();

        // Since there is 26 letters in alphabet and a space allowed = 27 characters
        // Capital A = 65
        // Capital Z = 90
        // Lets use 91 as space so Range = 26 + 1

        // Printing within a range
        // https://www.geeksforgeeks.org/generating-random-number-range-c/#
        randomChar = (randomChar % 27) + 65;

        if(randomChar == 91){
            printf(" ");
        }

        else{  
            printf("%c", randomChar);
        }

    }

    // Last character is newline
    printf("\n");

    return EXIT_SUCCESS;

}