// CS344 - Operating Systems 
// Assignment 5: dec_client.c
// Jonathan Pham
// 934256908
// phamjon@oregonstate.edu

// SOURCES: (includes posted client.c and server.c code)
// Using Exploration: stdin, stdout, stderr & C I/O library
// Using Exploration: Files
// 2.4 Lecture: File Access in C
// 4.2 Network Clients Lecture: Slide 18

// https://man7.org/linux/man-pages/man3/fgetc.3.html
// https://edstem.org/us/courses/37585/discussion/3201754?answer=7333443
// https://man7.org/linux/man-pages/man3/fgets.3p.html
// https://beej.us/guide/bgnet/html/#setsockoptman

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  // ssize_t
#include <sys/socket.h> // send(),recv()
#include <netdb.h>      // gethostbyname()

// For files
#include <fcntl.h>



// Error function used for reporting issues
void error(const char *msg) { 
  perror(msg); 
  exit(0); 
} 

// Set up the address struct
void setupAddressStruct(struct sockaddr_in* address, int portNumber, char* hostname){
 
    // Clear out the address struct
    memset((char*) address, '\0', sizeof(*address)); 

    // The address should be network capable
    address->sin_family = AF_INET;
    // Store the port number
    address->sin_port = htons(portNumber);

    // Get the DNS entry for this host name
    struct hostent* hostInfo = gethostbyname(hostname); 
    if (hostInfo == NULL) { 
        fprintf(stderr, "CLIENT: ERROR, no such host\n"); 
        exit(0); 
    }
    // Copy the first IP address from the DNS entry to sin_addr.s_addr
    memcpy((char*) &address->sin_addr.s_addr, hostInfo->h_addr_list[0], hostInfo->h_length);
}

int main(int argc, char *argv[]) {

    int socketFD, portNumber, charsWritten, charsRead;
    struct sockaddr_in serverAddress;

    // This is for sending/reading in partial chunks
    char buffer[1000];

    // completeMessage = ciphertext + key combined
    // decodedtext = returned decodedtext from server
    char decodedtext[500000];
    char completeMessage[500000];

    // cipherChar and keyChar are the separate strings passed in
    char cipherChar[250000];
    char keyChar[250000];

    // Check usage & args
    if (argc != 4) { 
        fprintf(stderr,"USAGE: %s ciphertext key port\n", argv[0]); 
        exit(0); 
    } 

    //////////////////////
    //////////////////////
    //  Step 1: Checking for KEY < CT   
    //  Check if key file is shorter than ciphertext      
    //////////////////////
    //////////////////////

    
    // Using Exploration: stdin, stdout, stderr & C I/O library
    // 2.4 Lecture: File Access in C
    // We can use I/O funcitons in C Standard Library
    
    // This is for the ciphertext file
    FILE *ciphertext;
    ciphertext = fopen(argv[1], "r");
    
    if(ciphertext == NULL){
        fprintf(stderr,"ERROR: Cannot open file\n"); 
        exit(1); 
    }

    // This will automatically allocate by getline() using malloc() (found in 2.4 slides)
    char* cipherContents = NULL;
    size_t GETbufferSize = 0;
    
    // store the length of ciphertext file
    getline(&cipherContents, &GETbufferSize, ciphertext);
    int cipherLen = strlen(cipherContents);
   

    // This is for the key file
    FILE *key;
    key = fopen(argv[2], "r");

    if(key == NULL){
        fprintf(stderr,"ERROR: Cannot open file\n"); 
        exit(1); 
    }

    char *keyContents = NULL;
    GETbufferSize = 0;

    // store the length of the key file
    getline(&keyContents, &GETbufferSize, key);
    int keyLen = strlen(keyContents);
    
    // Now, we can check if the key is shorter than ciphertext
    // If so, exit 
    if (keyLen < cipherLen){
        fprintf(stderr, "ERROR: Key (%d) is shorter than ciphertext(%d) \n", keyLen, cipherLen); 
        exit(1);
    }
    
   

    //////////////////////
    //////////////////////
    // Step 2: CHECK FOR BAD CHARACTERS         
    //////////////////////
    //////////////////////

    ciphertext = fopen(argv[1], "r");

    char cipherCharCheck;

    // ASCII:
    // Space = 32
    // A = 65
    // Z = 90
    // \n = 10

    // check ciphertext
    do{
        // https://man7.org/linux/man-pages/man3/fgetc.3.html
        // Check character one-by-one
        cipherCharCheck = fgetc(ciphertext);

        // if it is a space
        if(cipherCharCheck == 32){
            continue;
        }

        // between A to Z
        else if(cipherCharCheck > 64 && cipherCharCheck < 91){
            continue;
        }

        // if newLine, will exit after current loop
        else if(cipherCharCheck == 10){
            continue;
        }

        // else, its a bad character! exit
        else{
            fprintf(stderr, "ERROR: Bad character(s) \n"); 
            exit(1);
        }

    }while(cipherCharCheck != 10);

    // check for key
    key = fopen(argv[2], "r");

    char keyCharCheck;

    do{
       
        keyCharCheck = fgetc(key);

        // if it is a space
        if(keyCharCheck == 32){
            continue;
        }
        // between A to Z
        else if(keyCharCheck > 64 && keyCharCheck < 91){
            continue;
        }
        // if newLine, will exit after current loop
        else if(keyCharCheck == 10){
            continue;
        }

        // else, its a bad character! exit
        else{
            fprintf(stderr, "ERROR: Bad character(s) \n"); 
            exit(1);
        }

    }while(keyCharCheck != 10);
    



    //////////////////////
    //////////////////////
    //  Step 3: CLIENT SOCKET/CONNECT         
    //////////////////////
    //////////////////////

    
    // Create a socket
    socketFD = socket(AF_INET, SOCK_STREAM, 0); 
    if (socketFD < 0){
        error("CLIENT: ERROR opening socket");
    }

    // Set up the server address struct
    // 2nd argument = port number
    // 3rd argument = hostname (always localhost)
    setupAddressStruct(&serverAddress, atoi(argv[3]), "localhost");

    // Connect to server
    if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0){
        // error("CLIENT: ERROR connecting");
        fprintf(stderr, "Attempted port: %i\n", ntohs(serverAddress.sin_port));
        fprintf(stderr, "CLIENT: ERROR connecting\n", ntohs(serverAddress.sin_port));
        exit(2);
    }

    

    //////////////////////
    //////////////////////
    //  Step 4: CHECK FOR RIGHT SERVER  
    //  This first section verifies that the enc_client is connected to the correct enc_server  
    //////////////////////
    //////////////////////
    
   
    // Clear out the buffer array
    memset(buffer, '\0', sizeof(buffer));

    // Uses https://edstem.org/us/courses/37585/discussion/3201754?answer=7333443
    // This logic allows the client to send a message to the server so it can check 
    
    strcpy(buffer, "DEC"); // in this file, DEC is used for decoding

    // Send message to server
    charsWritten = send(socketFD, buffer, strlen(buffer), 0); 

    if (charsWritten < 0){
        error("CLIENT: ERROR writing to socket");
    }

    if (charsWritten < strlen(buffer)){
        printf("CLIENT: WARNING: Not all data written to socket!\n");
    }

    // Get return message from server
    // Clear out the buffer again for reuse
    memset(buffer, '\0', sizeof(buffer));

    // Read data from the socket, leaving \0 at end
    charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); 
    if (charsRead < 0){
        error("CLIENT: ERROR reading from socket");
    }
    
    
    // We check if the returned buffer is a NO
    // If NO, then exit (wrong server)
    // Else, continue;
    if(strcmp(buffer, "NO") == 0){
        fprintf(stderr, "Attempted port: %i\n", ntohs(serverAddress.sin_port));
        fprintf(stderr, "CLIENT: Connected to wrong server (NOT ENC)\n", ntohs(serverAddress.sin_port));
        exit(2);
    }


    //////////////////////
    //////////////////////
    //  Step 5: CONCATENATE CT AND KEY         
    //////////////////////
    //////////////////////

    // First set up CT
    memset(cipherChar, '\0', sizeof(cipherChar));
    ciphertext = fopen(argv[1], "r");

    // use fgets() to retrieve string from file
    // https://man7.org/linux/man-pages/man3/fgets.3p.html
    fgets(cipherChar, sizeof(cipherChar), ciphertext);

    // Remove the trailing \n that fgets adds (client.c)
    cipherChar[strcspn(cipherChar, "\n")] = '\0'; 
    

    // Then, set up Key
    memset(keyChar, '\0', sizeof(keyChar));
    key = fopen(argv[2], "r");

    fgets(keyChar, sizeof(keyChar), key);

    keyChar[strcspn(keyChar, "\n")] = '\0'; 


    // Finally, we concat CT and Key using strcat()
    strcat(completeMessage, cipherChar);
    strcat(completeMessage, "-");
    strcat(completeMessage,keyChar);
    strcat(completeMessage, "@@");

    //////////////////////
    //////////////////////
    //  Step 6: SENDING DATA   
    //////////////////////
    //////////////////////

    // store length of entire concatenated string into int
    int completeMessageLen = strlen(completeMessage);


    // Initialize: 
    // charsWritten = Total
    // charsSent = one loop
    charsWritten = 0;
    int charsSent = 0;
   
    // Adapted code from Beej Guide:
    // https://beej.us/guide/bgnet/html/#setsockoptman

    // Keep doing while there is still more text left in completeMessageLen
    while(charsWritten < completeMessageLen){

        // create a buffer variable inside the loop
        int theBuffer = sizeof(buffer);

        // If there are less than 1000 chars to send, shorten the buffer 
        if((completeMessageLen - charsWritten) < 1000){
            theBuffer = (completeMessageLen - charsWritten) + 1;
        }


        // Send a chunk of the message
        // completeMessage + charsWritten will track where we are in the loop
        charsSent = send(socketFD, completeMessage + charsWritten, theBuffer, 0);
        
        // Error handling from 4.2 Lecture sl. 18
        if (charsSent == 0){
            break;
        }
        if (charsSent == -1){
            break;
        }

        // Increase the total of charsWritten
        charsWritten = charsWritten + charsSent;
    }

    // Error handle
    if (charsWritten <= strlen(buffer)){
        printf("CLIENT: WARNING: Not all data written to socket!\n");
    }

    
    //////////////////////
    //////////////////////
    //  Step 7: RECEIVE ENCRYPTED DATA  
    //  Get return message from server       
    //////////////////////
    //////////////////////

    
    // Clear out the buffer again for reuse
    memset(decodedtext, '\0', sizeof(decodedtext));
    charsRead = 0;

    // This entire chunk of text is taken from 4.2 Network Clients Lecture: Slide 18
    while(strstr(decodedtext, "@@") == NULL){

        // clear buffer
        memset(buffer, '\0', sizeof(buffer));

        // get next chunk
        charsRead = recv(socketFD, buffer, sizeof(buffer)-1, 0);

        // add the chunk to total ciphertext
        strcat(decodedtext, buffer);

        // Error handling
        if(charsRead == -1){
            break;
        }
        if(charsRead == 0){
            break;
        }

    }

    // Locate the terminal
    int terminalLocation = strstr(decodedtext, "@@") - decodedtext;

    // Replace the terminal location with a null terminator
    decodedtext[terminalLocation] = '\0';

    // output it out!
    printf("%s\n", decodedtext);    

    // Close the socket
    close(socketFD); 

    

    return 0;
}