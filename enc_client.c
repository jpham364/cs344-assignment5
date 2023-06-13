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
    char buffer[1000];

    char ciphertext[500000];
    char completeMessage[500000];
    char ptChar[250000];
    char keyChar[250000];

    // Check usage & args
    if (argc != 4) { 
        fprintf(stderr,"USAGE: %s plaintext key port\n", argv[0]); 
        exit(0); 
    } 

    //////////////////////
    //////////////////////
    //  Checking for KEY > PT         
    //////////////////////
    //////////////////////


    // Check if key file is shorter than plaintext
    // Using Exploration: stdin, stdout, stderr & C I/O library
    // Using Exploration: Files
    // 2.4 Lecture: File Access in C
    
    // This is for the plaintext file
    FILE *plaintext;
    plaintext = fopen(argv[1], "r");
    
    if(plaintext == NULL){
        fprintf(stderr,"ERROR: Cannot open file\n"); 
        exit(1); 
    }

    // This will automatically allocate by getline() using malloc() (found in 2.4 slides)
    char* ptContents = NULL;
    size_t GETbufferSize = 0;
    
    getline(&ptContents, &GETbufferSize, plaintext);
   

    int ptLen = strlen(ptContents);
    // printf("Length of PT: %d\n", ptLen);

    // This is for the key file
    FILE *key;
    key = fopen(argv[2], "r");

    if(key == NULL){
        fprintf(stderr,"ERROR: Cannot open file\n"); 
        exit(1); 
    }

    char *keyContents = NULL;
    GETbufferSize = 0;
    getline(&keyContents, &GETbufferSize, key);
    int keyLen = strlen(keyContents);
    // printf("Length of Key: %d\n", keyLen);

    if (keyLen < ptLen){
        fprintf(stderr, "ERROR: Key (%d) is shorter than plaintext(%d) \n", keyLen, ptLen); 
        exit(1);
    }
    
    // printf("CHECKED KEY < PT\n");

    //////////////////////
    //////////////////////
    // CHECK FOR BAD CHARACTERS         
    //////////////////////
    //////////////////////

    plaintext = fopen(argv[1], "r");

    char ptCharCheck;

    do{
        ptCharCheck = fgetc(plaintext);

        if(ptCharCheck == 32){
            continue;
        }
        else if(ptCharCheck > 64 && ptCharCheck < 91){
            continue;
        }
        else if(ptCharCheck == 10){
            continue;
        }
        else{
            fprintf(stderr, "ERROR: Bad character(s) \n"); 
            exit(1);
        }

    }while(ptCharCheck != 10);

    // printf("CHECKED BAD CHARACTERS\n");



    //////////////////////
    //////////////////////
    //  CLIENT SOCKET/CONNECT         
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

    // printf("CONNECTED TO SERVER\n");

    //////////////////////
    //////////////////////
    //  CHECK FOR RIGHT SERVER    
    //////////////////////
    //////////////////////
    
    // This first section verifies that the enc_client is connected to the correct enc_server
    // Get input message from user
    // printf("CLIENT: Sending ENC...\n");

    // Clear out the buffer array
    memset(buffer, '\0', sizeof(buffer));

    // Uses https://edstem.org/us/courses/37585/discussion/3201754?answer=7333443
    // This logic allows the client to send a message to the server so it can check 
    strcpy(buffer, "ENC");

    // Send message to server
    // Write to the server
    charsWritten = send(socketFD, buffer, strlen(buffer), 0); 

    if (charsWritten < 0){
        error("CLIENT: ERROR writing to socket");
    }

    if (charsWritten < strlen(buffer)){
        printf("CLIENT: WARNING: Not all data written to socket!\n");
    }

    // Get return message from server
    // Clear out the buffer again for reuse
    printf("RECIEVING SERVER CHECK...\n");

    memset(buffer, '\0', sizeof(buffer));
    // Read data from the socket, leaving \0 at end
    charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); 
    if (charsRead < 0){
        error("CLIENT: ERROR reading from socket");
    }
    
    // printf("%s\n", buffer);

    if(strcmp(buffer, "NO") == 0){
        fprintf(stderr, "Attempted port: %i\n", ntohs(serverAddress.sin_port));
        fprintf(stderr, "CLIENT: Connected to wrong server (NOT ENC)\n", ntohs(serverAddress.sin_port));
        exit(2);
    }

    // printf("CHECKED FOR RIGHT SERVER\n");

    //////////////////////
    //////////////////////
    //  CONCATENATE PT AND KEY         
    //////////////////////
    //////////////////////

    // First set up PT
    memset(ptChar, '\0', sizeof(ptChar));
    plaintext = fopen(argv[1], "r");

    fgets(ptChar, sizeof(ptChar), plaintext);

    // Remove the trailing \n that fgets adds
    ptChar[strcspn(ptChar, "\n")] = '\0'; 
    
    // printf("String: %s\n", ptChar);

    // Then, set up Key
    memset(keyChar, '\0', sizeof(keyChar));
    key = fopen(argv[2], "r");

    fgets(keyChar, sizeof(keyChar), key);
    // Remove the trailing \n that fgets adds
    keyChar[strcspn(keyChar, "\n")] = '\0'; 
    // printf("Key: %s\n", keyChar);

    // Finally, we concat using strcat
    strcat(completeMessage, ptChar);
    strcat(completeMessage, "-");
    strcat(completeMessage,keyChar);

    // printf("Concat: ");
    // printf("%s\n", completeMessage);

    // printf("CONCATENATED PT AND KEY\n");

    //////////////////////
    //////////////////////
    //  SENDING SIZE        
    //////////////////////
    //////////////////////

    // printf("SENDING SIZE...\n");
    // prepare to send size of string
    // https://www.geeksforgeeks.org/what-is-the-best-way-in-c-to-convert-a-number-to-a-string/
    memset(buffer, '\0', sizeof(buffer));
    sprintf(buffer, "%d", strlen(completeMessage));

    charsWritten = send(socketFD, buffer, strlen(buffer), 0); 

    if (charsWritten < 0){
        error("CLIENT: ERROR writing to socket");
    }

    if (charsWritten < strlen(buffer)){
        printf("CLIENT: WARNING: Not all data written to socket!\n");
    }

    // printf("SENT SIZE\n");

    //////////////////////
    //////////////////////
    //  SENDING DATA   
    //////////////////////
    //////////////////////

    // printf("SENDING DATA...\n");
    int completeMessageLen = strlen(completeMessage);

    charsWritten = 0;
    int charsSent = 0;
   
    // Adapted code from Beej Guide:
    // https://beej.us/guide/bgnet/html/#setsockoptman
    while(charsWritten < completeMessageLen){

        charsSent = send(socketFD, completeMessage + charsWritten, 1000, 0);
        charsWritten = charsWritten + charsSent;

        if (charsWritten == 0){
            break;
        }
        if (charsWritten == -1){
            break;
        }

        if (charsWritten <= strlen(buffer)){
        printf("CLIENT: WARNING: Not all data written to socket!\n");
        }
        
    }

    

    // printf("CLIENT SENT: %lu\n", charsWritten);
    // printf("SENT DATA\n");

    //////////////////////
    //////////////////////
    //  RECEIVE ENCRYPTED DATA         
    //////////////////////
    //////////////////////

    // Get return message from server
    // Clear out the buffer again for reuse
    // printf("RECIEVING ENCRYPTED DATA...\n");
    
    memset(ciphertext, '\0', sizeof(ciphertext));
    charsRead = 0;
    int temp = 0;

    do{
        memset(buffer, '\0', sizeof(buffer));
        temp = recv(socketFD, buffer, sizeof(buffer) - 1, 0);
        strcat(ciphertext, buffer);

        if (temp == -1){ 
            break;
        }

        if (temp == 0){
            break;
        }

        charsRead += temp;
    }while(charsRead < completeMessageLen);
   

    // printf("RECIEVED ENCRYPTED DATA\n");

    printf("%s\n", ciphertext);

    // Close the socket
    close(socketFD); 
    return 0;
}










