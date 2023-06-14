// CS344 - Operating Systems 
// Assignment 5: dec_server.c
// Jonathan Pham
// 934256908
// phamjon@oregonstate.edu

// SOURCES: (includes posted client.c and server.c code)
// Lecture 4.2: Network Clients sl. 18
// Exploration: Strings

// https://www.educative.io/blog/concatenate-string-c
// https://beej.us/guide/bgnet/html/#setsockoptman

// This logic helped in understanding receiving plaintext4 
// https://edstem.org/us/courses/37585/discussion/3202199?comment=7336513 


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Error function used for reporting issues
void error(const char *msg) {
  perror(msg);
  exit(1);
} 

// Set up the address struct for the server socket
void setupAddressStruct(struct sockaddr_in* address, int portNumber){
 
    // Clear out the address struct
    memset((char*) address, '\0', sizeof(*address)); 

    // The address should be network capable
    address->sin_family = AF_INET;
    // Store the port number
    address->sin_port = htons(portNumber);
    // Allow a client at any address to connect to this server
    address->sin_addr.s_addr = INADDR_ANY;
}

int main(int argc, char *argv[]){

    int connectionSocket, charsRead;
    char buffer[1000];

    // completeMessage = combined CT and Key
    // decodedtext = created decodedtext by server
    char decodedtext[500000];
    char completeMessage[500000];

    // These Char variables holds the separate strings of CT and Key
    char cipherChar[250000];
    char keyChar[250000];
    

    struct sockaddr_in serverAddress, clientAddress;
    socklen_t sizeOfClientInfo = sizeof(clientAddress);

    // Check usage & args
    if (argc < 2) { 
        fprintf(stderr,"USAGE: %s listening_port\n", argv[0]); 
        exit(1);
    } 
    
    // Create the socket that will listen for connections
    int listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket < 0) {
        error("ERROR opening socket");
    }

    // Set up the address struct for the server socket
    setupAddressStruct(&serverAddress, atoi(argv[1]));

    // Associate the socket to the port
    if (bind(listenSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0){
        error("ERROR on binding");
    }

    // Start listening for connetions. Allow up to 5 connections to queue up
    listen(listenSocket, 5); 
    printf("SERVER: listening...\n");
    
    // Accept a connection, blocking if one is not available until one connects
    while(1){


        // Accept the connection request which creates a connection socket
        connectionSocket = accept(listenSocket, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); 
        if (connectionSocket < 0){
            error("ERROR on accept");
        }

       
        //////////////////////
        //////////////////////
        //  Step 0: FORK PROCESS UPON ACCEPT      
        //////////////////////
        //////////////////////
        pid_t spawnpid = -5;
        spawnpid = fork();


        switch(spawnpid){

            case -1:
                // Child fails!
                perror("Hull Breach!");
                exit(1);
                break;
            case 0: 
                
                // Start processing data from Client!
                // printf("SERVER: Connected to client running at host %d port %d\n", ntohs(clientAddress.sin_addr.s_addr), ntohs(clientAddress.sin_port));

                //////////////////////
                //////////////////////
                // Step 1: RECEIVING CLIENT CHECK        
                //////////////////////
                //////////////////////


                // Get the message from the client 
                // Clear buffer first
                memset(buffer, '\0', 1000);

                // Read the client's message from the socket
                charsRead = recv(connectionSocket, buffer, 999, 0); 

                // Error handle
                if (charsRead < 0){
                    error("ERROR reading from socket");
                }
             

                // Check if the buffer received is DEC (since this is dec_server)
                if (strcmp(buffer, "DEC") != 0){
                    
                    // If DEC does not match send back a NO
                    charsRead = send(connectionSocket, "NO", 2, 0); 
                    if (charsRead < 0){
                        error("ERROR writing to socket");
                    }
                }

                // Else, send a YES that it is the right client connection
                else{
                    charsRead = send(connectionSocket, "YES", 3, 0); 
                    if (charsRead < 0){
                        error("ERROR writing to socket");
                    }

                }

           
                //////////////////////
                //////////////////////
                // Step 2: RECEIVING DATA        
                //////////////////////
                //////////////////////

                // Clear completeMessage to store incoming data
                memset(completeMessage, '\0', sizeof(completeMessage));

                // reset charsRead variable to 0
                charsRead = 0;


                // Received code is from Lecture 4.2: Network Clients sl. 18

                while(strstr(completeMessage, "@@") == NULL){

                    memset(buffer, '\0', sizeof(buffer)); // clear buffer

                    charsRead = recv(connectionSocket, buffer, sizeof(buffer)-1 , 0); // get next chunk

                    strcat(completeMessage, buffer); // add the chunk to total ciphertext
                    
                    
                    if (charsRead == -1){
                        
                        break;

                    }
                    if (charsRead == 0){
                       
                        break;

                    }

                }

                // Locate the terminal
                int terminalLocation = strstr(completeMessage, "@@") - completeMessage;

                // Replace the terminal location with a null terminator
                completeMessage[terminalLocation] = '\0';

                ////////////////////
                ////////////////////
                // Step 3: SEPARATE DATA        
                // Split the entire message into separate plaintext and key strings
                ////////////////////
                ////////////////////

                // initialize token and saveptr
                char *token;
                char *saveptr;
                
                // Get ciphertext using strtok_r
                // Documentation from Exploration: Strings
                token = strtok_r(completeMessage, "-", &saveptr);

                // clear cipherChar and copy token into it
                memset(cipherChar, '\0', sizeof(cipherChar));
                strcpy(cipherChar, token);


                // tokenize again to get Key
                token = strtok_r(NULL, "\0", &saveptr);

                // clear keyChar and copy token into it
                memset(keyChar, '\0', sizeof(keyChar));
                strcpy(keyChar, token);

             
                //////////////////////
                //////////////////////
                //  Step 4: DECODE         
                //////////////////////
                //////////////////////

                // for loop
                int i;

                // these variables will represent characters with integers
                char cipherInt;
                char keyInt;
                int decodedInt; 

                // Clear decodedtext to store 
                memset(decodedtext, '\0', sizeof(decodedtext));


                // ASCII:
                // Space = 32
                // A = 65
                // Z = 90
                // \n = 10

                // Pad Format: (0-26)
                // A = 0
                // Z = 25
                // Space = 26

                // Loop the entire ciphertext and key for each character in the ciphertext
                for (i = 0; i < strlen(cipherChar); i++){

                    // If the current CT char is a space
                    // assign the cipherInt as 26 according to the Pad
                    if(cipherChar[i] == 32){
                        cipherInt = 26;
                    }

                    // Else convert to ASCII as normal by sub 65
                    else{
                        cipherInt = cipherChar[i] - 65;
                    }

                    // If the current Key char is a space
                    // assign the keyInt as 26 according to the Pad
                    if(keyChar[i] == 32){
                        keyInt = 26;
                    }

                    // Else convert to ASCII as normal by sub 65
                    else{
                        keyInt = keyChar[i] - 65;
                    }
                    

                    // Subtract the CT int with the key int
                    decodedInt = (cipherInt - keyInt);

                    // According to the Assignment 5 Page
                    // "If a number is negative, then 26 is added to make the number zero or higer"
                    if(decodedInt < 0){
                        decodedInt += 27;
                    }

                    // Else, Mod 27 (not 26 because of space)
                    else{
                        decodedInt = decodedInt % 27;
                    }


                    // Now we can append char to string

                    // If the calcualted cipherInt is 26, concat a space  
                    if(decodedInt == 26){
                        sprintf(decodedtext, "%s%c", decodedtext, ' ');
                    }

                    // Else, concat a normal ASCII character
                    else{
                        sprintf(decodedtext, "%s%c", decodedtext,(decodedInt + 65));
                    }

                }

                // Append a terminal @@ to send/recieve later: 4.2 (sl. 18)
                strcat(decodedtext, "@@");
               

                //////////////////////
                //////////////////////
                // Step 5: SEND BACK DECODED DATA         
                //////////////////////
                //////////////////////

                // clear buffer
                memset(buffer, '\0', sizeof(buffer));

                // Set variables to 0;
                // charsWritten = total
                // charsSent = one loop 
                int charsWritten = 0;
                int charsSent = 0;

                // Keep doing while there is more text left in ciphertext
                while(charsWritten < strlen(decodedtext)){

                    // decodedtext + charsWritten will track where we are in loop
                    charsSent = send(connectionSocket, decodedtext + charsWritten, 1000, 0);
                    charsWritten = charsWritten + charsSent;

                    // error handling
                    if (charsWritten < 0){
                        error("CLIENT: ERROR writing to socket");
                    }

                }

                // more error handling
                if (charsWritten <= strlen(buffer)){
                    printf("CLIENT: WARNING: Not all data written to socket!\n");
                }


                close(connectionSocket); 



                break;
            default:
                // Parent, end process and wait for new connections
                break;
        }

       
        // // Close the connection socket for this client
        close(connectionSocket); 
    }
    // Close the listening socket
    close(listenSocket); 
    return 0;
}