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

    char ciphertext[500000];
    char completeMessage[500000];
    char ptChar[250000];
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

       

        pid_t spawnpid = -5;
        spawnpid = fork();
        switch(spawnpid){
            case -1:
                perror("Hull Breach!");
                exit(1);
                break;
            case 0: 
                printf("SERVER: Connected to client running at host %d port %d\n", ntohs(clientAddress.sin_addr.s_addr), ntohs(clientAddress.sin_port));

                //////////////////////
                //////////////////////
                //  RECEIVING CLIENT CHECK        
                //////////////////////
                //////////////////////
                // Get the message from the client and display it
                memset(buffer, '\0', 1000);
                // Read the client's message from the socket
                charsRead = recv(connectionSocket, buffer, 999, 0); 

                if (charsRead < 0){
                    error("ERROR reading from socket");
                }
                printf("SERVER: I received this from the client: \"%s\"\n", buffer);

                if (strcmp(buffer, "ENC") != 0){
                    // charsRead = send(connectionSocket,  "NO", 2, 0); 
                    // Send a Success message back to the client
                    charsRead = send(connectionSocket, "NO", 2, 0); 
                    if (charsRead < 0){
                        error("ERROR writing to socket");
                    }
                }
                else{
                    charsRead = send(connectionSocket, "YES", 3, 0); 
                    if (charsRead < 0){
                        error("ERROR writing to socket");
                    }

                }

                printf("CHECKED CLIENT\n");
                ////////////////////
                ////////////////////
                //  RECEIVING SIZE        
                ////////////////////
                ////////////////////
                // Get the message from the client and display it
                memset(buffer, '\0', 1000);
                // Read the client's message from the socket
                charsRead = recv(connectionSocket, buffer, 999, 0); 
                if (charsRead < 0){
                    error("ERROR reading from socket");
                }
                

                int numCharsClient = atoi(buffer);
                printf("SERVER: %d\n", numCharsClient);

                printf("RECIEVED SIZE\n");
                //////////////////////
                //////////////////////
                //  RECEIVING DATA        
                //////////////////////
                //////////////////////

                printf("RECIEVING DATA...\n");
                memset(completeMessage, '\0', sizeof(completeMessage));
                charsRead = 0;
                int temp = 0;
                do{
                    memset(buffer, '\0', sizeof(buffer)); // clear buffer
                    temp = recv(connectionSocket, buffer, sizeof(buffer) - 1, 0);
                    strcat(completeMessage, buffer);

                    if (temp == -1){
                        printf("temp == -1\n");
                        break;
                    }
                    if (temp == 0){
                        printf("temp == 0\n");
                        break;
                    }
                
                    charsRead += temp;
                    
                }while(charsRead < numCharsClient);

                // printf("SERVER READ: %d\n", charsRead);
                printf("%s\n", completeMessage);
                printf("RECIEVED DATA\n");

                //////////////////////
                //////////////////////
                //  SEPARATE DATA        
                //////////////////////
                //////////////////////

                char *token;
                char *saveptr;
                
                // Get plaintext
                token = strtok_r(completeMessage, "-", &saveptr);

                memset(ptChar, '\0', sizeof(ptChar));
                strcpy(ptChar, token);

                // printf("ptChar: %s\n", ptChar);

                // Then get Token
                token = strtok_r(NULL, "\0", &saveptr);
                memset(keyChar, '\0', sizeof(keyChar));
                strcpy(keyChar, token);

                // printf("keyChar: %s\n", keyChar);

                printf("SEPARATED DATA\n");
                //////////////////////
                //////////////////////
                //  ENCRYPT         
                //////////////////////
                //////////////////////
                int i;
                char ptInt;
                char keyInt;
                char cipherInt; 
                memset(ciphertext, '\0', sizeof(ciphertext));
                for (i = 0; i < strlen(ptChar); i++){

                    if(ptChar[i] == 32){
                        ptInt = 26;
                    }
                    else{
                        ptInt = ptChar[i] - 65;
                    }

                    if(keyChar[i] == 32){
                        keyInt = 26;
                    }
                    else{
                        keyInt = keyChar[i] - 65;
                    }
                    

                    cipherInt = (ptInt + keyInt) % 27;
                    // https://www.educative.io/blog/concatenate-string-c
                    // Concatenate using sprintf

                    if(cipherInt == 26){
                        sprintf(ciphertext, "%s%c", ciphertext, cipherInt);
                    }
                    else{
                        sprintf(ciphertext, "%s%c", ciphertext,(cipherInt + 65));
                    }


                }

                printf("ENCRYPTED DATA\n");
                // //////////////////////
                // //////////////////////
                // //  SEND BACK ENCRYPTED DATA         
                // //////////////////////
                // //////////////////////

                printf("SENDING ENCRYPTED DATA...\n");
                memset(buffer, '\0', sizeof(buffer));
                int charsWritten = 0;
                int charsSent = 0;

                while(charsWritten < numCharsClient){

                    charsSent = send(connectionSocket, ciphertext + charsWritten, 1000, 0);
                    charsWritten = charsWritten + charsSent;
                }

                if (charsWritten < 0){
                    error("CLIENT: ERROR writing to socket");
                }

                if (charsWritten <= strlen(buffer)){
                    printf("CLIENT: WARNING: Not all data written to socket!\n");
                }

                printf("SENT BACK ENCRYPTED DATA\n");

                close(connectionSocket); 
                break;
            default:
                break;
        }

       
        // // Close the connection socket for this client
        close(connectionSocket); 
    }
    // Close the listening socket
    close(listenSocket); 
    return 0;
}