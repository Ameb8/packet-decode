#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>


#define MAC_ADDR_LEN 6
#define MAC_ADDR_DELIM ":"
#define TYPE_LEN 2
#define TYPE_DELIM ""
#define PAYLOAD_DELIM " "
#define PAYLOAD_COL_WIDTH 8
#define PAYLOAD_NUM_COLS 4
#define 


int printBytes(FILE* file, int numBytes, char* delim) {
    int nextByte = 0;
    int bytesRead = 0;

    while(bytesRead < numBytes - 2) {
        fread(&nextByte, 1, 1, file);

        if(feof(file)) // Halt reading
            break;

        bytesRead++;
        printf("%02X%s", nextByte& 0xFF, delim);
    }

    // Read last byte while end of file not reached
    if(bytesRead == numBytes - 1) {
        fread(&nextByte, 1, 1, file);

        if(!feof(file)) { // Last byte read successfully
            bytesRead++;
            printf("%02X", nextByte& 0xFF);
        }
    }

    return bytesRead;
}


int main(int argc, char *argv[]) {
    int errCode = 0; // Tracks errors
    int nextByte = 0; // Holds byte being processed
    FILE* packetData = NULL; // Pointer to input packet data
    int bitsRead = 0; // Tracks number of bits read

    if(argc < 2) { // No filepath argument received
        errCode = 1;
    } else {
        packetData = fopen(argv[1], "rb"); // Open file

        if(!packetData) { // Could not open file
            errCode = 1;
        } else { // Read file data
            printf("\nEthernet header:\n------------"); // Display packet's header

            // Print destination MAC address    
            printf("\nDestination MAC address:\t\t\t");
            if(printBytes(packetData, MAC_ADDR_LEN, MAC_ADDR_DELIM) != MAC_ADDR_LEN) 
                errCode = 2; // Dest MAC address failed to read

            // Print Source MAC address
            printf("\nSource MAC address:\t\t\t\t");
            if(printBytes(packetData, MAC_ADDR_LEN, MAC_ADDR_DELIM) != MAC_ADDR_LEN)
                errCode = 2; // Source MAC address failed to read
            
            // Print Type
            printf("\nType:\t\t\t\t\t\t\t");
            if(printBytes(packetData, TYPE_LEN, TYPE_DELIM) != TYPE_LEN)
                errCode = 2; // Type failed to read

            printf("\n\nPayload:\n")


        }

    }

    return errCode;
}