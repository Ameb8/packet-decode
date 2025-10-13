#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>

// MAC Address Format
#define MAC_ADDR_LEN 6
#define MAC_ADDR_DELIM ":"

// Type Field Format
#define TYPE_LEN 2
#define TYPE_DELIM ""

// Payload Format
#define PAYLOAD_DELIM " "
#define PAYLOAD_COL_DELIM "\t"
#define PAYLOAD_ROW_DELIM "\n"
#define PAYLOAD_COL_WIDTH 8
#define PAYLOAD_NUM_COLS 4


// Prints specified number of bytes pointed to by `file` arg
// Output is separated by `delim` arg
// Does not check for end of file or error after reading bytes
int printBytes(FILE* file, int numBytes, const char* delim) {
    int nextByte = 0;
    int bytesRead = 0;

    // Read bytes and print
    while(bytesRead < numBytes - 1) {
        fread(&nextByte, 1, 1, file);
        bytesRead++;
        printf("%02X%s", nextByte& 0xFF, delim);
    }

    // Print last byte without delimiter
    fread(&nextByte, 1, 1, file);
    bytesRead++;
    printf("%02X", nextByte& 0xFF);
    
    return bytesRead;
}


// Prints next byte pointed to by FILE* arg
// Returns non-zero if end of file reached
static inline int printByteSafe(FILE* file) {
    int nextByte;

    // Read and display byte
    fread(&nextByte, 1, 1, file);
    printf("%02X", nextByte& 0xFF);

    return feof(file); 
}


// Prints the payload portion of an Ethernet packet
// Prints in the column-based format specified by PAYLOAD_ Macro constants
// FILE* argument must point to begining of payload data
// Returns the number of bytes read
int printPayload(FILE* file) {
    int bytesRead = 0; // Tracks total bytes read
    int rowLen = PAYLOAD_NUM_COLS * PAYLOAD_COL_WIDTH; // Total row length

    // Print bytes until end of file
    while(!printByteSafe(file)) {
        if(bytesRead % rowLen == 0) { // End of row reached
            printf(PAYLOAD_ROW_DELIM);
        } else if(bytesRead % PAYLOAD_COL_WIDTH == 0) { // End of column reached
            printf(PAYLOAD_COL_DELIM);
        } else { // Use standard delimiter
            printf(PAYLOAD_DELIM);
        }

        bytesRead++; // Increment count
    }

    return bytesRead;
}


// Run program to decode and display Ethernet packets
// Takes path to .bin file containing one packet of data as argument
int main(int argc, char *argv[]) {
    int errCode = 0; // Tracks errors
    int nextByte = 0; // Holds byte being processed
    FILE* packetData = NULL; // Pointer to input packet data
    int payloadRead = 0; // Tracks number of bits read

    if(argc < 2) { // No filepath argument received
        errCode = 1;
    } else { // Attempt to open binary packet data
        packetData = fopen(argv[1], "rb"); // Open file

        if(!packetData) { // Could not open file
            errCode = 2;
        } else { // Read file data
            printf("\nEthernet header:\n------------"); // Display packet's header

            // Print destination MAC address    
            printf("\nDestination MAC address:\t\t\t");
            printBytes(packetData, MAC_ADDR_LEN, MAC_ADDR_DELIM);
        
            // Print Source MAC address
            printf("\nSource MAC address:\t\t\t\t");
            printBytes(packetData, MAC_ADDR_LEN, MAC_ADDR_DELIM);
            
            // Print Type
            printf("\nType:\t\t\t\t\t\t\t");
            printBytes(packetData, TYPE_LEN, TYPE_DELIM);

            // Print payload
            printf("\n\nPayload:\n");
            printPayload(packetData);
        }

    }

    return errCode;
}