#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>


// Label for Ethernet packet
#define PACKET_LBL "Ethernet header:\n----------------"
#define TYPE_LBL "\nType:\t\t\t\t"
#define MAC_SRC_LBL "\nSource MAC address:\t\t"
#define MAC_DEST_LBL "\nDestination MAC address:\t"
#define PAYLOAD_LBL "\n\nPayload:\n"

// MAC Address Format
#define MAC_ADDR_LEN 6 // MAC address length
#define MAC_ADDR_DELIM ":" // MAC address byte delimiter

// Type Field Format
#define TYPE_LEN 2 // Length of type field
#define TYPE_DELIM "" // Delimiter between type field bytes

// Payload Format
#define PAYLOAD_DELIM " " // Delimiter between each individual payload byte
#define PAYLOAD_COL_DELIM "   " // Delimiter separating payload columns
#define PAYLOAD_ROW_DELIM "\n" // Delimiter separating payload rows
#define PAYLOAD_COL_WIDTH 8 // Width of columns in payload 
#define PAYLOAD_NUM_COLS 4 // Number of columns in payload

// Error Codes
#define ERR_FILE_NOT_FOUND 1 // File arg missing
#define ERR_FILE_NOT_OPEN 2 // File failed to open

// Error Messages
#define MSG_FILE_NOT_FOUND "\nError: A path to a .bin containing with Ethernet " \
                           " packet is required. \n Run with `./PacketDecode <path>`"
#define MSG_FILE_NOT_OPEN "\nError: File argument could not be opened"


// Prints specified number of bytes pointed to by `file` arg
// Output is separated by `delim` arg
// Does not check for end of file or error after reading bytes
int printBytes(FILE* file, int numBytes, const char* delim) {
    int nextByte = 0; // Stores read bytes
    int bytesRead = 0; // Tracks number of bytes read

    // Read bytes and print
    while(bytesRead < numBytes - 1) {
        fread(&nextByte, 1, 1, file);
        printf("%02X%s", nextByte& 0xFF, delim);
        bytesRead++;
    }

    // Print last byte without delimiter
    fread(&nextByte, 1, 1, file);
    printf("%02X", nextByte& 0xFF);
    bytesRead++;
    
    return bytesRead;
}


// Prints next byte pointed to by FILE* arg
// Returns non-zero if end of file reached
static inline int printByteSafe(FILE* file) {
    int nextByte; // Stores byte being read

    // Read and display byte
    fread(&nextByte, 1, 1, file);
    printf("%02X", nextByte& 0xFF);

    return feof(file); 
}


// Prints the payload portion of an Ethernet packet
// Prints in the column-based format specified by PAYLOAD_ Macro constants
// `payloadData` argument must point to begining of payload data
// Returns the number of bytes read
int printPayload(FILE* payloadData) {
    int bytesRead = 0; // Tracks total bytes read
    int rowLen = PAYLOAD_NUM_COLS * PAYLOAD_COL_WIDTH; // Total row length

    // Print bytes until end of file
    while(!printByteSafe(payloadData)) {
        if(bytesRead % rowLen == rowLen - 1) { // End of row reached
            printf(PAYLOAD_ROW_DELIM);
        } else if(bytesRead % PAYLOAD_COL_WIDTH == PAYLOAD_COL_WIDTH - 1) { // End of column reached
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
    FILE* packetData = NULL; // Pointer to input packet data

    if(argc < 2) { // No filepath argument received
        errCode = 1;
    } else { // Attempt to open binary packet data
        packetData = fopen(argv[1], "rb"); // Open file

        if(!packetData) { // Could not open file
            errCode = 2;
        } else { // Read file data
            printf(PACKET_LBL); // Display packet's header

            printf(MAC_DEST_LBL); // Print destination MAC address
            printBytes(packetData, MAC_ADDR_LEN, MAC_ADDR_DELIM);
        
            printf(MAC_SRC_LBL); // Print Source MAC address
            printBytes(packetData, MAC_ADDR_LEN, MAC_ADDR_DELIM);
            
            printf(TYPE_LBL); // Print destination MAC address
            printBytes(packetData, TYPE_LEN, TYPE_DELIM);

            printf(PAYLOAD_LBL); // Print payload
            printPayload(packetData);
        }

    }

    // Handle errors
    if(errCode == ERR_FILE_NOT_FOUND) { // Missing path argument
        printf(MSG_FILE_NOT_FOUND);
    } else if(errCode == ERR_FILE_NOT_OPEN) { // File could not be opened
        printf(MSG_FILE_NOT_OPEN);
    }

    return errCode;
}