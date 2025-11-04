#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>


// Label for Ethernet packet fields
#define ETHERNET_LBL "Ethernet header:\n----------------"
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

// IP Header Format
#define IP_LBL "\n\nIPv4 Header:\n----------------"
#define VER_LBL "\nVersion:\t\t\t"
#define HLEN_LBL "\nInternet header length:\t\t"
#define DSCP_LBL "\nDSCP:\t\t\t\t"
#define ECN_LBL "\nECN:\t\t\t\t"
#define LEN_LBL "\nTotal Length:\t\t\t"
#define ID_LBL "\nIdentification:\t\t\t"
#define FLAGS_LBL "\nFlags:\t\t\t\t"
#define FRAG_OFF_LBL "\nFragment Offset:\t\t"
#define TTL_LBL "\nTime to Live:\t\t\t"
#define PROTOCOL_LBL "\nProtocol:\t\t\t"
#define IP_CHECKSUM_LBL "\nIP Checksum:\t\t\t0x"
#define IP_SRC_LBL "\nSource IP Address:\t\t"
#define IP_DEST_LBL "\nDestination IP Address:\t\t"
#define IP_OPTION_LBL(n) "\nIP Option Word #%d\t\t0x", n
#define NO_OPTIONS_LBL "\nOptions:\t\t\tNo Options"

// IP Field English Labels

// ECN Labels
#define ECN_DISABLE "\tNon-ECT Packet"
#define ECN_ALLOW "\tECN-capable packet"
#define ECN_CONGESTED "\tPacket Experienced Congestion"

// Fragment Flag Labels
#define FRAG_NONE "No Flag Set"
#define FRAG_DISABLED "Dont' Fragment"
#define FRAG_MORE "More Fragments"

#define IP_ADR_LEN 4

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
#define MSG_FILE_NOT_FOUND "\nError: A path to a .bin containing Ethernet " \
                           " packet data is required. \n Run with `./PacketDecode <path>`"
#define MSG_FILE_NOT_OPEN "\nError: File argument could not be opened"


// Helper functions
int printBytes(FILE* file, int numBytes, const char* delim);
static inline int printByteSafe(FILE* file);
int printPayload(FILE* packetData);
void printEthernetHeader(FILE* packetData);
void printIPHeader(FILE* packetData);
static inline void printIPOptions(FILE* packetData, int numOptions);


// Run program to decode and display Ethernet packets
// Takes path to .bin file containing one packet of data as argument
int main(int argc, char *argv[]) {
    int errCode = 0; // Tracks errors
    FILE* packetData = NULL; // Pointer to input packet data

    if(argc < 2) { // No filepath argument received
        errCode = ERR_FILE_NOT_FOUND;
    } else { // Attempt to open binary packet data
        packetData = fopen(argv[1], "rb"); // Open file

        if(!packetData) { // Could not open file
            errCode = ERR_FILE_NOT_OPEN;
        } else { // Read file data
            printEthernetHeader(packetData); // Process Ethernet header

            printIPHeader(packetData); // Process IP header

            printf(PAYLOAD_LBL); // Process payload
            printPayload(packetData);

            fclose(packetData); // Close packet data file
        }

    }

    printf("\n"); // Print trailing newline

    // Handle errors
    if(errCode == ERR_FILE_NOT_FOUND) { // Missing path argument
        printf(MSG_FILE_NOT_FOUND);
    } else if(errCode == ERR_FILE_NOT_OPEN) { // File could not be opened
        printf(MSG_FILE_NOT_OPEN);
    }

    return errCode;
}


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
    int bytesRead = 0;
    
    // attempt to read and display byte
    if(fread(&nextByte, 1, 1, file)) {
        printf("%02x", nextByte& 0xFF);
        bytesRead = 1;
    }

    return bytesRead; 
}



// Reads and prints IP address from binary file
// File pointer must point to begining of IP Address
// Does not check for read errors or EOF
void printIPAddress(FILE* file) {
    int nextByte = 0; // Stores read bytes
    int bytesRead = 0; // Tracks number of bytes read

    // Read bytes and print
    while(bytesRead < IP_ADR_LEN - 1) {
        fread(&nextByte, 1, 1, file);
        printf("%d.", nextByte);
        bytesRead++;
    }

    // Print last byte without delimiter
    fread(&nextByte, 1, 1, file);
    printf("%d", nextByte);
}


// Prints the payload portion of an Ethernet packet
// Prints in the column-based format specified by PAYLOAD_ Macro constants
// `payloadData` argument must point to begining of payload data
// Returns the number of bytes read
int printPayload(FILE* packetData) {
    int bytesRead = 0; // Tracks total bytes read
    int rowLen = PAYLOAD_NUM_COLS * PAYLOAD_COL_WIDTH; // Total row length

    // Print bytes until end of file
    while(printByteSafe(packetData)) {
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


// Reads and prints Ethernet Packet header from .bin file
// packetData must already point to start of Ethernet Header data
// Formatting and display info defined by IP Header Format macro constants at top of file
// Does not check for read errors or EOF
void printEthernetHeader(FILE* packetData) {
    printf(ETHERNET_LBL); // Display packet's header

    printf(MAC_DEST_LBL); // Print destination MAC address
    printBytes(packetData, MAC_ADDR_LEN, MAC_ADDR_DELIM);

    printf(MAC_SRC_LBL); // Print Source MAC address
    printBytes(packetData, MAC_ADDR_LEN, MAC_ADDR_DELIM);
    
    printf(TYPE_LBL); // Print type field
    printBytes(packetData, TYPE_LEN, TYPE_DELIM);
}


// Prints specified number of IP Options from packet data
// For each option, print macro constant defined label plus 4 bytes
// packetData argument must point to start of IP Options data
// Does not check for read errors or EOF
static inline void printIPOptions(FILE* packetData, int numOptions) {
    int optionsProcessed = 0;
    int bytesProcessed;
    int nextByte;

    while(optionsProcessed < numOptions) { // Iterate through IP Options
        printf(IP_OPTION_LBL(++optionsProcessed)); // Print label
        bytesProcessed = 0; // Set or reset bytes processed

        while(bytesProcessed < 4) { // Read and print IP Option bytes
            fread(&nextByte, 1, 1, packetData); // Read byte from packet data
            printf("%02x", nextByte & 0xFF); // Print byte
            bytesProcessed++; // Iterate count
        }
    }
}


// Reads and prints IPv4 Packet header from .bin file
// packetData must already point to start of IP Header data
// Formatting and display info defined by IP Header Format macro constants at top of file
// Does not check for read errors or EOF  
void printIPHeader(FILE* packetData) {
    int nextByte;
    int extractedBits;
    int optLen;

    printf(IP_LBL); // Print IP header label

    fread(&nextByte, 1, 1, packetData); // Read first byte

    extractedBits = (nextByte >> 4) & 0x0F; // Extract 4-bit verion field
    printf("%s%02x", VER_LBL, extractedBits); // Print version field

    optLen = nextByte & 0x0F; // Extract 4-bit IH Length field
    printf("%s%02x", HLEN_LBL, optLen); // Print IH length

    fread(&nextByte, 1, 1, packetData); // Read second byte

    extractedBits = (nextByte >> 2) & 0x3F; // Extract DSCP field
    printf("%s%02x", DSCP_LBL, extractedBits); // Display DSCP field

    extractedBits = nextByte & 0x03; // Extract 2-bit ECN field
    printf("%s%02X", ECN_LBL, extractedBits); // Print ECN field
    
    // Print ECN value in English
    if(extractedBits == 0) // ECN disabled
        printf(ECN_DISABLE);
    else if(extractedBits == 3) // Packet allows ECN
        printf(ECN_ALLOW);
    else // ECN field indicates congestion
        printf(ECN_CONGESTED);

    fread(&nextByte, 1, 1, packetData); // Read first byte of total length
    extractedBits = nextByte << 8; // Shift bits to left to make room for 2nd byte

    fread(&nextByte, 1, 1, packetData); // Read 2nd byte of total length
    extractedBits |= nextByte; // Combine both bytes into 1 value

    // Print Total Length Field with bytes combined from big-endian format
    printf("%s%d", LEN_LBL, extractedBits);

    fread(&nextByte, 1, 1, packetData); // Read first byte of identification field
    extractedBits = nextByte << 8; // Shift bits to left to make room for 2nd byte
    
    fread(&nextByte, 1, 1, packetData); // Read second byte of identification field
    extractedBits |= nextByte; // Combine both bites into 1 value

    // Print Identification with bytes combined from big-endian format
    printf("%s%d", ID_LBL, extractedBits);

    printf(FLAGS_LBL); // Print Fragment field label

    // Read byte with fragment flags and start of offset
    fread(&nextByte, 1, 1, packetData);

    // Display fragment status
    if((nextByte >> 5) & 1) // More fragments being sent
        printf(FRAG_MORE);
    else if((nextByte >> 6) & 1) // Fragmentation not allowed
       printf(FRAG_DISABLED);
    else // No Fragment flags set
        printf(FRAG_NONE);

    // Extract first 5 bits of fragment offset from end of byte
    extractedBits = nextByte & 0x1F;

    fread(&nextByte, 1, 1, packetData); // Read rest of fragment offset
    printf("%s%d", FRAG_OFF_LBL, (extractedBits << 8) | nextByte); // Display fragment offset

    fread(&nextByte, 1, 1, packetData); // Read Time to Live field
    printf("%s%d", TTL_LBL, nextByte); // Print Time to Live field

    fread(&nextByte, 1, 1, packetData); // Read Protocol field
    printf("%s%d", PROTOCOL_LBL, nextByte); // Print Protocol field

    fread(&nextByte, 1, 1, packetData); // Read first byte of IP Checksum
    extractedBits = nextByte << 8; // Shift bits left by 8 into extractedBits

    fread(&nextByte, 1, 1, packetData); // Read second byte of IP Checksum
    printf("%s%04x", IP_CHECKSUM_LBL, extractedBits | nextByte); // Display combined IP Checksum

    printf(IP_SRC_LBL); // Display source IP address label
    printIPAddress(packetData); // Display source IP Address

    printf(IP_DEST_LBL); // Display destination IP address label
    printIPAddress(packetData); // Display destination IP Address

    if(optLen > 5) // Print IP Options
        printIPOptions(packetData, optLen - 5);
    else // No IP Options to print
        printf(NO_OPTIONS_LBL);
}