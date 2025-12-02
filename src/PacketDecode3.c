#include <stdio.h>
#include <stdlib.h>
#define _CRT_SECURE_NO_WARNINGS
#include <stdint.h>

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
#define FRAG_DISABLED "Don't Fragment"
#define FRAG_MORE "More Fragments"

#define IP_ADR_LEN 4


// TCP header format
#define TCP_LBL "\n\nTCP HEADER:\n----------------"
#define SRC_PORT_LBL "\nSource Port:\t\t\t"
#define DEST_PORT_LBL "\nDestination Port:\t\t"
#define SEQ_NUM_LBL "\nRaw Sequence Number:\t\t"
#define ACK_NUM_LBL "\nRaw Acknowledgement Number:\t"
#define DATA_OFS_LBL "\nData Offset:\t\t\t"
#define TCP_FLAGS_LBL "\nFlags:\t\t\t\t"
#define WINDOW_SIZE_LBL "\nWindow Size:\t\t\t"
#define TCP_CHECKSUM_LBL "\nTCP Checksum:\t\t\t0x"
#define TCP_URG_PTR_LBL "\nUrgent Pointer:\t\t\t"
#define TCP_OPT_LBL "\nTCP Option word #"
#define TCP_NO_OPT_LBL "\nOptions:\t\t\tNo Options"


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

// Bit masks to check specific bit in byte
#define BIT_MASK_0 1
#define BIT_MASK_1 2
#define BIT_MASK_2 4
#define BIT_MASK_3 8
#define BIT_MASK_4 16
#define BIT_MASK_5 32


// Helper functions for reading and printing data
static inline int printBytes(FILE* file, int numBytes, const char* delim);
static inline uint8_t printByteSafe(FILE* file);
static inline uint32_t readUIntBE(FILE* data, int nBytes);

// Functions to parse and display packet segments
void printEthernetHeader(FILE* packetData);
void printIPHeader(FILE* packetData);
void printTCPHeader(FILE* packetData);
static inline void printIPOptions(FILE* packetData, int numOptions);
int printPayload(FILE* packetData);


// Run program to decode and display Ethernet packets
// Takes path to .bin file containing one packet of data as argument
int main(int argc, char *argv[]) {
    int errCode = 0; // Tracks errors
    FILE* packetData = NULL; // Pointer to input packet data

    if(argc < 2) { // No filepath argument received
        errCode = ERR_FILE_NOT_FOUND; // Set error code
        printf(MSG_FILE_NOT_FOUND); // Alert user of error
    } else { // Attempt to open binary packet data
        packetData = fopen(argv[1], "rb"); // Open file

        if(!packetData) { // Could not open file
            errCode = ERR_FILE_NOT_OPEN; // Set error code
            printf(MSG_FILE_NOT_OPEN); // Alert user of error
        } else { // Read file data
            printEthernetHeader(packetData); // Process Ethernet header

            printIPHeader(packetData); // Process IP header

            printTCPHeader(packetData); // Process TCP header

            printf(PAYLOAD_LBL); // Process payload
            printPayload(packetData);

            fclose(packetData); // Close packet data file
        }

    }

    printf("\n"); // Print trailing newline

    return errCode;
}


// Prints specified number of bytes pointed to by `file` arg
// Bytes are printed as individual hexadecimal values
// Output is separated by `delim` arg
// Does not check for end of file or error after reading bytes
static inline int printBytes(FILE* file, int numBytes, const char* delim) {
    uint8_t nextByte = 0; // Stores read bytes
    int bytesRead = 0; // Tracks number of bytes read

    // Read bytes and print
    while(bytesRead < numBytes - 1) {
        fread(&nextByte, 1, 1, file);
        printf("%02x%s", nextByte& 0xFF, delim);
        bytesRead++;
    }

    // Print last byte without delimiter
    fread(&nextByte, 1, 1, file);
    printf("%02x", nextByte& 0xFF);
    bytesRead++;
    
    return bytesRead;
}


// Prints next byte pointed to by FILE* arg
// Returns non-zero if end of file reached
static inline uint8_t printByteSafe(FILE* file) {
    uint8_t nextByte; // Stores byte being read
    uint8_t bytesRead = 0; // Non-zero if byte read successful
    
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
    uint8_t nextByte = 0; // Stores read bytes
    uint8_t bytesRead = 0; // Tracks number of bytes read

    // Read bytes and print
    while(bytesRead < IP_ADR_LEN - 1) {
        fread(&nextByte, 1, 1, file);
        printf("%u.", nextByte);
        bytesRead++;
    }

    // Print last byte without delimiter
    fread(&nextByte, 1, 1, file);
    printf("%u", nextByte);
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
    uint8_t nextByte;
    uint32_t extractedBits = 0;
    int optLen;

    printf(IP_LBL); // Print IP header label

    fread(&nextByte, 1, 1, packetData); // Read first byte

    extractedBits = (nextByte >> 4); // Extract 4-bit verion field
    printf("%s%02x", VER_LBL, extractedBits); // Print version field

    optLen = nextByte & 0x0F; // Extract 4-bit IH Length field
    printf("%s%02x", HLEN_LBL, optLen); // Print IH length

    fread(&nextByte, 1, 1, packetData); // Read second byte

    extractedBits = (nextByte >> 2) & 0x3F; // Extract DSCP field
    printf("%s%02x", DSCP_LBL, extractedBits); // Display DSCP field

    extractedBits = nextByte & 0x03; // Extract 2-bit ECN field
    printf("%s%02x", ECN_LBL, extractedBits); // Print ECN field
    
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
    printf("%s%u", LEN_LBL, extractedBits);

    fread(&nextByte, 1, 1, packetData); // Read first byte of identification field
    extractedBits = nextByte << 8; // Shift bits to left to make room for 2nd byte
    
    fread(&nextByte, 1, 1, packetData); // Read second byte of identification field
    extractedBits |= nextByte; // Combine both bites into 1 value

    // Print Identification with bytes combined from big-endian format
    printf("%s%u", ID_LBL, extractedBits);

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
    printf("%s%u", FRAG_OFF_LBL, (extractedBits << 8) | nextByte); // Display fragment offset

    fread(&nextByte, 1, 1, packetData); // Read Time to Live field
    printf("%s%u", TTL_LBL, nextByte); // Print Time to Live field

    fread(&nextByte, 1, 1, packetData); // Read Protocol field
    printf("%s%u", PROTOCOL_LBL, nextByte); // Print Protocol field

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


// Function to read up to 4 bytes sequentially as one value
// File pointer in data will be advanced nBytes on success
// Does not check for EOF or read errors
static inline uint32_t readUIntBE(FILE* data, int nBytes) {
    uint32_t value = 0; // Resulting BE format value
    uint8_t nextByte; // Used to read bytes

    while(nBytes > 0) { // Read each byte
        fread(&nextByte, 1, 1, data); // read 1 byte
        value = (value << 8) | nextByte; // Shift 1 byte and append
        nBytes--; // Decrement bytes to read
    }

    return value;
}


// Reads and prints TCP Packet header from file
// packetData must already point to start of TCP Header data
// Formatting and display info defined by TCP Header Format macro constants at top of file
// Does not check for read errors or EOF 
// File pointer is advanced to end of header when successful
void printTCPHeader(FILE* packetData) {
    uint8_t nextByte, optWords, idx;

    printf(TCP_LBL);

    // Read and display source and destination ports
    printf("%s%u", SRC_PORT_LBL, readUIntBE(packetData, 2));
    printf("%s%u", DEST_PORT_LBL, readUIntBE(packetData, 2));

    // Read and display raw sequence and acknowledgment numbers
    printf("%s%u", SEQ_NUM_LBL, readUIntBE(packetData, 4)); // Sequence number
    printf("%s%u", ACK_NUM_LBL, readUIntBE(packetData, 4)); // Acknowledgement number

    // Read and display header data offset (total number of 4-Byte words in header)
    fread(&nextByte, 1, 1, packetData); // Read full byte of data
    nextByte >>= 4; // Right shift by 4 to isolate leading 4 bytes
    optWords = nextByte - 5; // Set number of 4-byte words in options
    printf("%s%u", DATA_OFS_LBL, nextByte); // Display Data offset

    // Read Byte containing flags
    printf(TCP_FLAGS_LBL); // Display flags header
    fread(&nextByte, 1, 1, packetData); // Read next byte

    // Check individual bits for flags
    if(nextByte & BIT_MASK_5) printf("URG "); // Check URGENT flag
    if(nextByte & BIT_MASK_4) printf("ACK "); // Check ACK flag
    if(nextByte & BIT_MASK_3) printf("PSH "); // Check PUSH flag
    if(nextByte & BIT_MASK_2) printf("RST "); // Check RESET flag
    if(nextByte & BIT_MASK_1) printf("SYN "); // Check SYNCHRONIZE flag
    if(nextByte & BIT_MASK_0) printf("FIN "); // Check Finish flag

    // Read and display advertised window field
    printf("%s%u", WINDOW_SIZE_LBL, readUIntBE(packetData, 2));
    
    // Read and display TCP checksum field
    printf("%s%02x", TCP_CHECKSUM_LBL, readUIntBE(packetData, 2));

    // Read and display urgent pointer field
    printf("%s%u", TCP_URG_PTR_LBL, readUIntBE(packetData, 2));

    if(optWords > 0) { // Read and display options
        for(idx = 0; idx < optWords; idx++) // Process options sequentially
            printf("%s%d:\t\t0x%08x", TCP_OPT_LBL, idx, readUIntBE(packetData, 4));
    } else { // No options in header
        printf(TCP_NO_OPT_LBL);
    }
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


