#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<string.h>
#include <ctime>
#include <netinet/in.h>
#include <netdb.h> 
#include <resolv.h>
#include<arpa/inet.h>
#include <string>
#include <cstring>
#include <algorithm>
#include <fstream>
#include<string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include<arpa/inet.h>
#include<stdio.h>

using namespace std;


// Struct for DNS header. flags are in reverse order per byte for endian conversion. 
struct DNS_HEADER
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

//Question structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

//RR structure
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

//RR data structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)


// ************************************************************************
// * Local functions we are going to use.
// ************************************************************************
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host);
void parseArg(char *arg);
void queryServer();
u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count);
u_char* queryServerQuestion(unsigned char *host, char *nameserver);
