#include "includes.h"
#define NSERVER 9316


#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<string.h>
#include<arpa/inet.h>
#include<string.h>
#include<arpa/inet.h>
#include<stdio.h>
#define MAXLINE 1024


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

//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};
 

void ChangetoDnsNameFormat(char* dns,char* host) 
{
    int lock = 0 , i;
    strcat((char*)host,".");
     
    for(i = 0 ; i < strlen((char*)host) ; i++) 
    {
        if(host[i]=='.') 
        {
            *dns++ = i-lock;
            for(;lock<i;lock++) 
            {
                *dns++=host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++='\0';
}



void queryServer(){
    int test;

    int sockfd;	// Socketfd
    int n;	
    socklen_t len;
    char sendline[1024],recvline[1024]; // Buffers for sending and receiving
    struct sockaddr_in servaddr;  //Server addresshort
    strcpy(sendline,"");  //Put an empty tring into sendline
    printf("\n Enter the message : ");  //prompt user for mesage
    scanf("%s",sendline);  //Receive user input
    sockfd=socket(AF_INET,SOCK_DGRAM,0);  //Initialize the socketfd
    bzero(&servaddr,sizeof(servaddr));  //Zero the server address
    servaddr.sin_family=AF_INET;  //Specify and internet address
    //servaddr.sin_addr.s_addr=inet_addr("127.0.0.1");  //Set the address
    //servaddr.sin_port=htons(5035);  //Set the port
    servaddr.sin_addr.s_addr=inet_addr("138.67.1.2");  //Set the address
    servaddr.sin_port=htons(53);  //Set the port
    connect(sockfd,(struct sockaddr*)&servaddr,sizeof(servaddr));  //Connect to the server
    len=sizeof(servaddr);  //get size of server address
    test = sendto(sockfd,sendline,MAXLINE,0,(struct sockaddr*)&servaddr,len);  //Send sendline through socket
    printf("Send Result: %i\n", test);
    n=recvfrom(sockfd,recvline,MAXLINE,0,NULL,NULL);  //receive a response
    recvline[n]=0;  //set the end of the received data
    printf("Return Result: %i\n", n);
    printf("\n Server's Echo : %s\n\n",recvline);  //print received data
    
    

}

void queryServerQuestion(char* name){
    int test;
    int i , j , stop;
    struct RES_RECORD answers[20],auth[20],addit[20];

    int sockfd;	// Socketfd
    int n;	
    socklen_t len;
    int bufsize = 65536;
    char recvbuf[bufsize], *qname, buf[bufsize], *reader; // Buffers for sending and receiving
    struct sockaddr_in servaddr;  //Server address
    struct QUESTION *question = NULL;
    struct DNS_HEADER *dns = NULL;
    
    
    
    sockfd=socket(AF_INET,SOCK_DGRAM,0);  //Initialize the socketfd
    bzero(&servaddr,sizeof(servaddr));  //Zero the server address
    servaddr.sin_family=AF_INET;  //Specify and internet address
    //servaddr.sin_addr.s_addr=inet_addr("127.0.0.1");  //Set the address
    //servaddr.sin_port=htons(5035);  //Set the port
    servaddr.sin_addr.s_addr=inet_addr("138.67.1.2");  //Set the address
    servaddr.sin_port=htons(53);  //Set the port
    connect(sockfd,(struct sockaddr*)&servaddr,sizeof(servaddr));  //Connect to the server
    
    
    //Set the DNS structure to standard queries
    dns = (struct DNS_HEADER *)&buf;
 
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;
    
    
    
    //point to the query portion
    qname =&buf[sizeof(struct DNS_HEADER)];
 
    ChangetoDnsNameFormat(qname , name);
    question = (struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it
    
    question->qtype = htons(1); 
    question->qclass = htons(1); 
    
    printf("\nSending Packet...");
    if( sendto(sockfd,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&servaddr,sizeof(servaddr)) < 0)
    {
        perror("sendto failed\n");
    }
    printf("Done\n");
    

    n=recvfrom(sockfd,recvbuf,bufsize,0,NULL,NULL);  //receive a response
    recvbuf[n] = 0;  //set the end of the received data
    printf("Return Result: %i\n", n);
    printf("\n Server's Echo : %s\n\n",recvbuf);  //print received data
    
    
    ///////////////////////////////////////////////////////////////////////////
    dns = (struct DNS_HEADER*) recvbuf;
    
    
    
    reader = &recvbuf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
 
    printf("\nThe response contains : ");
    printf("\n %d Questions.",ntohs(dns->q_count));
    printf("\n %d Answers.",ntohs(dns->ans_count));
    printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
    printf("\n %d Additional records.\n\n",ntohs(dns->add_count));
     
    
    return;
}

// ***************************************************************************
// * Main
// ***************************************************************************
int main(int argc, char **argv) {

    char *address;
    //address = (char*)malloc(sizeof("test"));
    address = (char*)malloc(50);
    strcpy(address, "www.mines.edu");

    queryServerQuestion(address);

    return 0;
    
}



