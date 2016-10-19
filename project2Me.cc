// DNS Query Syststem
// Kelton Hislop

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
    char *name;
    struct R_DATA *resource;
    char *rdata;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
 
// This function was borowed from http://www.binarytides.com/dns-query-code-in-c-with-winsock/
void ChangetoDnsNameFormat(char* header,char* host) 
{
    int lock = 0 , i;
    strcat((char*)host,".");
     
    for(i = 0 ; i < strlen((char*)host) ; i++) 
    {
        if(host[i]=='.') 
        {
            *header++ = i-lock;
            for(;lock<i;lock++) 
            {
                *header++=host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *header++='\0';
}

char* ReadName(char* cursor,char* buffer,int* count)
{
    char *name;
    int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (char*)malloc(256);
 
    name[0]='\0';
    
    
    //printf("cursor Num : %s ", cursor);
 
    //read the names in 3www6google3com format
    while(*cursor!=0)
    {
        if(*cursor>=192)
        {
            offset = (*cursor)*256 + *(cursor+1) - 49152; //49152 = 11000000 00000000 ;)
            cursor = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*cursor;
        }
 
        cursor = cursor+1;
 
        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }
 
    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }
 
    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++) 
    {
        p=name[i];
        for(j=0;j<(int)p;j++) 
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
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
    int i , j, stop;
    struct RES_RECORD answers[20];
        struct sockaddr_in a;

    int sockfd;	// Socketfd
    int n;	
    socklen_t len;
    int bufsize = 65536;
    char recvbuf[bufsize], *qpos, buf[bufsize], *cursor; // Buffers for sending and receiving
    struct sockaddr_in servaddr;  //Server address
    struct QUESTION *question = NULL;
    struct DNS_HEADER *header = NULL;
    
    
    
    sockfd=socket(AF_INET,SOCK_DGRAM,0);  //Initialize the socketfd
    bzero(&servaddr,sizeof(servaddr));  //Zero the server address
    servaddr.sin_family=AF_INET;  //Specify and internet address
    //servaddr.sin_addr.s_addr=inet_addr("127.0.0.1");  //localhost
    //servaddr.sin_port=htons(5035);  //Set the port
    servaddr.sin_addr.s_addr=inet_addr("138.67.1.2");  //Mines
    //servaddr.sin_addr.s_addr=inet_addr("198.41.0.4");  //root a
    servaddr.sin_port=htons(53);  //Set the port
    //connect(sockfd,(struct sockaddr*)&servaddr,sizeof(servaddr));  //Connect to the server
    
    
    //Set the DNS structure to standard queries
    header = (struct DNS_HEADER *)&buf;
 
    header->id = (unsigned short) htons(getpid());
    header->qr = 0; //This is a query
    header->opcode = 0; //This is a standard query
    header->aa = 0; //Not Authoritative
    header->tc = 0; //This message is not truncated
    header->rd = 1; //Recursion Desired
    header->ra = 0; //Recursion not available
    header->z = 0;
    header->ad = 0;
    header->cd = 0;
    header->rcode = 0;
    header->q_count = htons(1); //we have only 1 question
    header->ans_count = 0;
    header->auth_count = 0;
    header->add_count = 0;
    
    
    
    //point past the header
    qpos = &buf[12];
 
    ChangetoDnsNameFormat(qpos , name);
    question = (struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qpos) + 1)]; //fill it
    
    question->qtype = htons(1); 
    question->qclass = htons(1); 
    
    printf("\nSending Packet...");
    if( sendto(sockfd,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qpos)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&servaddr,sizeof(servaddr)) < 0)
    {
        perror("sendto failed\n");
    }
    printf("Done\n");
    

    n=recvfrom(sockfd,recvbuf,bufsize,0,NULL,NULL);  //receive a response
    recvbuf[n] = 0;  //set the end of the received data
    printf("Return Result: %i\n", n);
    if(n < 1){
        printf("No response from this server.");
        return;
    }
    printf("\n Server's Echo : %s\n\n",recvbuf);  //print received data
    
    
    ///////////////////////////////////////////////////////////////////////////
    header = (struct DNS_HEADER*) recvbuf;
    
    cursor = &recvbuf[sizeof(struct DNS_HEADER) + (strlen((const char*)qpos)+1) + sizeof(struct QUESTION)];
    
    if(ntohs(header->ans_count) < 1){
        printf("No available answer from this server.\n\n");
        return;
    }
    
 
    printf("\nThe response contains : ");
    printf("\n %d Questions.",ntohs(header->q_count));
    printf("\n %d Answers.",ntohs(header->ans_count));
    printf("\n %d Authoritative Servers.",ntohs(header->auth_count));
    printf("\n %d Additional records.\n\n",ntohs(header->add_count));
    
    /////////////////////////////////////////////////////////////////////////////
    
    
    //reading answers
    for(i=0;i<ntohs(header->ans_count);i++)
    {
        answers[i].name=ReadName(cursor,recvbuf,&stop);
        cursor+=stop;
        answers[i].resource=(R_DATA*)(cursor);
        cursor+=sizeof(R_DATA);
        if(ntohs(answers[i].resource->type)==1)
        {
            answers[i].rdata=new char[ntohs(answers[i].resource->data_len)];
            for(int j=0;j<ntohs(answers[i].resource->data_len);j++)
                answers[i].rdata[j]=cursor[j];
            answers[i].rdata[ntohs(answers[i].resource->data_len)]='\0';
            cursor+=ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata=ReadName(cursor,recvbuf,&stop);
            cursor+=stop;
        }
    }
    printf("Name One : %s\n", answers[0].name);
    
    
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



